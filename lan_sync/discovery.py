"""局域网发现（SPEC-v2 §3）：mDNS 首选 + UDP 广播兜底 + 来源仲裁。

三条纪律：
1. **任何来源都不直接信**。候选端点必须先经 `GET /info` 探针成功才进设备表，所以伪造广播包
   换不来信任，只能换来一次被拒的探测。
2. **地址取 socket/解析结果，不信包内自报地址**。VPN/多网卡下自报常错（v1 已踩过）。
3. **某 device_id 的 mDNS 新鲜（45s）时忽略它的广播端点**：mDNS 带真实端口，广播只带默认端口。
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Callable

from .protocol import (
    ANNOUNCE_INTERVAL_SECS,
    MAGIC_V1,
    MDNS_SERVICE,
    MDNS_SERVICE_V1,
    MDNS_SUPPRESS_WINDOW_SECS,
    NSD_NAME_PREFIX_V1,
    PROBE_THROTTLE_SECS,
    UDP_PORT,
    PeerInfo,
    decode_announce,
    encode_announce,
)
from .identity import announce_targets, best_address

log = logging.getLogger("anki.lansync.discovery")

VIA_MDNS = "mdns"
VIA_UDP = "udp"
VIA_MANUAL = "manual"


def instance_name(info: PeerInfo, prefix: str = "AnkiSync-") -> str:
    """实例名只带可读前缀 + id 前 8 位；完整 id 由 `/info` 给出。"""
    raw = f"{prefix}{info.device_id[:8]}"
    return "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in raw)


def txt_records(info: PeerInfo) -> dict:
    return {
        "v": str(info.protocol),
        "id": info.device_id[:8],
        "kind": info.kind,
        "roles": ",".join(info.roles or ["p2p"]),
    }


class Discovery:
    """拥有 mDNS 注册/浏览与 UDP 广播/监听，产出**已验证**的 peer 回调。

    `probe(host, port)` 与 `on_peer(info, host, port, via)` 都由 engine 注入——只有它拿得到
    HTTP 客户端和设备表；这里只负责"发现候选端点 + 节流 + 仲裁"。
    """

    def __init__(self, store, my_info: Callable[[], PeerInfo],
                 on_peer: Callable[[PeerInfo, str, int, str], None],
                 probe: Callable[[str, int], PeerInfo | None],
                 udp_port: int = UDP_PORT,
                 announce_interval: float = ANNOUNCE_INTERVAL_SECS,
                 mdns: bool = True,
                 own_device_id: str = "") -> None:
        self.store = store
        self.my_info = my_info
        self.on_peer = on_peer
        self.probe = probe
        self.udp_port = udp_port
        self.announce_interval = announce_interval
        # 同机两个实例时关掉 mDNS，只测 UDP + 手动路径
        self.mdns = mdns
        self.own_device_id = own_device_id

        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._zeroconf = None
        self._browsers: list = []
        self._registrations: list = []
        self._probed_at: dict[str, float] = {}
        self._kick_until = 0.0
        self._lock = threading.Lock()
        self._udp_sock: socket.socket | None = None
        self.mdns_ok = False
        self.udp_ok = False

    # ------------------------------------------------------------- 生命周期
    def start(self) -> None:
        self._stop.clear()
        # 发包口与收包口分开：收包口被占只该让"听"失效，不该顺手关掉"喊"。
        self._send_sock = self._make_send_socket()
        self._udp_sock = self._make_listen_socket()
        self._spawn(self._announce_loop)
        if self._udp_sock is not None:
            self._spawn(self._listen_loop)
        if self.mdns:
            self._start_mdns()

    def _spawn(self, target: Callable[[], None]) -> None:
        thread = threading.Thread(target=_guard(target), daemon=True,
                                  name=f"lansync-{target.__name__}")
        self._threads.append(thread)
        thread.start()

    def stop(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=3)
        self._threads.clear()
        self._stop_mdns()
        for sock in (self._udp_sock, self._send_sock):
            try:
                if sock is not None:
                    sock.close()
            except OSError:
                pass
        self._udp_sock = self._send_sock = None

    # ------------------------------------------------------------------ mDNS
    def _start_mdns(self) -> None:
        try:
            from zeroconf import ServiceInfo, Zeroconf
        except ImportError:
            log.warning("zeroconf 不可用，只靠 UDP 广播与手动添加")
            return
        info = self.my_info()
        addr = best_address()
        if not addr:
            log.info("没有可宣告地址，跳过 mDNS 注册")
            return
        try:
            self._zeroconf = Zeroconf()
            name = instance_name(info)
            common = {
                "port": info.port,
                "server": f"{name.lower()}.local.",
                "addresses": [socket.inet_aton(addr)],
            }
            self._registrations = [
                self._zeroconf.register_service(ServiceInfo(
                    MDNS_SERVICE, f"{name}.{MDNS_SERVICE}",
                    properties=txt_records(info), **common)),
                # 再注册一份 v1 服务类型：只会上线 v1 的安卓 fork 才 browse 得到我们
                self._zeroconf.register_service(ServiceInfo(
                    MDNS_SERVICE_V1,
                    f"{NSD_NAME_PREFIX_V1}{info.device_id[:8]}.{MDNS_SERVICE_V1}",
                    properties={"id": info.device_id[:8], "kind": info.kind}, **common)),
            ]
            self._browse()
            self.mdns_ok = True
        except Exception:  # noqa: BLE001 - 防火墙/OEM 常屏蔽 mDNS，降级而不是报错
            log.exception("mDNS 注册失败，退回 UDP")
            self.mdns_ok = False

    def _stop_mdns(self) -> None:
        if self._zeroconf is None:
            return
        try:
            for browser in self._browsers:
                browser.cancel()
            for registration in self._registrations:
                registration.unregister()
            self._zeroconf.close()
        except Exception:  # noqa: BLE001
            log.debug("mDNS 关闭时异常", exc_info=True)
        self._zeroconf = None
        self._browsers = []
        self._registrations = []

    def _browse(self) -> None:
        from zeroconf import ServiceBrowser

        class Handler:
            def add_service(_h, zc, type_, name):  # noqa: N805
                self._on_mdns(zc, type_, name)

            def update_service(_h, zc, type_, name):  # noqa: N805
                self._on_mdns(zc, type_, name)

            def remove_service(_h, zc, type_, name):  # noqa: N805
                del zc, type_, name

        for service_type in (MDNS_SERVICE, MDNS_SERVICE_V1):
            self._browsers.append(ServiceBrowser(self._zeroconf, service_type, Handler()))

    def _on_mdns(self, zc, service_type: str, name: str) -> None:
        try:
            record = zc.get_service_info(service_type, name, timeout=2000)
        except Exception:  # noqa: BLE001 - 解析失败留给广播/手动路径
            return
        port = int(getattr(record, "port", 0) or 0) if record else 0
        for address in (getattr(record, "addresses", None) or []):
            try:
                host = socket.inet_ntoa(bytes(address)[:4])
            except OSError:
                continue
            if host.startswith("127."):
                continue
            self._verify(host, port or 5600, VIA_MDNS)

    # ------------------------------------------------------------------- UDP
    def _make_send_socket(self) -> socket.socket:
        # 不绑固定口：同机多实例各自用临时源端口发广播，谁也不抢谁的 46000
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return sock

    def _make_listen_socket(self) -> socket.socket | None:
        """收包口。绑不上就退回临时端口并置 `udp_ok=False`——**发**照旧，只是**听**不见了。

        `self.udp_port`（发往哪个口）绝不跟着改：改成临时端口等于对着空气广播。
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("0.0.0.0", self.udp_port))  # noqa: S104 - 收广播必须通配
            self.udp_ok = True
            sock.settimeout(1.0)
            return sock
        except OSError:
            log.warning("UDP %s 绑定失败：只发不收（广播兜底不可用，mDNS/手动仍可用）",
                        self.udp_port)
            sock.close()
            self.udp_ok = False
            return None

    def _announce_loop(self) -> None:
        sock = self._send_sock
        while not self._stop.is_set():
            info = self.my_info()
            # 双 magic 各发一份：v2 同伴读前者，还在跑 v1 的安卓 fork 读后者
            packets = [encode_announce(info), encode_announce(info, MAGIC_V1)]
            for target in announce_targets(best_address()):
                for packet in packets:
                    try:
                        sock.sendto(packet, (target, self.udp_port))
                    except OSError:
                        log.debug("announce -> %s 失败", target, exc_info=True)
            wait = (1.0 if time.time() < self._kick_until else self.announce_interval)
            self._stop.wait(wait)

    def kick(self, window: float = 6.0) -> None:
        """自愈用：清掉探测节流并密集广播一阵，应对 DHCP 换址后的对端。"""
        with self._lock:
            self._probed_at.clear()
        self._kick_until = time.time() + window

    def _listen_loop(self) -> None:
        sock = self._udp_sock
        while not self._stop.is_set():
            try:
                raw, sender = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            decoded = decode_announce(raw)
            if decoded is None:
                continue
            version, peer = decoded
            host = sender[0]  # 只信 socket 源地址
            if peer.device_id == self.own_device_id or host.startswith("127."):
                continue
            if self.store.mdns_recent(peer.device_id, MDNS_SUPPRESS_WINDOW_SECS):
                continue
            self._verify(host, peer.port, VIA_UDP, announced_version=version)

    # -------------------------------------------------- 探测节流 / 端点验证
    def _throttled(self, endpoint: str) -> bool:
        now = time.time()
        with self._lock:
            if now - self._probed_at.get(endpoint, 0.0) < PROBE_THROTTLE_SECS:
                return True
            self._probed_at[endpoint] = now
            return False

    def verify_endpoint(self, host: str, port: int, via: str) -> PeerInfo | None:
        """手动添加与自愈也走这里：拿不到合法 `/info` 就不算 peer。"""
        info = self.probe(host, port)
        if info is None or not info.device_id or info.device_id == self.own_device_id:
            return None
        if via == VIA_MDNS:
            self.store.touch_mdns(info.device_id)
        self.on_peer(info, host, port, via)
        return info

    def _verify(self, host: str, port: int, via: str, announced_version: int | None = None) -> None:
        if self._throttled(f"{host}:{port}"):
            return
        info = self.verify_endpoint(host, port, via)
        # 广播自称 v1、`/info` 说 v2：以 `/info` 为准，只记一行日志
        if info is not None and announced_version is not None and info.protocol != announced_version:
            log.info("peer %s:%s announce=v%s 但 info=v%s，按 info 处理",
                     host, port, announced_version, info.protocol)


def _guard(target: Callable[[], None]) -> Callable[[], None]:
    def run() -> None:
        try:
            target()
        except Exception:  # noqa: BLE001 - 线程异常不能带走进程
            log.exception("lansync discovery 线程 %s 退出", target.__name__)

    return run
