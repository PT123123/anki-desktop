"""轮次编排、配对落地、模式协商（SPEC-v2 §4–§8）。

`LanEngine` 是唯一持有状态的地方：store / 身份 / 集合桥 / hub / HTTP 服务 / 发现 / 客户端。
`server.py` 通过它的一组回调读写，`scheduler.py` 只问它"该同步谁了"——**什么时候同步的策略
全在调度器**，HTTP 处理线程从不起同步线程，只留一个"立刻跑一轮"的请求标记。

三个不变量：
1. 同一时刻对同一 peer 只有一轮在跑（`_round_locks`，拿不到就记一次 BUSY，不排队堆积）。
2. 因对端导入而起的本地变更**不再回推给那个对端**（`note_local_write(caused_by=...)`），
   否则两端会互相点着同步下去。
3. 集合锁只在本地导出/导入期间持有；apkg 的网络传输在锁外（hub 模式例外：rslib 自己
   管那一整条会话，见 `anki_bridge.sync_to_hub`）。
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto
from . import discovery as disc
from . import server as lan_server
from .anki_bridge import Busy, CollectionBridge, HubSeedRequired
from .client import PeerClient
from .hub import HubServer
from .identity import Identity, load_or_create
from .protocol import (
    HUB_PORT_END,
    HUB_PORT_START,
    KIND_DESKTOP,
    MAX_PACKAGE_BYTES,
    MODE_APKG,
    MODE_HUB,
    OFFLINE_AFTER_SECS,
    TCP_PORT_END,
    TCP_PORT_START,
    UDP_PORT,
    PeerInfo,
    LanError,
    pick_mode,
)
from .store import Store

log = logging.getLogger("anki.lansync.engine")

PAIR_TTL_SECS = 300.0


def _code_of(exc: Exception) -> str:
    """同步历史里的失败码：带 `code` 的用其语义码，否则退到异常类型名。"""
    return str(getattr(exc, "code", None) or type(exc).__name__)


@dataclass
class PeerState:
    peer_id: str
    name: str = ""
    kind: str = ""
    protocol: int = 2
    host: str = ""
    port: int = 0
    via: str = ""
    modes: list[str] = field(default_factory=lambda: [MODE_APKG])
    roles: list[str] = field(default_factory=list)
    hub_port: int = 0
    last_heard: float = 0.0
    paired: bool = False

    @property
    def online(self) -> bool:
        return (time.time() - self.last_heard) <= OFFLINE_AFTER_SECS

    def row(self) -> dict:
        return {
            "peer_id": self.peer_id, "id8": self.peer_id[:8], "name": self.name,
            "kind": self.kind, "protocol": self.protocol, "endpoint": self.endpoint_str,
            "via": self.via, "modes": self.modes, "roles": self.roles, "hub_port": self.hub_port,
            "online": self.online, "paired": self.paired, "last_heard": self.last_heard,
        }

    @property
    def endpoint_str(self) -> str:
        return f"{self.host}:{self.port}"


class LanEngine:
    def __init__(self, data_dir: Path, collection_path: Path | str,
                 profile: str = "current", *, bind_host: str = "0.0.0.0",
                 http_port_start: int = TCP_PORT_START,
                 http_port_end: int = TCP_PORT_END,
                 udp_port: int = UDP_PORT, mdns: bool = True,
                 hub_port_start: int = HUB_PORT_START,
                 hub_port_end: int = HUB_PORT_END) -> None:
        """端口/广播参数都可覆盖：同机跑两个实例做端到端验证时必须换私有端口段。"""
        self.data_dir = Path(data_dir)
        self.work_dir = self.data_dir / "xfer"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.bind_host = bind_host
        self.http_port_start = http_port_start
        self.http_port_end = http_port_end
        self.udp_port = udp_port
        self.mdns = mdns
        self.store = Store(self.data_dir / "sync.db")
        self.identity: Identity = load_or_create(self.store)
        self.bridge = CollectionBridge(collection_path, profile)
        self.hub = HubServer(self.data_dir / "hub", host=self.hub_bind(),
                             port_start=hub_port_start, port_end=hub_port_end)
        self.nonces = crypto.NonceCache()
        self.client = PeerClient(self.store, self.identity, self.nonces)
        self.server: lan_server.LanHttpServer | None = None
        self._server_thread: threading.Thread | None = None
        self.discovery: disc.Discovery | None = None
        self.port = 0
        self.started_at = time.time()

        self._peers: dict[str, PeerState] = {}
        self._peers_lock = threading.Lock()
        self._round_locks: dict[str, threading.Lock] = {}
        self._temps: set[Path] = set()
        self._temps_lock = threading.Lock()
        self.progress: dict = {}
        self._dirty: dict[str, float] = {}
        self._last_round: dict[str, float] = {}
        self._immediate: list[str] = []
        self._state_lock = threading.Lock()

    # ------------------------------------------------------------------ 配置
    def cfg(self, key: str, default=None):
        return self.store.get_config(key, default)

    def set_cfg(self, key: str, value) -> None:
        self.store.set_config(key, value)

    def enabled(self) -> bool:
        return bool(self.cfg("enabled", False))

    def allow_v1_plaintext(self) -> bool:
        return bool(self.cfg("allow_v1_plaintext", False))

    def hub_role(self) -> bool:
        return bool(self.cfg("hub_role", False))

    def hub_bind(self) -> str:
        # 默认只监听回环；绑局域网地址要用户明确勾选（SPEC §6.2）
        return str(self.cfg("hub_bind", "127.0.0.1"))

    def auto_round(self) -> bool:
        return bool(self.cfg("auto_round", True))

    def interval_secs(self) -> float:
        return float(self.cfg("interval_secs", 300))

    # ------------------------------------------------------------- 生命周期
    def start(self) -> None:
        if self.server is not None:
            return
        self.server, self.port = lan_server.serve(self, host=self.bind_host,
                                                 port_start=self.http_port_start,
                                                 port_end=self.http_port_end)
        self._server_thread = threading.Thread(target=self.server.serve_forever,
                                               daemon=True, name="lansync-http")
        self._server_thread.start()
        if self.hub_role():
            try:
                self.hub.start()
            except Exception:  # noqa: BLE001 - hub 起不来不该拖垮 p2p
                log.exception("hub 启动失败，只提供 apkg 模式")
        self.discovery = disc.Discovery(
            store=self.store, my_info=self.info, on_peer=self.register_peer,
            probe=self.client.probe, udp_port=self.udp_port, mdns=self.mdns,
            own_device_id=self.identity.device_id,
        )
        self.discovery.start()
        # 重启后不能继承"在线"，所以主动补探一轮
        self.reprobe_all()

    def stop(self) -> None:
        if self.discovery:
            self.discovery.stop()
            self.discovery = None
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self._server_thread:
            self._server_thread.join(timeout=5)
            self._server_thread = None
        self.hub.stop()
        self.bridge.close()
        self._clean_temps()

    def set_enabled(self, value: bool) -> None:
        """false→true 要立刻跑一轮，不等下一个调度周期（SPEC §8 触发点）。"""
        was = self.enabled()
        self.set_cfg("enabled", bool(value))
        if value and not was:
            if self.server is None:
                self.start()
            self.request_immediate("enable")
        elif was and not value:
            self.stop()

    # ------------------------------------------------------------ 身份/公告
    def my_modes(self) -> list[str]:
        """本机能作为**发起端**参与的数据面。桌面两者皆可：用 hub 不需要自己也开服务端，
        只要能连对端的 rslib 同步端点。是不是在**serve**一个 hub 由 `roles`/`hub_port` 表达。
        """
        return [MODE_APKG, MODE_HUB]

    def hub_serving(self) -> bool:
        return bool(self.hub_role() and self.hub.running)

    def info(self) -> PeerInfo:
        serving = self.hub_serving()
        return PeerInfo(
            device_id=self.identity.device_id, name=self.identity.name,
            kind=KIND_DESKTOP, port=self.port or 5600, modes=self.my_modes(),
            roles=["p2p"] + (["hub"] if serving else []),
            kids=self.store.paired_kids(), ts=int(time.time()),
            hub_port=self.hub.port if serving else 0,
        )

    def info_json(self) -> str:
        return self.info().to_json(v1_compat=True)

    def on_port_bound(self, port: int) -> None:
        self.port = port

    # ---------------------------------------------------------------- 设备表
    def register_peer(self, info: PeerInfo, host: str, port: int, via: str) -> None:
        paired = self.store.get_secret(info.device_id) is not None
        self.store.upsert_device(info.device_id, name=info.name, kind=info.kind,
                                 protocol=info.protocol, endpoint=f"{host}:{port}", via=via)
        with self._peers_lock:
            state = self._peers.get(info.device_id) or PeerState(info.device_id)
            was_online = state.last_heard > 0 and state.online
            state.name, state.kind, state.protocol = info.name, info.kind, info.protocol
            state.host, state.port, state.via = host, port, via
            state.modes, state.roles = list(info.modes), list(info.roles)
            state.hub_port = info.hub_port
            state.last_heard = time.time()
            state.paired = paired
            self._peers[info.device_id] = state
        # 离线→在线是个"不等下一轮"的触发点（SPEC §8）
        if not was_online and paired and self.auto_round():
            self.mark_dirty(info.device_id, reason="came online")

    def note_heard(self, peer_id: str, name: str = "", host: str = "") -> None:
        with self._peers_lock:
            state = self._peers.get(peer_id) or PeerState(peer_id)
            state.last_heard = time.time()
            if name:
                state.name = name
            if host and not state.host:
                state.host = host
            self._peers[peer_id] = state

    def peers(self) -> list[dict]:
        with self._peers_lock:
            return [s.row() for s in sorted(self._peers.values(), key=lambda s: s.name)]

    def peer_state(self, peer_id: str) -> PeerState | None:
        with self._peers_lock:
            return self._peers.get(peer_id)

    def find_peer(self, ref: str) -> PeerState | None:
        """按完整 id / 唯一 id 前缀 / 名字 / `host:port` 找已注册 peer，歧义时返回 None。"""
        with self._peers_lock:
            states = list(self._peers.values())
        for match in (lambda s: s.peer_id == ref,
                      lambda s: s.peer_id.startswith(ref),
                      lambda s: s.name == ref,
                      lambda s: s.endpoint_str == ref):
            hits = [s for s in states if match(s)]
            if len(hits) == 1:
                return hits[0]
            if len(hits) > 1:
                return None
        return None

    def paired_peers(self, online_only: bool = True) -> list[PeerState]:
        with self._peers_lock:
            out = [s for s in self._peers.values() if s.paired and s.host and s.port]
        return [s for s in out if s.online or not online_only]

    def reprobe_all(self) -> list[str]:
        """按库里存过的端点补探；一个都没探通就开一次重发现窗口（应对 DHCP 换址）。"""
        refreshed: list[str] = []
        if self.discovery is None:
            return refreshed
        for row in self.store.devices():
            verified = False
            for endpoint in row["endpoints"] or []:
                host, _, port = endpoint.partition(":")
                if self.discovery.verify_endpoint(host, int(port or 5600),
                                                  row.get("added_via") or disc.VIA_MANUAL):
                    verified = True
                    refreshed.append(row["peer_id"])
            if not verified:
                log.debug("peer %s 的已知端点都没探通，等广播/mDNS 重新给出地址",
                          row["peer_id"][:8])
        return refreshed

    # ------------------------------------------------------------------ 配对
    def begin_pairing(self) -> dict:
        """展示端：本机生成 6 位码 + 32B 贡献值；码给对方看，贡献值只入库等 commit。"""
        self.store.expire_pair_codes()
        code = crypto.gen_pair_code()
        contribution = crypto.gen_secret()
        expires_at = self.store.new_pair_code(code, contribution, PAIR_TTL_SECS)
        return {"pair_code": code, "expires_in": max(0, int(expires_at - time.time())),
                "security_code": None,
                "hint": "对方输入本码完成配对后，两端会各显示一个 4 位安全码；"
                        "核对一致才算信任建立，不一致请解除配对重来"}

    def handle_pair_commit(self, payload: dict, host: str = "") -> dict:
        """展示端收到 commit：先一次性消费码，再解包。

        顺序不能反：码只有 6 位十进制（约 20 bit），解包失败意味着对方要么猜错了码，要么在
        穷举这个码的包裹密钥。先解包的话码还活着，同一个码就能被反复拿来试；先消费的话一次
        失败即作废（§4.1）。认不出的码不烧会话 —— take_pair_code 直接抛 pair_invalid。
        """
        code = str(payload.get("pair_code", ""))
        mine = self.store.take_pair_code(code)
        theirs = crypto.unwrap_with_pair_code(code, payload.get("envelope") or {})
        peer_info = PeerInfo.from_json(json.dumps(payload.get("peer_info") or {}))
        if not peer_info.device_id:
            raise LanError(400, "bad_peer_info")
        shared = self._finish_pairing(peer_info, mine, theirs)
        # 对端的 host 只能从 socket 拿；包内自报地址在 VPN/多网卡下常错
        self.register_peer(peer_info, host or "127.0.0.1", peer_info.port, "pair")
        return {"peer_info": json.loads(self.info().to_json()),
                "envelope": crypto.wrap_with_pair_code(code, mine),
                "security_code": crypto.gen_security_code(shared),
                "peer_id": peer_info.device_id}

    def pair_with(self, peer_ref: str, code: str) -> dict:
        """输入端：向已发现的 peer（peer_id 或 host:port）提交 6 位码。"""
        host, port = self._resolve_endpoint(peer_ref)
        my_contribution = crypto.gen_secret()
        peer_info, theirs = self.client.pair_commit(host, port, code, self.info(),
                                                    my_contribution)
        shared = self._finish_pairing(peer_info, my_contribution, theirs)
        self.register_peer(peer_info, host, port, disc.VIA_MANUAL)
        return {"peer_id": peer_info.device_id, "name": peer_info.name,
                "security_code": crypto.gen_security_code(shared)}

    def _resolve_endpoint(self, ref: str) -> tuple[str, int]:
        state = self.peer_state(ref)
        if state and state.host:
            return state.host, state.port
        host, _, port = ref.partition(":")
        return host, int(port or 5600)

    def _finish_pairing(self, peer_info: PeerInfo, mine: bytes, theirs: bytes) -> bytes:
        """两端各自算出同一个共享密钥并入库；密钥永不出网，公开侧只有 kid。"""
        shared = crypto.combine_secrets(mine, theirs, self.identity.device_id,
                                        peer_info.device_id)
        kid = crypto.kid_of(shared)
        self.store.put_secret(peer_info.device_id, kid, shared)
        self.store.upsert_device(peer_info.device_id, name=peer_info.name,
                                 kind=peer_info.kind, protocol=peer_info.protocol,
                                 via="pair")
        self.store.set_paired(peer_info.device_id, kid, crypto.gen_security_code(shared))
        self.store.add_log(peer_info.device_id, peer_info.name, "-", "pair", True,
                           details={"kid": kid})
        with self._peers_lock:
            state = self._peers.setdefault(peer_info.device_id, PeerState(peer_info.device_id))
            state.paired = True
        return shared

    def verify_security_code(self, peer_id: str, shown: str) -> bool:
        row = self.store.device(peer_id) or {}
        return bool(row.get("security_code")) and row["security_code"] == shown.strip().lower()

    def unpair(self, peer_id: str) -> None:
        """解除配对 = 删掉共享密钥：此后对端拿不到任何信封路由，包括 hub grant。"""
        self.store.forget(peer_id)
        with self._peers_lock:
            state = self._peers.get(peer_id)
            if state:
                state.paired = False
            self._dirty.pop(peer_id, None)

    # ------------------------------------------------------- 服务端侧回调
    def export_to_temp(self, peer_id: str) -> Path:
        target = self.work_dir / f"export-{int(time.time())}-{uuid.uuid4().hex[:6]}.apkg"
        try:
            self.bridge.export_package(target)
        except Busy as exc:
            raise LanError(409, "BUSY", str(exc)) from exc
        self.track_temp(target)
        return target

    def handle_import(self, peer_id: str, path: Path, declared: int, v1: bool = False,
                      direction: str = "push") -> dict:
        if declared and declared > MAX_PACKAGE_BYTES:
            raise LanError(507, "too_large")
        started = time.time()
        name = self._name_of(peer_id)
        try:
            result = self.bridge.import_package(path)
        except Busy as exc:
            self._log_import_failure(peer_id, name, path, "BUSY")
            raise LanError(409, "BUSY", str(exc)) from exc
        except LanError:
            raise
        except Exception as exc:  # noqa: BLE001 - 后端拒包也要让对端看到失败并留下记录
            self._log_import_failure(peer_id, name, path, type(exc).__name__)
            raise LanError(500, "import_failed", str(exc)) from exc
        details = {**result, "SECURITY": "plaintext-v1"} if v1 else result
        self.store.add_log(peer_id, name, MODE_APKG, direction, True,
                           duration_ms=int((time.time() - started) * 1000),
                           bytes_in=Path(path).stat().st_size, details=details)
        # 对端推来的变更不再回推给对端，否则两轮之间会打乒乓
        self.note_local_write(caused_by=peer_id or "v1")
        return {"ok": True, **result}

    def _log_import_failure(self, peer_id: str, name: str, path: Path, code: str) -> None:
        self.store.add_log(peer_id, name, MODE_APKG, "push", False, code=code,
                           details={"path": Path(path).name})

    def handle_notify(self, peer_id: str, payload: dict) -> dict:
        hub_leg = payload.get("hub")
        if hub_leg:
            threading.Thread(target=self._hub_sync_as_server, args=(peer_id, hub_leg),
                             daemon=True, name="lansync-hub-ack").start()
            return {"queued": True, "mode": MODE_HUB}
        if self.auto_round():
            # 对端说它有新变更：把它标脏，让调度器在去抖窗口内去拉
            self.mark_dirty(peer_id, reason="notify")
            return {"queued": True, "mode": MODE_APKG}
        return {"queued": False, "mode": MODE_APKG}

    def handle_hub_grant(self, peer_id: str) -> dict:
        if not self.hub_role():
            raise LanError(403, "hub_off", "this device is not offering a hub")
        if not self.hub.running:
            raise LanError(409, "hub_down")
        grant = self.own_grant()
        self.store.add_log(peer_id, self._name_of(peer_id), MODE_HUB, "grant", True)
        return grant

    def _hub_sync_as_server(self, peer_id: str, grant: dict) -> None:
        """我们自己是 hub 宿主时走回环，别把流量绕上无线。"""
        endpoint = str(grant.get("endpoint", ""))
        if self.hub.running and endpoint == self.hub.endpoint():
            endpoint = f"http://127.0.0.1:{self.hub.port}/"
        try:
            result = self.bridge.sync_to_hub(endpoint, grant["username"], grant["password"])
            self.store.add_log(peer_id, self._name_of(peer_id), MODE_HUB, "sync", True,
                               duration_ms=result["duration_ms"], details=result)
        except Exception as exc:  # noqa: BLE001 - 对端催的同步失败只记日志
            self.store.add_log(peer_id, self._name_of(peer_id), MODE_HUB, "sync", False,
                               code=_code_of(exc))

    def note_exported(self, peer_id: str, path: Path) -> None:
        self.store.add_log(peer_id, self._name_of(peer_id), MODE_APKG, "pull", True,
                           bytes_out=Path(path).stat().st_size)

    def note_v1_round(self, direction: str) -> None:
        self.store.add_log("v1-peer", "v1 (plaintext)", MODE_APKG, direction, True,
                           details={"SECURITY": "plaintext-v1"})

    def _name_of(self, peer_id: str) -> str:
        state = self.peer_state(peer_id)
        if state and state.name:
            return state.name
        return (self.store.device(peer_id) or {}).get("name") or peer_id[:8]

    # ------------------------------------------------------------ 临时文件
    def track_temp(self, path: Path) -> None:
        with self._temps_lock:
            self._temps.add(Path(path))

    def forget_temp(self, path: Path) -> None:
        with self._temps_lock:
            self._temps.discard(Path(path))
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            log.debug("临时文件删除失败 %s", path, exc_info=True)

    def _clean_temps(self) -> None:
        with self._temps_lock:
            paths, self._temps = list(self._temps), set()
        for path in paths:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass

    # ---------------------------------------------------------------- 轮次
    def _round_lock(self, peer_id: str) -> threading.Lock:
        with self._peers_lock:
            return self._round_locks.setdefault(peer_id, threading.Lock())

    def negotiate_mode(self, state: PeerState) -> str | None:
        if state.protocol < 2:
            return MODE_APKG if self.allow_v1_plaintext() else None
        # 对端"能当 hub 用"的信号是它在 serve（roles+hub_port），不是它声明支持 hub 模式：
        # 每台桌面的 modes 都含 hub，那只表示它可以作为发起端连别人的 hub。
        peer_serves = "hub" in state.roles and bool(state.hub_port)
        if self.hub_serving() and MODE_HUB in state.modes:
            # 我在 serve 且对端连得上：必须走 hub，**不能**退到 apkg —— 整库推过去会把
            # 对端已经删掉的卡片复活，等于亲手废掉 hub 的 graves 语义。
            return MODE_HUB
        return pick_mode(self.my_modes(), state.modes, peer_has_hub=peer_serves)

    def sync_round(self, peer_id: str, mode: str | None = None,
                   full: str | None = None) -> dict:
        state = self.peer_state(peer_id) or self.find_peer(peer_id)
        if state is None:
            raise LanError(409, "no_endpoint", peer_id[:8])
        peer_id = state.peer_id  # 后面全部按真 id 记锁与日志，不接受前缀/名字
        if not state.host or not state.port:
            raise LanError(409, "no_endpoint", peer_id[:8])
        lock = self._round_lock(peer_id)
        if not lock.acquire(blocking=False):
            self.store.add_log(peer_id, state.name, mode or "-", "round", False, code="BUSY")
            return {"ok": False, "code": "busy"}
        mode = mode or self.negotiate_mode(state)
        if mode is None:
            lock.release()
            raise LanError(403, "no_common_mode", f"peer modes={state.modes}")
        started = time.time()
        self.progress = {"peer": state.name or peer_id[:8], "mode": mode, "phase": "start",
                         "started": started}
        self._last_round[peer_id] = started
        try:
            result = (self._round_apkg(state) if mode == MODE_APKG
                      else self._round_hub(state, full=full))
        except LanError as exc:
            self._log_round(state, mode, started, code=exc.code)
            raise
        except Exception as exc:  # noqa: BLE001 - 网络/后端异常都要落进同步历史
            self._log_round(state, mode, started, code=_code_of(exc))
            raise
        finally:
            self.progress = {}
            lock.release()
        self._log_round(state, mode, started, result=result)
        return {"ok": True, "mode": mode, **result}

    def hub_seed(self, peer_ref: str, upload: bool) -> dict:
        """显式裁决"两边都有内容谁覆盖谁"：`upload=True` 以本机为种子，否则加入 hub 的库。

        自动轮次遇到这种分歧会记一次 `hub_seed_required` 失败而**不会**替用户选（悄悄
        full_upload 会把另一台刚播下的库整库换掉）。
        """
        return self.sync_round(peer_ref, MODE_HUB,
                               full="upload" if upload else "download")

    def _log_round(self, state: PeerState, mode: str, started: float,
                   code: str = "", result: dict | None = None) -> None:
        self.store.add_log(state.peer_id, state.name, mode, "round", result is not None,
                           code=code, duration_ms=int((time.time() - started) * 1000),
                           details=result or {})

    def _round_apkg(self, state: PeerState) -> dict:
        v1 = state.protocol < 2
        out: dict = {"mode": MODE_APKG, "push": None, "pull": None}
        export = self.export_to_temp(state.peer_id)
        try:
            self.progress.update(phase="push", bytes=export.stat().st_size)
            out["push"] = (self.client.v1_push_package(state.host, state.port, export)
                           if v1 else
                           self.client.push_package(state.host, state.port, state.peer_id,
                                                    export))
        finally:
            self.forget_temp(export)
        incoming = self.work_dir / f"in-{int(time.time())}-{uuid.uuid4().hex[:6]}.apkg"
        self.track_temp(incoming)
        try:
            self.progress.update(phase="pull")
            size = (self.client.v1_pull_package(state.host, state.port, incoming) if v1 else
                    self.client.pull_package(state.host, state.port, state.peer_id, incoming,
                                             progress=self._on_pull_bytes))
            out["pull"] = self._import_local(state.peer_id, incoming, size, v1=v1)
        finally:
            self.forget_temp(incoming)
        if v1:
            out["SECURITY"] = "plaintext-v1"
        return out

    def _on_pull_bytes(self, written: int) -> None:
        self.progress.update(bytes_pulled=written)

    def _import_local(self, peer_id: str, path: Path, size: int, v1: bool = False) -> dict:
        """拉回来的包在本地导入：与对端推进来的处理一致，但方向记 pull。"""
        return self.handle_import(peer_id, path, size, v1=v1, direction="pull")

    def own_grant(self) -> dict:
        """我自己就是 hub 宿主时的凭据：不必向自己发一次 HTTP 要 grant。"""
        username, password = self.hub.grant_shared()
        return {"endpoint": self.hub.endpoint(), "username": username,
                "password": password, "profile": self.bridge.profile, "mode": MODE_HUB}

    def _round_hub(self, state: PeerState, full: str | None = None) -> dict:
        # 我是宿主时用自己的凭据（流量走回环），否则向对端要一份 grant
        grant = (self.own_grant() if self.hub_serving()
                 else self.client.hub_grant(state.host, state.port, state.peer_id))
        self.progress.update(phase="hub_sync")
        local = self.bridge.sync_to_hub(grant["endpoint"], grant["username"],
                                        grant["password"], full=full)
        self.store.add_log(state.peer_id, state.name, MODE_HUB, "sync", True,
                           duration_ms=local["duration_ms"], details=local)
        self.progress.update(phase="hub_peer_sync")
        # 对端也要把它自己的变更推上 hub，否则它本地的那一半永远不上桌
        ack = self.client.notify(state.host, state.port, state.peer_id, {"hub": grant})
        return {"mode": MODE_HUB, "local": local, "peer_ack": ack}

    def sync_all(self, include_offline: bool = False) -> list[dict]:
        results = []
        for state in self.paired_peers(online_only=not include_offline):
            try:
                results.append({"peer_id": state.peer_id, **self.sync_round(state.peer_id)})
            except LanError as exc:
                results.append({"peer_id": state.peer_id, "ok": False, "code": exc.code,
                                "message": str(exc)})
        return results

    # -------------------------------------------------------- 调度器接口
    def mark_dirty(self, peer_id: str, reason: str = "") -> None:
        with self._state_lock:
            self._dirty[peer_id] = time.time()
        if reason:
            log.debug("peer %s 待同步：%s", peer_id[:8], reason)

    def note_local_write(self, caused_by: str = "") -> None:
        """本地集合变了（含对端导入）：给除来源外的所有已配对 peer 记一次待同步。"""
        targets = [s.peer_id for s in self.paired_peers(online_only=False)]
        now = time.time()
        with self._state_lock:
            for peer_id in targets:
                if peer_id != caused_by:
                    self._dirty.setdefault(peer_id, now)

    def due_peers(self, debounce: float, min_interval: float) -> list[str]:
        now = time.time()
        ready = {s.peer_id for s in self.paired_peers(online_only=True)}
        with self._state_lock:
            due = [pid for pid, dirty_at in self._dirty.items()
                   if pid in ready and now - dirty_at >= debounce
                   and now - self._last_round.get(pid, 0.0) >= min_interval]
        return due

    def clear_dirty(self, peer_ids: list[str]) -> None:
        with self._state_lock:
            for pid in peer_ids:
                self._dirty.pop(pid, None)

    def request_immediate(self, reason: str) -> None:
        """开关打开 / 对端 notify 之外的"别等下一轮"：留给调度器 1s 内消费。"""
        with self._state_lock:
            self._immediate.append(reason)

    def consume_immediate(self) -> list[str]:
        with self._state_lock:
            reasons, self._immediate = self._immediate, []
        return reasons

    def last_round(self, peer_id: str) -> float:
        with self._state_lock:
            return self._last_round.get(peer_id, 0.0)

    # ---------------------------------------------------------------- 状态
    def state(self) -> dict:
        discovery = self.discovery
        return {
            "identity": {"device_id": self.identity.device_id, "id8": self.identity.device_id[:8],
                         "name": self.identity.name, "kind": self.identity.kind,
                         "machine_uid": self.identity.machine_uid},
            "enabled": self.enabled(),
            "running": self.server is not None,
            "port": self.port,
            "uptime_secs": int(time.time() - self.started_at),
            "modes": self.my_modes(),
            "config": {"allow_v1_plaintext": self.allow_v1_plaintext(),
                       "hub_role": self.hub_role(), "hub_bind": self.hub_bind(),
                       "auto_round": self.auto_round(), "interval_secs": self.interval_secs()},
            "peers": self.peers(),
            "paired": [row["peer_id"] for row in self.store.devices() if row["paired"]],
            "hub": self.hub.status() if self.hub_role() else {"running": False},
            "discovery": {"mdns": bool(discovery and discovery.mdns_ok),
                          "udp": bool(discovery and discovery.udp_ok)},
            "counts": self.safe_counts(),
            "progress": dict(self.progress),
            "log": self.store.logs(20),
        }

    def safe_counts(self) -> dict:
        try:
            return self.bridge.counts()
        except Exception as exc:  # noqa: BLE001 - 状态面板不该因为集合被占就整块失败
            return {"error": type(exc).__name__}
