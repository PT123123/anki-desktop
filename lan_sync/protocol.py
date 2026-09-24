"""Anki 局域网同步（桌面端）· 线上协议层。

字段语义以 docs/lan-sync/SPEC-v2.md 为准，不要在这里私改。
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field, fields

PROTOCOL_VERSION = 2
MAGIC_V2 = "ANKI-LAN/2"
MAGIC_V1 = "ANKIPLUS-LAN/1"

TCP_PORT_START = 5600
TCP_PORT_END = 5610
UDP_PORT = 46000
HUB_PORT_START = 8080
HUB_PORT_END = 8090

MDNS_SERVICE = "_ankisync._tcp.local."
ANNOUNCE_INTERVAL_SECS = 5.0
OFFLINE_AFTER_SECS = 20.0
UI_TICK_SECS = 2.0
MDNS_SUPPRESS_WINDOW_SECS = 45.0
PROBE_THROTTLE_SECS = 15.0
MAX_PACKAGE_BYTES = 1024 ** 3

HEADER_MAGIC = "X-Anki-Sync"
HEADER_KID = "X-Anki-Kid"
HEADER_TS = "X-Anki-Ts"
HEADER_PEER = "X-Anki-Peer"
HEADER_PEER_ID = "X-Anki-Peer-Id"
HEADER_V1_MAGIC = "X-Ankiplus-Lansync"
# 大载荷路由（导入/导出）把信封放在头里，body 留给 `.apkg` 原始字节
HEADER_ENVELOPE = "X-Anki-Envelope"
# 导出响应回显请求信封里的 nonce，把这段明文字节绑定到一次已认证的请求
HEADER_XFER = "X-Anki-Xfer"

MODE_APKG = "apkg"
MODE_HUB = "hub"
KIND_DESKTOP = "desktop"
KIND_ANDROID = "android"


class LanError(Exception):
    """带 HTTP 状态与机器可读 code 的协议错误。"""

    def __init__(self, status: int, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.status = status
        self.code = code


@dataclass
class PeerInfo:
    """`GET /info` 的响应体，也是 announce 包的载荷。不含任何密钥。"""

    device_id: str = ""
    name: str = ""
    kind: str = KIND_DESKTOP
    protocol: int = PROTOCOL_VERSION
    modes: list[str] = field(default_factory=lambda: [MODE_APKG, MODE_HUB])
    roles: list[str] = field(default_factory=list)
    port: int = 0
    kids: list[str] = field(default_factory=list)
    ts: int = 0
    hub_port: int = 0

    def to_json(self, v1_compat: bool = False) -> str:
        """`v1_compat=True` 时附带 v1（已上线的安卓端）必读的字段别名。

        v1 的 `LanPeerInfo` 要求 `id` 存在，缺了 kotlinx 直接抛异常并拒掉这个 peer，
        所以对 v1 探针必须双写。
        """
        data = asdict(self)
        if v1_compat:
            data.update(
                {"id": self.device_id, "platform": self.kind, "appVersion": "", "sentAt": self.ts}
            )
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str | bytes) -> PeerInfo:
        """容忍未知字段（v1 单测已要求，v2 继续）；同时吃下 v1 的字段别名。"""
        data = json.loads(raw)
        if "device_id" not in data and "id" in data:
            data["device_id"] = data["id"]
        if "kind" not in data and "platform" in data:
            data["kind"] = data["platform"]
        if "ts" not in data and "sentAt" in data:
            data["ts"] = data["sentAt"]
        known = {f.name for f in fields(cls)}
        info = cls(**{k: v for k, v in data.items() if k in known})
        if info.protocol < PROTOCOL_VERSION:
            # v1 只实现了 apkg 累积合并；别让它冒充自己支持 hub/配对
            info.modes = [MODE_APKG]
            info.roles = []
            info.kids = []
        return info


MDNS_SERVICE_V1 = "_ankiplus-sync._tcp.local."
NSD_NAME_PREFIX_V1 = "AnkiPlus-"


def encode_announce(info: PeerInfo, magic: str = MAGIC_V2) -> bytes:
    info = PeerInfo(**{**asdict(info), "ts": info.ts or 0})
    v1 = magic == MAGIC_V1
    payload = info.to_json(v1_compat=v1)
    return f"{magic} ".encode("ascii") + payload.encode("utf-8")


def decode_announce(raw: bytes) -> tuple[int, PeerInfo] | None:
    """返回 (协议版本, PeerInfo)；不是我们的包就返回 None，绝不抛。"""
    for magic, version in ((MAGIC_V2, PROTOCOL_VERSION), (MAGIC_V1, 1)):
        prefix = magic.encode("ascii") + b" "
        if raw.startswith(prefix):
            try:
                return version, PeerInfo.from_json(raw[len(prefix) :])
            except (ValueError, TypeError):
                return None
    return None


def pick_mode(my_modes: list[str], peer_modes: list[str], peer_has_hub: bool) -> str | None:
    """hub > apkg；交集为空则不可同步。"""
    common = [m for m in (MODE_HUB, MODE_APKG) if m in my_modes and m in peer_modes]
    if MODE_HUB in common and peer_has_hub:
        return MODE_HUB
    if MODE_APKG in common:
        return MODE_APKG
    return common[0] if common else None


def is_site_local_ipv4(addr: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    return ip.is_private and not ip.is_loopback and not ip.is_link_local


def subnet_broadcast(addr: str, netmask_bits: int = 24) -> str | None:
    """子网定向广播；AP 常丢 255.255.255.255，所以两个都要发。"""
    try:
        net = ipaddress.IPv4Network(f"{addr}/{netmask_bits}", strict=False)
    except ValueError:
        return None
    return str(net.broadcast_address)
