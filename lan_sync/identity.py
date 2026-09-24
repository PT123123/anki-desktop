"""设备身份与可宣告地址（SPEC-v2 §2、§3.7）。"""

from __future__ import annotations

import getpass
import platform
import socket
import uuid
from dataclasses import dataclass

from .protocol import KIND_DESKTOP, is_site_local_ipv4, subnet_broadcast

# 不发包的 UDP connect：只为让内核选出默认路由地址
_PROBE_TARGETS = ("192.0.2.1", "10.255.255.1")


@dataclass(frozen=True)
class Identity:
    device_id: str
    name: str
    kind: str = KIND_DESKTOP
    machine_uid: str = ""


def machine_uid() -> str:
    """粗粒度机器标识，用于重装后提示归并（不自动折叠）。"""
    node = platform.node().lower()
    mac = uuid.getnode()
    return f"{node}:{mac:012x}"


def _default_route_address() -> str | None:
    for target in _PROBE_TARGETS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((target, 1))
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
    return None


def candidate_addresses() -> list[str]:
    """本机所有 site-local IPv4，按可宣告优先级排序。

    拒绝回环/链路本地/公网地址：宣告它们会让对端连到一个不存在的宿主。
    """
    found: list[str] = []
    default = _default_route_address()
    if default:
        found.append(default)
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        infos = []
    for info in infos:
        addr = info[4][0]
        if addr not in found:
            found.append(addr)
    usable = [a for a in found if is_site_local_ipv4(a)]
    # 默认路由地址已经排在最前；这里只去重、保持稳定次序
    return list(dict.fromkeys(usable))


def best_address() -> str | None:
    addrs = candidate_addresses()
    return addrs[0] if addrs else None


def announce_targets(addr: str | None) -> list[str]:
    """全局广播 + 子网定向广播：多数 AP 会丢前者，所以两个都发。"""
    targets = ["255.255.255.255"]
    if addr:
        subnet = subnet_broadcast(addr)
        if subnet and subnet not in targets:
            targets.append(subnet)
    return targets


def load_or_create(store) -> Identity:
    existing = store.get_meta("device_id")
    if existing:
        return Identity(existing, store.get_meta("device_name") or _default_name(),
                        KIND_DESKTOP, store.get_meta("machine_uid") or machine_uid())
    ident = Identity(str(uuid.uuid4()), _default_name(), KIND_DESKTOP, machine_uid())
    store.set_meta("device_id", ident.device_id)
    store.set_meta("device_name", ident.name)
    store.set_meta("machine_uid", ident.machine_uid)
    return ident


def _default_name() -> str:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - 某些环境取不到用户名
        user = ""
    node = platform.node() or "desktop"
    return f"{node}-{user[:6]}" if user else node
