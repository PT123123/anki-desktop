"""Anki 局域网同步（桌面端）。

控制面/数据面分层与字段语义见 `docs/lan-sync/SPEC-v2.md`（双端唯一权威规格）。
公开入口只有 `LanEngine` 与 `Scheduler`；其余模块是实现细节。
"""

from .engine import LanEngine, PeerState
from .protocol import MODE_APKG, MODE_HUB, PROTOCOL_VERSION, LanError
from .scheduler import Scheduler
from .store import Store

__all__ = ["LanEngine", "PeerState", "Scheduler", "Store", "LanError",
           "PROTOCOL_VERSION", "MODE_APKG", "MODE_HUB"]
