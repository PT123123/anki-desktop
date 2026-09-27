"""AnkiQt 侧的接线：工具菜单一项 + 复用当前配置目录的引擎。

刻意**不在本进程启动服务**：`LanEngine.start()` 会带起调度器，而调度器一轮同步就要用
`CollectionBridge` 再开一次库 —— Anki 自己开着同一个库时那是打不开的（rslib 独占）。
所以界面只做"出码/扫码/核对"这三件不碰库的事，监听仍由 `python -m lan_sync serve`
那个进程负责；两边共用同一份 `sync.db`，出码用的端口就是从它里面读的（`bound_port`）。
"""

from __future__ import annotations

from pathlib import Path

from .engine import LanEngine

MENU_TITLE = "局域网配对二维码…"
_menu_action = None
_engine: LanEngine | None = None


def default_data_dir(collection_path: Path | str) -> Path:
    """和 CLI 的默认值保持一致：库旁边的 `lansync/`。"""
    return Path(collection_path).parent / "lansync"


def engine_for_mw(mw) -> LanEngine:
    """当前 profile 的引擎单例（不启动服务）。"""
    global _engine
    if _engine is not None:
        return _engine
    collection_path = Path(mw.col.path)
    _engine = LanEngine(
        data_dir=default_data_dir(collection_path),
        collection_path=collection_path,
        profile=getattr(mw.pm, "name", "current"),
    )
    return _engine


def open_pair_qr_dialog(mw) -> None:
    from .qtui import PairQrDialog

    PairQrDialog(engine_for_mw(mw), mw).exec()


def register_tools_entry(mw) -> object:
    """把入口挂进"工具"菜单底部；重复调用只留一项。"""
    global _menu_action
    if _menu_action is not None:
        return _menu_action
    from aqt.qt import QAction

    action = QAction(MENU_TITLE, mw)
    action.triggered.connect(lambda: open_pair_qr_dialog(mw))
    mw.form.menuTools.addAction(action)
    _menu_action = action
    return action
