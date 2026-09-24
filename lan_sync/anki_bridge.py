"""Anki 后端桥：集合句柄、apkg 导出/导入、hub 模式真协议同步。

流程按 .probe/dataplane_probe.py 实测通过的写法固定下来：
- apkg：export_anki_package(whole collection, 带排程/牌组配置/媒体) → 对端 import(IF_NEWER)
- hub：sync_login → sync_collection；遇到 FULL_UPLOAD/FULL_DOWNLOAD 必须
  close_for_full_sync() → full_upload_or_download() → reopen(after_full_sync=True)，
  期间不得另建 Collection 句柄（会撞 "Anki already open"）。
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

FULL_VALUES = {"FULL_UPLOAD", "FULL_DOWNLOAD", "FULL_SYNC"}


class Busy(Exception):
    """集合被占用；调用方应映射成 409 BUSY，让对端重试而不是死锁。"""


class CollectionBridge:
    def __init__(self, collection_path: Path | str, profile: str = "current",
                 lock_timeout_secs: float = 90.0) -> None:
        self.path = Path(collection_path)
        self.profile = profile
        self.lock_timeout_secs = lock_timeout_secs
        self._col = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------ 句柄管理
    def _ensure_open(self):
        from anki.collection import Collection

        if self._col is None:
            self._col = Collection(str(self.path))
        return self._col

    def close(self) -> None:
        with self._lock:
            if self._col is not None:
                try:
                    self._col.close()
                finally:
                    self._col = None

    def exclusive(self):
        """只在本地导出/导入期间持有；网络传输绝不在此锁内。"""

        class _Gate:
            def __enter__(inner):  # noqa: N805
                if not self._lock.acquire(timeout=self.lock_timeout_secs):
                    raise Busy(f"collection busy for >{self.lock_timeout_secs}s")
                return self._ensure_open()

            def __exit__(inner, *exc):  # noqa: N805
                self._lock.release()

        return _Gate()

    # --------------------------------------------------------------- 统计
    def counts(self) -> dict:
        with self.exclusive() as col:
            return {
                "notes": col.db.scalar("select count(*) from notes"),
                "cards": col.db.scalar("select count(*) from cards"),
                "graves": col.db.scalar("select count(*) from graves"),
                "pending_usn": col.db.scalar("select count(*) from notes where usn=-1"),
                # 变更水位线：pylib 这版没暴露 get_collection_timestamps，用 notes.mod 最大值
                "mod": col.db.scalar("select ifnull(max(mod), 0) from notes") or 0,
            }

    # ---------------------------------------------------------- apkg 数据面
    def export_package(self, out_path: Path | str) -> int:
        from anki.collection import ExportAnkiPackageOptions

        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with self.exclusive() as col:
            options = ExportAnkiPackageOptions(
                with_scheduling=True, with_deck_configs=True, with_media=True
            )
            col.export_anki_package(out_path=str(out_path), options=options, limit=None)
        return out_path.stat().st_size

    def import_package(self, package_path: Path | str) -> dict:
        from anki.collection import ImportAnkiPackageRequest
        from anki.import_export_pb2 import (
            ImportAnkiPackageOptions,
            ImportAnkiPackageUpdateCondition as Cond,
        )

        before = self.counts()
        with self.exclusive() as col:
            request = ImportAnkiPackageRequest(
                package_path=str(package_path),
                options=ImportAnkiPackageOptions(
                    merge_notetypes=True,
                    update_notes=Cond.Value("IMPORT_ANKI_PACKAGE_UPDATE_CONDITION_IF_NEWER"),
                    update_notetypes=Cond.Value("IMPORT_ANKI_PACKAGE_UPDATE_CONDITION_IF_NEWER"),
                    with_scheduling=True,
                ),
            )
            col.import_anki_package(request)
        after = self.counts()
        return {
            "before": before,
            "after": after,
            "notes_added": after["notes"] - before["notes"],
            "cards_added": after["cards"] - before["cards"],
        }

    # ----------------------------------------------------------- hub 数据面
    def sync_to_hub(self, endpoint: str, username: str, password: str,
                    sync_media: bool = True, full: str | None = None) -> dict:
        """一次集合同步。`full` 是本机对"两边都有内容"这场的裁决，见 `_decide_full_sync`。

        - `None`（默认，自动）：只跟着 rslib 的判定走；`FULL_SYNC` 会抛 `HubSeedRequired`。
        - `"upload"`：以本机为准整库覆盖 hub（当种子）。
        - `"download"`：以 hub 为准丢弃本机（加入别人的库）。
        """
        started = time.time()
        steps: list[str] = []
        with self._lock:
            col = self._ensure_open()
            auth = col.sync_login(username=username, password=password, endpoint=endpoint)
            out = col.sync_collection(auth, sync_media=False)
            required = _required_name(out.required)
            steps.append(required)
            if required in FULL_VALUES:
                upload = self._decide_full_sync(col, required, full)
                col.close_for_full_sync()
                col.full_upload_or_download(
                    auth=auth, server_usn=out.server_media_usn, upload=upload
                )
                col.reopen(after_full_sync=True)
                self._col = col
                steps.append("full_" + ("upload" if upload else "download"))
                out = col.sync_collection(auth, sync_media=False)
                steps.append(_required_name(out.required))
            if sync_media:
                try:
                    col.sync_media(auth)
                    steps.append("media")
                except Exception as exc:  # noqa: BLE001 - 媒体失败不该让整轮失败
                    steps.append(f"media_failed:{type(exc).__name__}")
            after = {
                "notes": col.db.scalar("select count(*) from notes"),
                "cards": col.db.scalar("select count(*) from cards"),
            }
        return {"steps": steps, "after": after, "duration_ms": int((time.time() - started) * 1000)}

    @staticmethod
    def _decide_full_sync(col, required: str, full: str | None) -> bool:
        """全量传输方向的裁决。

        - `FULL_UPLOAD`：服务端这个 hkey 下还没有库，上传不会覆盖任何人的数据。
        - `FULL_DOWNLOAD`：rslib 判定本机没有值得保留的东西。
        - `FULL_SYNC`：**两边都有内容且互不相干**。一个 hkey 就是一个命名空间，
          悄悄 full_upload 会把另一台刚播下的库整个换掉、它的卡片直接消失，所以这里
          必须停下来要用户显式 seed / adopt，不能替他选。
        """
        if full is not None:
            return full == "upload"
        if required == "FULL_SYNC":
            raise HubSeedRequired(
                f"hub 与本机都有内容（local_notes={col.note_count()}），谁覆盖谁必须显式决定"
            )
        return required != "FULL_DOWNLOAD"


class HubSeedRequired(Exception):
    """两边各有内容、无法自动判定谁覆盖谁；要用户显式 seed / adopt。"""

    code = "hub_seed_required"


_REQUIRED_NAMES = {0: "NO_CHANGES", 1: "NORMAL_SYNC", 2: "FULL_SYNC",
                   3: "FULL_DOWNLOAD", 4: "FULL_UPLOAD"}


def _required_name(value: int) -> str:
    return _REQUIRED_NAMES.get(int(value), f"UNKNOWN({value})")
