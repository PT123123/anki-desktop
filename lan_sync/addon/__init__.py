# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 PT123123 <31439216+PT123123@users.noreply.github.com>

"""Anki add-on 壳：把「工具 → 局域网配对二维码」接到仓库里的 `lan_sync`。

这个目录是唯一会被 Anki 加载的东西，里面**不放任何协议逻辑**：它只负责找到
`anki-desktop` 的仓库根，把它加进 `sys.path`，然后交给 `lan_sync.aqt_hook`。
所以改 `lan_sync/` 的代码不需要重装 add-on，重启 Anki 就生效。

装法见 `python -m lan_sync addon-install`（把本目录拷进 Anki 的 add-ons 目录）。
源码构建下仓库根能从 `aqt.__file__` 直接推出来（`<root>/qt/aqt/__init__.py`），
不需要配置；打包版 Anki 里推不出来，就读同目录的 `config.json`。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aqt import gui_hooks, mw


def _candidate_roots() -> list[Path]:
    roots: list[Path] = []
    try:
        import aqt

        roots.append(Path(aqt.__file__).resolve().parent.parent.parent)
    except Exception:
        pass
    config = Path(__file__).with_name("config.json")
    if config.is_file():
        try:
            roots.append(Path(json.loads(config.read_text(encoding="utf-8"))["anki_desktop"]))
        except Exception:
            pass
    return roots


def _on_main_window() -> None:
    for root in _candidate_roots():
        if (root / "lan_sync" / "aqt_hook.py").is_file():
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from lan_sync.aqt_hook import register_tools_entry

            register_tools_entry(mw)
            return


gui_hooks.main_window_did_init.append(_on_main_window)
