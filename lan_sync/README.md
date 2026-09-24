# LAN sync（桌面端）

权威协议规格在仓库外的 `../../docs/lan-sync/SPEC-v2.md`（相对 `anki-desktop/`）。
本文件只是指针 + 本地入口，**不要在这里改字段语义**。

## 代码

- `lan_sync/` —— 控制面 + 数据面实现：
  `protocol.py`（常量/信封格式）、`crypto.py`（HKDF/AES-GCM/配对密钥）、`store.py`（`sync.db`）、
  `identity.py`、`discovery.py`（mDNS + UDP 广播 + 地址选择）、`client.py`/`server.py`（HTTP）、
  `engine.py`（配对/协商/一轮同步）、`hub.py`（`SimpleServer` 子进程）、`anki_bridge.py`
  （apkg 导出导入、hub 真协议同步、`FULL_SYNC` 封口）、`scheduler.py`、`cli.py`。
- `tools/lansync_e2e.py` —— 端到端台架，67 条断言，臂名含义见 SPEC §10。
- `tests/lan_sync/` —— 单元层（加密、配对定序、协商、信封、路由）。

## 跑起来

```bash
# 台架（同机起两个真实实例，无需 Anki GUI）
../.venv-lansync/Scripts/python.exe tools/lansync_e2e.py

# 单元测试
../.venv-lansync/Scripts/python.exe -m pytest tests/lan_sync -q

# CLI
../.venv-lansync/Scripts/python.exe -m lan_sync serve
../.venv-lansync/Scripts/python.exe -m lan_sync peers
../.venv-lansync/Scripts/python.exe -m lan_sync sync
```

## 已知边界（未验证项）

真机/局域网环境下的表现尚未验证：AP 隔离路由下的广播、VPN 下的地址选择、
含大量媒体的 `.apkg` 多轮收敛。这些与安卓侧待验证清单一起列在 SPEC §11。
