# LAN sync（桌面端）

权威协议规格在仓库外的 `../../docs/lan-sync/SPEC-v2.md`（相对 `anki-desktop/`）。
本文件只是指针 + 本地入口，**不要在这里改字段语义**。

## 代码

- `lan_sync/` —— 控制面 + 数据面实现：
  `protocol.py`（常量/信封格式）、`crypto.py`（HKDF/AES-GCM/配对密钥）、`store.py`（`sync.db`）、
  `identity.py`、`discovery.py`（mDNS + UDP 广播 + 地址选择）、`client.py`/`server.py`（HTTP）、
  `engine.py`（配对/协商/一轮同步）、`hub.py`（`SimpleServer` 子进程）、`anki_bridge.py`
  （apkg 导出导入、hub 真协议同步、`FULL_SYNC` 封口）、`scheduler.py`、`cli.py`。
- **配对二维码**（SPEC §4.7）：`pairqr.py` 是票据文本 ↔ 字段的编解码（纯 ASCII、无依赖）；
  `qrimg.py` 出图/读图（segno 渲染 PNG/SVG/终端半块码，opencv 从图片文件解回文本，**惰性导入**，
  没装这两个包时其余命令与单测都不受影响）；`qtui.py` 是 `PairQrDialog`（亮码 + 选图扫码 +
  互信表/安全码/解除配对）；`aqt_hook.py` + `addon/__init__.py` 把它挂进 Anki 的"工具"菜单。
  无摄像头的电脑端"扫码"= **导入一张二维码图片**（截图、传过来的文件都行）。
- **GUI 不在进程内起服务**：`CollectionBridge` 打不开 Anki 已经持有的库，所以对话框只共用同一份
  `sync.db`（含常驻 `serve` 进程写的 `bound_port`）。要先 `lansync serve`，GUI 只负责出码/扫码。
- `tools/lansync_e2e.py` —— 端到端台架，73 条断言，臂名含义见 SPEC §10。
- `tools/lansync_vectors.py` —— 生成/校验 `docs/lan-sync/vectors.json`（含 `pair_qr` 段）双副本。
- `tests/lan_sync/` —— 单元层（加密、配对定序、协商、信封、路由、票据、出图/读图往返、
  离屏 `test_qtui.py`）。

## 跑起来

```bash
# 台架（同机起两个真实实例，无需 Anki GUI）
../.venv-lansync/Scripts/python.exe tools/lansync_e2e.py

# 单元测试
../.venv-lansync/Scripts/python.exe -m pytest tests/lan_sync -q

# 离屏 Qt 对话框测试（要带 PyQt6 的源码构建环境，不是 .venv-lansync）
QT_QPA_PLATFORM=offscreen out/pyenv/Scripts/python.exe -m pytest tests/lan_sync/test_qtui.py -q

# CLI
../.venv-lansync/Scripts/python.exe -m lan_sync serve
../.venv-lansync/Scripts/python.exe -m lan_sync peers
../.venv-lansync/Scripts/python.exe -m lan_sync sync

# 配对二维码：亮码 / 扫码（扫码=读图片文件）
../.venv-lansync/Scripts/python.exe -m lan_sync pair show-qr --out pair.png
../.venv-lansync/Scripts/python.exe -m lan_sync pair scan-qr pair.png
# 手动兜底仍在：pair show-code / pair join <ip:port> <码> / pair confirm <peer_id>

# 把"工具 → 局域网配对二维码"装进 Anki 的 add-ons 目录（装完重启 Anki）
../.venv-lansync/Scripts/python.exe -m lan_sync addon-install
```

## 已知边界（未验证项）

真机/局域网环境下的表现尚未验证：AP 隔离路由下的广播、VPN 下的地址选择、
含大量媒体的 `.apkg` 多轮收敛。这些与安卓侧待验证清单一起列在 SPEC §11。

配对二维码额外两条：
- 票据里的内网 IP 在真实 Wi-Fi 下能否被对端连上并 commit —— 台架绑 127.0.0.1，
  所以 E7qr 走的是"票据里的码 + loopback"，没证明 host 可达。
- AnkiQt 的"工具 → 局域网配对二维码"对话框只做过离屏测试，**菜单项、PNG 出图、选图扫码
  在真实 Anki 窗口里没人点过**，需要手工点一遍。
