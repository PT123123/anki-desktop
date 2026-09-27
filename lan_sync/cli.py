"""桌面端局域网同步的命令行入口。

没有 GUI 的原因：这一层的价值在协议与数据面，GUI 属于 AnkiQt（仓库里那套 Qt 前端），
接进去是另一个竖切。CLI 覆盖同样的操作面，也正好是测试台架要用的驱动方式。

集合锁：Anki 打开着自己的库时这里打不开（rslib 独占），所以 `--collection` 既可以指
真实库（用完 Anki 再跑同步），也可以指独立的库文件（台架、离线转换）。
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import sys
import time
from pathlib import Path

from .engine import LanEngine
from .scheduler import Scheduler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lan_sync", description="Anki 局域网同步（桌面端）")
    parser.add_argument("--collection", type=Path, required=True,
                        help="collection.anki2 路径")
    parser.add_argument("--data-dir", type=Path, default=None,
                        help="元数据目录，默认 <集合所在目录>/lansync")
    parser.add_argument("--profile", default="current")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("state", help="打印当前状态 JSON")
    sub.add_parser("peers", help="列出已知设备")
    sub.add_parser("enable", help="打开开关并常驻")
    sub.add_parser("disable", help="关闭开关")
    sub.add_parser("logs", help="最近同步历史")

    serve = sub.add_parser("serve", help="启动服务 + 发现 + 调度，前台运行")
    serve.add_argument("--interval", type=int, default=None, choices=[10, 300, 1800],
                       help="同步周期档位（秒）")

    pair = sub.add_parser("pair", help="配对")
    pair.add_argument("action",
                      choices=["show-code", "join", "confirm", "show-qr", "scan-qr"])
    pair.add_argument("peer", nargs="?",
                      help="join: peer_id 或 ip:port / confirm: peer_id / scan-qr: 二维码图片路径")
    pair.add_argument("code", nargs="?", help="join: 对方显示的 6 位码 / confirm: 4 位安全码")
    pair.add_argument("--out", type=Path, default=None,
                      help="show-qr: 把二维码写成图片文件（.svg 或 --svg 出矢量；否则 PNG）")
    pair.add_argument("--svg", action="store_true", help="show-qr: --out 时写 SVG 而不是 PNG")
    pair.add_argument("--no-terminal", dest="terminal", action="store_false",
                      help="show-qr: 不在终端打印二维码（只出 JSON/图片）")

    sync = sub.add_parser("sync", help="立刻跑一轮")
    sync.add_argument("peer", nargs="?", help="留空则同步所有在线已配对设备")

    hub = sub.add_parser("hub", help="hub 模式（内置 rslib 同步服务器）")
    hub.add_argument("action",
                     choices=["on", "off", "rotate", "status", "seed", "adopt"])
    hub.add_argument("--lan", action="store_true", help="on: 绑局域网地址而不是 127.0.0.1")
    hub.add_argument("--peer", default="", help="seed/adopt: 对端（id / id 前缀 / 名字）")

    v1 = sub.add_parser("v1", help="与还在跑 v1 的安卓 fork 互通（明文，默认关闭）")
    v1.add_argument("action", choices=["on", "off"])

    config = sub.add_parser("config", help="读/写配置项")
    config.add_argument("key")
    config.add_argument("value", nargs="?")

    addon = sub.add_parser("addon-install",
                           help="把「工具 → 局域网配对二维码」装进 Anki 的 add-ons 目录")
    addon.add_argument("--anki-desktop", type=Path, default=None,
                       help="仓库根，默认取当前 lan_sync 的上级目录")

    return parser


def _engine(args) -> LanEngine:
    data_dir = args.data_dir or (Path(args.collection).parent / "lansync")
    return LanEngine(data_dir, args.collection, profile=args.profile)


def _print(payload) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def cmd_state(args) -> int:
    engine = _engine(args)
    try:
        _print(engine.state())
    finally:
        engine.store.close()
    return 0


def cmd_peers(args) -> int:
    engine = _engine(args)
    try:
        _print({"peers": engine.peers(), "stored": engine.store.devices()})
    finally:
        engine.store.close()
    return 0


def cmd_logs(args) -> int:
    engine = _engine(args)
    try:
        _print(engine.store.logs(50))
    finally:
        engine.store.close()
    return 0


def cmd_enable(args) -> int:
    engine = _engine(args)
    engine.set_cfg("enabled", True)
    _print({"enabled": True, "next": "跑 `serve` 让 HTTP + 发现 + 调度常驻"})
    engine.store.close()
    return 0


def cmd_disable(args) -> int:
    engine = _engine(args)
    engine.set_cfg("enabled", False)
    # 正在跑的 serve 会在下一跳（1s 内）看到开关变了并关掉端口
    _print({"enabled": False, "note": "常驻的 serve 会在 1s 内停止监听"})
    engine.store.close()
    return 0


def cmd_pair(args) -> int:
    engine = _engine(args)
    try:
        if args.action == "show-code":
            _print(engine.begin_pairing())
        elif args.action == "show-qr":
            from . import qrimg  # 惰性：只有出码才需要 segno

            info = engine.show_pair_qr()
            if args.out is not None:
                if args.svg or args.out.suffix.lower() == ".svg":
                    written = qrimg.render_svg(info["ticket_text"], args.out)
                else:
                    written = qrimg.render_png(info["ticket_text"], args.out)
                info["qr_image"] = str(written)
            if getattr(args, "terminal", True):
                print(qrimg.terminal_ascii(info["ticket_text"]))
                print("（终端二维码若扫不出：反转明暗，或用 --out 出一张图片再扫）")
            info.pop("ticket_text")  # 不把票据原文重复进摘要；图片/终端已含
            _print(info)
        elif args.action == "scan-qr":
            if not args.peer:
                print("用法: pair scan-qr <二维码图片路径>", file=sys.stderr)
                return 2
            from . import qrimg  # 惰性：只有扫码才需要 opencv

            try:
                text = qrimg.decode_image(args.peer)
            except (FileNotFoundError, ValueError) as exc:
                print(f"读图失败：{exc}", file=sys.stderr)
                return 2
            if not text:
                print("图片里没识别到二维码", file=sys.stderr)
                return 1
            _print(engine.scan_ticket_text(text))
        elif args.action == "join":
            if not args.peer or not args.code:
                print("用法: pair join <peer_id|ip:port> <6位码>", file=sys.stderr)
                return 2
            _print(engine.pair_with(args.peer, args.code))
        else:
            if not args.peer or not args.code:
                print("用法: pair confirm <peer_id> <4位安全码>", file=sys.stderr)
                return 2
            ok = engine.verify_security_code(args.peer, args.code)
            _print({"verified": ok,
                    "note": "两端显示的安全码必须一致，否则局域网里有中间人" if not ok else ""})
            return 0 if ok else 1
    finally:
        engine.store.close()
    return 0


def cmd_sync(args) -> int:
    engine = _engine(args)
    try:
        if not engine.enabled():
            print("先跑 enable 或 serve", file=sys.stderr)
            return 2
        if args.peer:
            peer = engine.find_peer(args.peer)
            if peer is None:
                results = [{"peer_id": args.peer, "ok": False, "code": "unknown_peer"}]
            else:
                results = [{"peer_id": peer.peer_id, **engine.sync_round(peer.peer_id)}]
        else:
            results = engine.sync_all()
        _print(results)
        return 0 if all(r.get("ok") for r in results) else 1
    finally:
        engine.stop()
        engine.store.close()
    return 0


def cmd_hub(args) -> int:
    engine = _engine(args)
    try:
        if args.action == "on":
            engine.set_cfg("hub_bind", "0.0.0.0" if args.lan else "127.0.0.1")
            engine.hub.host = str(engine.cfg("hub_bind"))
            engine.set_cfg("hub_role", True)
            _print({"hub_role": True, "bind": engine.hub_bind()})
        elif args.action == "off":
            engine.set_cfg("hub_role", False)
            engine.hub.stop()
            _print({"hub_role": False})
        elif args.action == "rotate":
            username, password = engine.hub.rotate_shared()
            _print({"username": username, "password": password,
                    "note": "旧凭据立即失效；已配对设备需要重新拿 grant"})
        elif args.action in ("seed", "adopt"):
            if not args.peer:
                print("hub seed/adopt 需要 --peer <id|前缀|名字>", file=sys.stderr)
                return 2
            upload = args.action == "seed"
            _print(engine.hub_seed(args.peer, upload=upload))
            _print({"warning": ("本机已整库覆盖 hub，对端必须 adopt 才会跟上"
                                if upload else
                                "本机已整库接受 hub 的内容，本机独有的改动已丢弃")})
        else:
            _print(engine.hub.status())
    finally:
        engine.store.close()
    return 0


def cmd_v1(args) -> int:
    engine = _engine(args)
    engine.set_cfg("allow_v1_plaintext", args.action == "on")
    _print({"allow_v1_plaintext": args.action == "on",
            "warning": "v1 通道明文且无配对，只在自家网络里临时开"})
    engine.store.close()
    return 0


def cmd_config(args) -> int:
    engine = _engine(args)
    if args.value is None:
        _print({args.key: engine.cfg(args.key)})
    else:
        try:
            value = json.loads(args.value)
        except ValueError:
            value = args.value
        engine.set_cfg(args.key, value)
        _print({args.key: value})
    engine.store.close()
    return 0


def anki_addons_dir() -> Path:
    """Anki 的 add-ons 目录（和它自己算 profile 目录用的是同一套环境变量）。"""
    if home := os.environ.get("ANKI_HOME"):
        base = Path(home)
    elif sys.platform == "win32":
        base = Path(os.environ["APPDATA"]) / "Anki2"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "Anki2"
    else:
        xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        base = Path(xdg) / "Anki2"
    return base / "addons21"


ADDON_ID = "lansync_pairqr"


def cmd_addon_install(args) -> int:
    """把 `lan_sync/addon/` 拷进 Anki 的 add-ons 目录，并记下仓库根。

    壳里不放逻辑，只有 `sys.path` + 菜单注册，所以重装只在改壳本身时才需要。
    """
    repo_root = (args.anki_desktop or Path(__file__).resolve().parent.parent).resolve()
    if not (repo_root / "lan_sync" / "aqt_hook.py").is_file():
        _print({"error": f"{repo_root} 不是 anki-desktop 仓库根（缺 lan_sync/aqt_hook.py）"})
        return 1
    src = Path(__file__).resolve().parent / "addon"
    dest = anki_addons_dir() / ADDON_ID
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest, dirs_exist_ok=True)
    (dest / "config.json").write_text(
        json.dumps({"anki_desktop": str(repo_root)}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    _print({"addons_dir": str(dest), "anki_desktop": str(repo_root),
            "next": "重启 Anki，工具菜单里就有「局域网配对二维码…」"})
    return 0


def cmd_serve(args) -> int:
    engine = _engine(args)
    engine.set_cfg("enabled", True)
    if args.interval:
        engine.set_cfg("interval_secs", args.interval)
    engine.start()
    scheduler = Scheduler(engine)
    scheduler.start()

    stopping = {"now": False}

    def stop(*_ignored):
        stopping["now"] = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(f"lan_sync 监听 :{engine.port} 设备 {engine.identity.name}"
          f"({engine.identity.device_id[:8]})", flush=True)
    try:
        while not stopping["now"]:
            state = engine.state()
            print(f"[{time.strftime('%H:%M:%S')}] peers="
                  f"{sum(1 for p in state['peers'] if p['online'])}/"
                  f"{len(state['peers'])} 轮次={scheduler.rounds_run} "
                  f"进度={state['progress'] or '-'}", flush=True)
            time.sleep(5)
    finally:
        scheduler.stop()
        engine.stop()
        engine.store.close()
    return 0


COMMANDS = {
    "state": cmd_state,
    "peers": cmd_peers,
    "logs": cmd_logs,
    "enable": cmd_enable,
    "disable": cmd_disable,
    "pair": cmd_pair,
    "sync": cmd_sync,
    "hub": cmd_hub,
    "v1": cmd_v1,
    "config": cmd_config,
    "addon-install": cmd_addon_install,
    "serve": cmd_serve,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    return COMMANDS[args.command](args)
