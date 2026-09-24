"""内置 rslib 同步服务端（SimpleServer）的子进程封装 —— hub 模式的服务器侧。

要点：
- 服务端日志**必须落文件**。把它 stdout 接到管道又没人读，管道灌满会让服务端写入阻塞、
  客户端表现为超时（探针阶段真实踩过）。
- SYNC_PORT 无法在运行时改，换端口只能重启；因此端口回退靠 start() 里预探测。
- 用户表来自环境变量（SYNC_USERn），改用户 = 重启子进程。
"""

from __future__ import annotations

import json
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

from .protocol import HUB_PORT_END, HUB_PORT_START


class HubError(Exception):
    pass


class HubServer:
    def __init__(self, data_dir: Path, host: str = "127.0.0.1",
                 port_start: int = HUB_PORT_START, port_end: int = HUB_PORT_END) -> None:
        self.data_dir = Path(data_dir)
        self.host = host
        self.port_start = port_start
        self.port_end = port_end
        self.users_file = self.data_dir / "hub_users.json"
        self.log_path = self.data_dir / "syncserver.log"
        self.proc: subprocess.Popen | None = None
        self.port: int | None = None

    # --------------------------------------------------------------- 用户表
    def load_users(self) -> dict:
        if self.users_file.exists():
            return json.loads(self.users_file.read_text(encoding="utf-8"))
        return {}

    def _write_users(self, users: dict) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.users_file.write_text(json.dumps(users, indent=2), encoding="utf-8")

    SHARED = "shared"

    def _new_entry(self) -> dict:
        return {"username": f"lan_{secrets.token_hex(3)}",
                "password": secrets.token_urlsafe(18)}

    def _ensure_shared(self) -> dict:
        """凭据必须在**起子进程之前**落盘：syncserver 没有 SYNC_USERn 会直接拒绝启动。"""
        users = self.load_users()
        entry = users.get(self.SHARED)
        if not entry:
            entry = self._new_entry()
            users[self.SHARED] = entry
            self._write_users(users)
        return entry

    def grant_shared(self) -> tuple[str, str]:
        """返回 hub 的**唯一**账号；一个 hkey 才是一个同步命名空间。

        给每台设备各发一个账号是错的：rslib 服务端按 hkey 隔离，两个 hkey 就是两个互
        不可见的库，永远不收敛。所以所有已配对设备共用一份凭据，谁能拿到由 §4 的配对
        决定（`/hub/grant` 走信封认证）；换凭据 = `rotate_shared()`。
        """
        entry = self._ensure_shared()
        return entry["username"], entry["password"]

    def rotate_shared(self) -> tuple[str, str]:
        """作废旧凭据（下次 grant 发新的）；已持有旧凭据的设备会被挡在门外。"""
        users = self.load_users()
        users.pop(self.SHARED, None)
        self._write_users(users)
        entry = self._ensure_shared()
        if self.running:
            # 先换新凭据再重启，否则跑着的进程仍是旧 hkey，grant 出去的用它就连不上
            self.restart()
        return entry["username"], entry["password"]

    # ------------------------------------------------------------- 生命周期
    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _free_port(self) -> int:
        for port in range(self.port_start, self.port_end + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.bind((self.host, port))
                except OSError:
                    continue
                return port
        raise HubError(f"no free port in {self.port_start}-{self.port_end}")

    def start(self) -> str:
        if self.running:
            return self.endpoint()
        import anki  # noqa: F401 - 提前失败：轮子没装就直接报清楚

        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "syncbase").mkdir(exist_ok=True)
        self._ensure_shared()
        env = {
            "SYNC_HOST": self.host,
            "SYNC_PORT": str(self._free_port()),
            "SYNC_BASE": str(self.data_dir / "syncbase"),
            "RUST_LOG": "anki=info",
        }
        for index, entry in enumerate(self.load_users().values(), start=1):
            env[f"SYNC_USER{index}"] = f"{entry['username']}:{entry['password']}"
        self.port = int(env["SYNC_PORT"])

        import os

        # 先剥掉继承来的 SYNC_*：调试时 shell 里残留一个 SYNC_USER2，就会多开一个
        # 无人认领的 hkey，而 grant 里永远不会发出它的凭据。
        full_env = {k: v for k, v in os.environ.items() if not k.startswith("SYNC_")}
        full_env.update({k: v for k, v in env.items() if k.startswith("SYNC_")})
        full_env["RUST_LOG"] = env["RUST_LOG"]
        with open(self.log_path, "ab") as log_file:
            self.proc = subprocess.Popen(
                [sys.executable, "-m", "anki.syncserver"],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=full_env,
            )
        self._wait_ready()
        return self.endpoint()

    def _wait_ready(self, timeout: float = 30.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise HubError(f"syncserver exited: {self.tail_log()}")
            try:
                with socket.create_connection((self.host, self.port), timeout=1):
                    return
            except OSError:
                time.sleep(0.4)
        raise HubError(f"syncserver did not come up on {self.host}:{self.port}")

    def stop(self) -> None:
        if self.proc is None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        finally:
            self.proc = None

    def restart(self) -> None:
        self.stop()
        self.start()

    def endpoint(self) -> str:
        return f"http://{_display_host(self.host)}:{self.port}/"

    def tail_log(self, lines: int = 12) -> str:
        if not self.log_path.exists():
            return "<no log>"
        return "\n".join(
            self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
        )

    def status(self) -> dict:
        return {
            "running": self.running,
            "host": self.host,
            "port": self.port,
            "endpoint": self.endpoint() if self.port else None,
            "users": len(self.load_users()),
            "log": str(self.log_path),
        }


def _display_host(host: str) -> str:
    if host in ("0.0.0.0", "::"):  # noqa: S104 - 监听地址不能直接给对端连
        from .identity import best_address

        return best_address() or "127.0.0.1"
    return host
