"""本地 HTTP 服务（SPEC-v2 §5）：控制面路由 + 两条数据面的服务端侧。

只依赖标准库，不引入 web 框架。设计约束：

- **集合锁绝不跨网络持有**：`/apkg/export` 先让 engine 在锁内导出到临时文件，再把文件流出去；
  `/apkg/import` 先把 body 落到临时文件，再进锁导入。传输慢不会卡住正在复习的用户。
- **大 body 不进内存**：按 `Content-Length` 流式写盘，超限直接 507。
- **未配对的请求最多拿到 `/info` 和 `/pair/*`**；其余路由缺 magic 或 kid 无效一律 403，
  不区分"没这个设备"和"没配对"，避免探测。
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import crypto
from .protocol import (
    HEADER_ENVELOPE,
    HEADER_KID,
    HEADER_MAGIC,
    HEADER_PEER,
    HEADER_V1_MAGIC,
    HEADER_XFER,
    MAGIC_V1,
    MAGIC_V2,
    MAX_PACKAGE_BYTES,
    TCP_PORT_END,
    TCP_PORT_START,
    LanError,
)

log = logging.getLogger("anki.lansync.server")

ENVELOPE_ROUTES = {"devices/sync", "round/notify", "hub/grant", "apkg/export", "apkg/import"}
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
PAIR_FAIL_LIMIT = 10
PAIR_FAIL_WINDOW = 60.0


class LanHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, engine, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.engine = engine
        self._failures: dict[str, list[float]] = {}
        self._fail_lock = threading.Lock()

    # ------------------------------------------------------------ 限流原语
    def note_pair_failure(self, host: str) -> None:
        now = time.time()
        with self._fail_lock:
            hits = [t for t in self._failures.setdefault(host, []) if now - t < PAIR_FAIL_WINDOW]
            hits.append(now)
            self._failures[host] = hits

    def pair_locked(self, host: str) -> bool:
        now = time.time()
        with self._fail_lock:
            hits = [t for t in self._failures.get(host, []) if now - t < PAIR_FAIL_WINDOW]
            self._failures[host] = hits
            return len(hits) >= PAIR_FAIL_LIMIT

    def clear_pair_failures(self, host: str) -> None:
        with self._fail_lock:
            self._failures.pop(host, None)


def serve(engine, host: str = "0.0.0.0",  # noqa: S104 - 局域网同步本就要对 peers 开放
          port_start: int = TCP_PORT_START,
          port_end: int = TCP_PORT_END) -> tuple[LanHttpServer, int]:
    """绑定端口（5600 起回退），返回 (server, actual_port)；调用方负责 `serve_forever`。"""
    last_error: OSError | None = None
    for port in range(port_start, port_end + 1):
        try:
            server = LanHttpServer(engine, (host, port), _Handler)
        except OSError as exc:
            last_error = exc
            continue
        # 实际端口回写，peers 靠 `/info` 与 mDNS 拿到它，不需要猜
        engine.on_port_bound(port)
        return server, port
    raise OSError(f"no free port in {port_start}-{port_end}: {last_error}")


class _Handler(BaseHTTPRequestHandler):
    server: LanHttpServer

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A002 - 覆盖标准库命名
        log.debug("%s %s", self.address_string(), fmt % args)

    # ------------------------------------------------------------- 响应工具
    @property
    def engine(self):
        return self.server.engine

    def _loopback(self) -> bool:
        return self.client_address[0] in LOOPBACK

    def _send(self, status: int, body: bytes = b"", content_type: str = "application/json",
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, str(value))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload: dict, status: int = 200) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def _error(self, status: int, code: str, message: str = "") -> None:
        # 出错时不复用连接：请求体可能根本没读完，留着会让下一个请求读到脏字节
        self.close_connection = True
        self._json({"error": code, "message": message or code}, status)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _read_body_to_file(self, limit: int = MAX_PACKAGE_BYTES) -> Path:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise LanError(411, "length_required", "import needs Content-Length")
        if length > limit:
            raise LanError(507, "too_large", f"{length} > {limit}")
        target = self.engine.work_dir / f"incoming-{uuid.uuid4().hex[:8]}.apkg"
        target.parent.mkdir(parents=True, exist_ok=True)
        remaining = length
        with open(target, "wb") as handle:
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    raise LanError(400, "truncated_body", "connection closed mid-body")
                handle.write(chunk)
                remaining -= len(chunk)
        self.engine.track_temp(target)
        return target

    # ------------------------------------------------------------- 认证工具
    def _envelope_request(self, route: str) -> tuple[str, dict, dict]:
        """返回 (peer_id, payload, envelope)；任何一步不过就抛 LanError。

        envelope 一并返回：导出路由要用它的 nonce 回显，把随后的明文字节流绑到这次认证上。
        """
        if self.headers.get(HEADER_MAGIC) != MAGIC_V2:
            raise LanError(403, "need_magic", "missing or wrong X-Anki-Sync")
        kid = self.headers.get(HEADER_KID, "")
        found = self.engine.store.find_by_kid(kid)
        if not found:
            raise LanError(403, "not_paired", f"unknown kid {kid!r}")
        peer_id, secret = found
        raw = self.headers.get(HEADER_ENVELOPE) if route == "apkg/import" else None
        if raw:
            envelope = self._load_json(base64.urlsafe_b64decode(raw.encode("ascii")),
                                        "bad_envelope")
        elif route == "apkg/import":
            # 这条路由的 body 是包体本身，信封只认头
            raise LanError(401, "bad_envelope", f"import needs {HEADER_ENVELOPE}")
        else:
            body = self._read_body()
            if not body:
                raise LanError(401, "bad_envelope", "empty body")
            envelope = self._load_json(body, "bad_envelope")
        payload_bytes = crypto.open_envelope(envelope, secret, route, kid=kid,
                                             nonces=self.engine.nonces)
        self.engine.note_heard(peer_id, self.headers.get(HEADER_PEER, ""),
                               self.client_address[0])
        return peer_id, self._load_json(payload_bytes, "bad_payload"), envelope

    @staticmethod
    def _load_json(raw: bytes | str, code: str) -> dict:
        try:
            return json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise LanError(401, code, str(exc)) from exc

    def _sealed_response(self, peer_id: str, route: str, payload: dict) -> None:
        entry = self.engine.store.get_secret(peer_id)
        if not entry:
            raise LanError(403, "not_paired")
        kid, secret = entry
        envelope = crypto.seal(json.dumps(payload).encode("utf-8"), secret, route, kid=kid)
        self._json(envelope)

    # ----------------------------------------------------------------- 路由
    def do_GET(self):  # noqa: N802 - 标准库命名
        try:
            path = self.path.split("?", 1)[0].strip("/")
            if path == "":
                self._send(200, f"anki-lan-sync {MAGIC_V2}\n".encode(), "text/plain")
            elif path == "info":
                self._json(json.loads(self.engine.info_json()))
            elif path == "state":
                if not self._loopback():
                    raise LanError(403, "loopback_only")
                self._json(self.engine.state())
            elif path == "export":
                self._v1_export()
            else:
                self._error(404, "not_found", path)
        except LanError as exc:
            self._error(exc.status, exc.code, str(exc))
        except (BrokenPipeError, ConnectionResetError):
            log.debug("peer 提前断开（导出中断是正常事件）")
        except Exception as exc:  # noqa: BLE001 - 未预料的异常也得回 500，不能裸断连接
            log.exception("lansync GET %s 失败", self.path)
            self._error(500, "internal_error", f"{type(exc).__name__}: {exc}")

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0].strip("/")
        try:
            if path == "pair/begin":
                if not self._loopback():
                    raise LanError(403, "loopback_only", "pair code must be minted locally")
                self._json(self.engine.begin_pairing())
            elif path == "pair/commit":
                self._pair_commit()
            elif path in ENVELOPE_ROUTES:
                self._envelope_route(path)
            elif path == "import":
                self._v1_import()
            else:
                self._error(404, "not_found", path)
        except LanError as exc:
            self._error(exc.status, exc.code, str(exc))
        except (BrokenPipeError, ConnectionResetError):
            log.debug("peer 提前断开")
        except Exception as exc:  # noqa: BLE001 - 未预料的异常也得回 500，不能裸断连接
            log.exception("lansync POST %s 失败", self.path)
            self._error(500, "internal_error", f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------- 配对入口
    def _pair_commit(self) -> None:
        host = self.client_address[0]
        if self.server.pair_locked(host):
            raise LanError(429, "pair_throttled", "too many bad codes")
        payload = self._load_json(self._read_body() or b"{}", "bad_envelope")
        try:
            response = self.engine.handle_pair_commit(payload, host=host)
        except LanError as exc:
            if exc.code in ("pair_invalid", "pair_consumed", "pair_expired"):
                self.server.note_pair_failure(host)
            raise
        self.server.clear_pair_failures(host)
        self._json(response)

    # ----------------------------------------------------------- 信封路由
    def _envelope_route(self, route: str) -> None:
        peer_id, payload, envelope = self._envelope_request(route)
        if route == "devices/sync":
            self._sealed_response(peer_id, route, {
                "devices": self.engine.store.public_rows(float(payload.get("since", 0.0))),
                "now": time.time(),
            })
        elif route == "round/notify":
            self._sealed_response(peer_id, route, self.engine.handle_notify(peer_id, payload))
        elif route == "hub/grant":
            self._sealed_response(peer_id, route, self.engine.handle_hub_grant(peer_id))
        elif route == "apkg/export":
            self._export_stream(peer_id, envelope)
        elif route == "apkg/import":
            self._import_package(peer_id, payload)

    def _export_stream(self, peer_id: str, envelope: dict) -> None:
        path = self.engine.export_to_temp(peer_id)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(path.stat().st_size))
            # 回显请求 nonce：这段明文字节只能属于一次已通过认证的导出请求
            self.send_header(HEADER_XFER, envelope["nonce"])
            self.send_header(HEADER_MAGIC, MAGIC_V2)
            self.end_headers()
            with open(path, "rb") as handle:
                while chunk := handle.read(1 << 20):
                    self.wfile.write(chunk)
            self.engine.note_exported(peer_id, path)
        except (BrokenPipeError, ConnectionResetError):
            log.info("peer %s 中断了导出", peer_id[:8])
        finally:
            self.engine.forget_temp(path)

    def _import_package(self, peer_id: str, payload: dict) -> None:
        target = self._read_body_to_file()
        try:
            result = self.engine.handle_import(peer_id, target, int(payload.get("bytes", 0)))
        finally:
            self.engine.forget_temp(target)
        self._sealed_response(peer_id, "apkg/import", result)

    # -------------------------------------------------------------- v1 兼容
    def _v1_allowed(self) -> bool:
        return bool(self.engine.allow_v1_plaintext())

    def _v1_export(self) -> None:
        if self.headers.get(HEADER_V1_MAGIC) != MAGIC_V1 or not self._v1_allowed():
            # 没有 magic 头就不给整库：否则局域网里一个浏览器标签页就能拖走全部卡片
            raise LanError(403, "v1_disabled")
        self.engine.note_v1_round("export")
        self._send_file(self.engine.export_to_temp(""))

    def _v1_import(self) -> None:
        if self.headers.get(HEADER_V1_MAGIC) != MAGIC_V1 or not self._v1_allowed():
            raise LanError(403, "v1_disabled")
        self.engine.note_v1_round("import")
        target = self._read_body_to_file()
        try:
            result = self.engine.handle_import("", target, 0, v1=True)
        finally:
            self.engine.forget_temp(target)
        self._json(result)

    def _send_file(self, path: Path) -> None:
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(path, "rb") as handle:
            while chunk := handle.read(1 << 20):
                self.wfile.write(chunk)
