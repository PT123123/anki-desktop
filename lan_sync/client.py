"""对端 HTTP 客户端（SPEC-v2 §5）。

两条数据面的差别在这里收口：
- v2 控制/小载荷路由：JSON 信封进出。
- v2 `.apkg` 大载荷：请求侧把信封放进 `X-Anki-Envelope` 头，body 是原始包字节；
  响应侧回显请求 nonce（`X-Anki-Xfer`）把字节绑定到一次已认证的请求。**bulk 字节本身不加密**，
  认证的是"谁有权取/推"，这与 hub 模式走明文 HTTP 同步是同一档安全 posture。
- v1 对端（旧安卓 fork）：只有 `/export`、`/import`，明文 + magic 头，且必须用户显式允许。
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Callable

import requests

from . import crypto
from .protocol import (
    HEADER_ENVELOPE,
    HEADER_KID,
    HEADER_MAGIC,
    HEADER_PEER,
    HEADER_PEER_ID,
    HEADER_TS,
    HEADER_V1_MAGIC,
    HEADER_XFER,
    MAGIC_V1,
    MAGIC_V2,
    MAX_PACKAGE_BYTES,
    PeerInfo,
    LanError,
)

CONTROL_TIMEOUT = 15.0
BULK_READ_TIMEOUT = 600.0
_CHUNK = 1 << 20


class PeerClient:
    def __init__(self, store, identity, nonces: crypto.NonceCache | None = None) -> None:
        self.store = store
        self.identity = identity
        # 重放去重表与响应侧共用（engine 传同一个实例）
        self.nonces = nonces or crypto.NonceCache()

    # ------------------------------------------------------------------ 底层
    def _base(self, host: str, port: int) -> str:
        return f"http://{host}:{port}"

    def _who(self) -> dict:
        return {HEADER_PEER: self.identity.name, HEADER_PEER_ID: self.identity.device_id}

    @staticmethod
    def _raise_for_response(resp: requests.Response) -> None:
        if resp.status_code < 400:
            return
        code = f"http_{resp.status_code}"
        message = resp.text[:200]
        try:
            body = resp.json()
            code = body.get("error", code)
            message = body.get("message", message)
        except ValueError:
            pass
        raise LanError(resp.status_code, code, message)

    def _sealed(self, peer_id: str, route: str,
                payload: dict) -> tuple[dict, bytes, dict]:
        entry = self.store.get_secret(peer_id)
        if not entry:
            raise LanError(403, "not_paired", f"no secret for {peer_id[:8]}")
        kid, secret = entry
        envelope = crypto.seal(json.dumps(payload).encode("utf-8"), secret, route, kid=kid)
        headers = {
            **self._who(),
            HEADER_MAGIC: MAGIC_V2,
            HEADER_KID: kid,
            HEADER_TS: str(envelope["ts"]),
        }
        return headers, json.dumps(envelope).encode("utf-8"), envelope

    def _open(self, peer_id: str, route: str, body: bytes) -> dict:
        entry = self.store.get_secret(peer_id)
        if not entry:
            raise LanError(403, "not_paired")
        kid, secret = entry
        try:
            envelope = json.loads(body)
        except ValueError as exc:
            raise LanError(401, "bad_envelope", str(exc)) from exc
        plain = crypto.open_envelope(envelope, secret, route, kid=kid, nonces=self.nonces)
        return json.loads(plain)

    # ------------------------------------------------------------------ 控制面
    def probe(self, host: str, port: int) -> PeerInfo | None:
        """发现验证：拿到合法 `/info` 才认这个 peer。失败一律 None，不抛。"""
        try:
            resp = requests.get(self._base(host, port) + "/info",
                                headers=self._who(), timeout=CONTROL_TIMEOUT)
            if resp.status_code != 200:
                return None
            return PeerInfo.from_json(resp.text)
        except (requests.RequestException, ValueError, TypeError):
            return None

    def post_envelope(self, host: str, port: int, peer_id: str, route: str,
                      payload: dict) -> dict:
        headers, body, _ = self._sealed(peer_id, route, payload)
        resp = requests.post(self._base(host, port) + f"/{route}",
                             data=body, headers=headers, timeout=CONTROL_TIMEOUT)
        self._raise_for_response(resp)
        return self._open(peer_id, route, resp.content)

    def devices_sync(self, host: str, port: int, peer_id: str, since: float) -> list[dict]:
        return self.post_envelope(host, port, peer_id, "devices/sync",
                                  {"since": since}).get("devices", [])

    def notify(self, host: str, port: int, peer_id: str, payload: dict) -> dict:
        """`/round/notify`：告诉对端"我这边变了，来同步"。

        payload 原样放进信封（`{"hub": grant}` 或 `{"counts": ..}`）——别再自作主张
        套一层 `counts`，那会让服务端顶层找不到 `hub` 而把 hub 补同步当成 apkg 提醒。
        """
        return self.post_envelope(host, port, peer_id, "round/notify",
                                  {**payload, "mod_ts": time.time()})

    def hub_grant(self, host: str, port: int, peer_id: str) -> dict:
        return self.post_envelope(host, port, peer_id, "hub/grant", {})

    # ------------------------------------------------------------------ 配对
    def pair_commit(self, host: str, port: int, pair_code: str, my_info: PeerInfo,
                    my_contribution: bytes) -> tuple[PeerInfo, bytes]:
        """输入端：把 6 位码发出去，换回对方的公开信息与贡献值。

        这一步还没有共享密钥，所以贡献值用码派生的临时对称密钥包裹。
        """
        envelope = crypto.wrap_with_pair_code(pair_code, my_contribution)
        payload = {"pair_code": pair_code, "peer_info": json.loads(my_info.to_json()),
                   "envelope": envelope}
        resp = requests.post(
            self._base(host, port) + "/pair/commit",
            data=json.dumps(payload).encode("utf-8"),
            headers={**self._who(), HEADER_MAGIC: MAGIC_V2},
            timeout=CONTROL_TIMEOUT,
        )
        self._raise_for_response(resp)
        body = resp.json()
        theirs = crypto.unwrap_with_pair_code(pair_code, body["envelope"])
        return PeerInfo.from_json(json.dumps(body["peer_info"])), theirs

    # ------------------------------------------------------------- apkg 数据面
    def push_package(self, host: str, port: int, peer_id: str, path: Path) -> dict:
        size = Path(path).stat().st_size
        if size > MAX_PACKAGE_BYTES:
            raise LanError(507, "too_large", f"{size} > {MAX_PACKAGE_BYTES}")
        headers, _, envelope = self._sealed(peer_id, "apkg/import", {"bytes": size})
        # body 被包体占了，所以信封挪到头里（服务端按同一规则还原）
        headers[HEADER_ENVELOPE] = base64.urlsafe_b64encode(
            json.dumps(envelope).encode("utf-8")
        ).decode("ascii")
        headers["Content-Length"] = str(size)
        with open(path, "rb") as handle:
            resp = requests.post(self._base(host, port) + "/apkg/import",
                                 data=handle, headers=headers,
                                 timeout=(CONTROL_TIMEOUT, BULK_READ_TIMEOUT))
        self._raise_for_response(resp)
        return self._open(peer_id, "apkg/import", resp.content)

    def pull_package(self, host: str, port: int, peer_id: str, out_path: Path,
                     progress: Callable[[int], None] | None = None) -> int:
        headers, body, envelope = self._sealed(peer_id, "apkg/export", {})
        resp = requests.post(self._base(host, port) + "/apkg/export",
                             data=body, headers=headers, stream=True,
                             timeout=(CONTROL_TIMEOUT, BULK_READ_TIMEOUT))
        self._raise_for_response(resp)
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with open(out_path, "wb") as handle:
            for chunk in resp.iter_content(_CHUNK):
                handle.write(chunk)
                written += len(chunk)
                if progress:
                    progress(written)
        if resp.headers.get(HEADER_XFER) != envelope["nonce"]:
            raise LanError(401, "xfer_mismatch", "response did not bind the request nonce")
        if written > MAX_PACKAGE_BYTES:
            raise LanError(507, "too_large", f"streamed {written}")
        return written

    # ---------------------------------------------------------------- v1 兼容
    def v1_headers(self) -> dict:
        return {**self._who(), HEADER_V1_MAGIC: MAGIC_V1}

    def v1_probe(self, host: str, port: int) -> PeerInfo | None:
        """v1 的 `/info` 字段名不同，`PeerInfo.from_json` 里做了别名映射。"""
        try:
            resp = requests.get(self._base(host, port) + "/info", timeout=CONTROL_TIMEOUT)
            if resp.status_code != 200 or "anki" not in resp.text.lower():
                return None
            return PeerInfo.from_json(resp.text)
        except (requests.RequestException, ValueError, TypeError):
            return None

    def v1_push_package(self, host: str, port: int, path: Path) -> dict:
        size = Path(path).stat().st_size
        headers = self.v1_headers()
        headers["Content-Length"] = str(size)
        with open(path, "rb") as handle:
            resp = requests.post(self._base(host, port) + "/import", data=handle,
                                 headers=headers, timeout=(CONTROL_TIMEOUT, BULK_READ_TIMEOUT))
        self._raise_for_response(resp)
        return resp.json() if resp.content else {}

    def v1_pull_package(self, host: str, port: int, out_path: Path) -> int:
        resp = requests.get(self._base(host, port) + "/export",
                            headers=self.v1_headers(), stream=True,
                            timeout=(CONTROL_TIMEOUT, BULK_READ_TIMEOUT))
        self._raise_for_response(resp)
        written = 0
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as handle:
            for chunk in resp.iter_content(_CHUNK):
                handle.write(chunk)
                written += len(chunk)
        return written
