"""配对密钥协商与报文信封加密（SPEC-v2 §4）。

信封：AES-256-GCM，密钥按路由派生（HKDF(secret, salt="anki-lan-sync/2", info=<route>)），
AAD = kid||ts，时间戳窗口 ±300s，nonce 在窗口内去重。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .protocol import LanError

SALT = b"anki-lan-sync/2"
PAIR_SALT = b"anki-lan-sync/2/pair"
KX_SALT = b"anki-lan-sync/2/kx"
TS_WINDOW_SECS = 300
NONCE_CACHE_SECS = TS_WINDOW_SECS * 2


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def gen_secret() -> bytes:
    return secrets.token_bytes(32)


def _hkdf(salt: bytes, info: bytes, length: int) -> HKDF:
    return HKDF(algorithm=SHA256(), length=length, salt=salt, info=info)


def derive_route_key(shared_secret: bytes, route: str) -> bytes:
    return _hkdf(SALT, route.encode("utf-8"), 32).derive(shared_secret)


def kid_of(shared_secret: bytes) -> str:
    """稳定、可公开的配对标识；不泄露密钥。"""
    return hmac.new(shared_secret, b"kid", hashlib.sha256).hexdigest()[:8]


def combine_secrets(own: bytes, peer: bytes, own_device_id: str, peer_device_id: str) -> bytes:
    """双方各贡献 32B，按 device_id 定序后 HKDF 出一个共享密钥。

    定序是为了两端算出同一个值——按发起/响应角色拼接会两端不一致。
    """
    first, second = (own, peer) if own_device_id <= peer_device_id else (peer, own)
    return _hkdf(KX_SALT, b"pair", 32).derive(first + second)


def _pair_code_key(pair_code: str) -> bytes:
    return _hkdf(PAIR_SALT, b"wrap", 32).derive(pair_code.encode("utf-8"))


def wrap_with_pair_code(pair_code: str, payload: bytes) -> dict:
    """配对阶段用 6 位码派生的临时密钥包裹本机贡献值。"""
    return seal(payload, _pair_code_key(pair_code), "pair/wrap", kid="pair")


def unwrap_with_pair_code(pair_code: str, envelope: dict) -> bytes:
    return open_envelope(envelope, _pair_code_key(pair_code), "pair/wrap", kid="pair")


class NonceCache:
    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def check_and_store(self, kid: str, nonce: str, now: float) -> bool:
        """True 表示新鲜；False 表示重放。"""
        with self._lock:
            cutoff = now - NONCE_CACHE_SECS
            for key, when in list(self._seen.items()):
                if when < cutoff:
                    self._seen.pop(key, None)
            if (kid, nonce) in self._seen:
                return False
            self._seen[(kid, nonce)] = now
            return True


def seal(plain: bytes, shared_secret: bytes, route: str, kid: str,
         now: float | None = None, nonce: bytes | None = None) -> dict:
    """`nonce` 只为可复现的互操作向量而存在（SPEC-v2 §4.6）；正常调用留空即随机。"""
    ts = int(now if now is not None else time.time())
    key = derive_route_key(shared_secret, route)
    nonce = nonce if nonce is not None else secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plain, f"{kid}|{ts}".encode("utf-8"))
    return {"kid": kid, "ts": ts, "nonce": b64e(nonce), "ct": b64e(ct)}


def open_envelope(envelope: dict, shared_secret: bytes, route: str, kid: str,
                  now: float | None = None, nonces: NonceCache | None = None) -> bytes:
    try:
        ts = int(envelope["ts"])
        env_kid = envelope["kid"]
        nonce = b64d(envelope["nonce"])
        ct = b64d(envelope["ct"])
    except (KeyError, TypeError, ValueError) as exc:
        raise LanError(401, "bad_envelope", f"malformed envelope: {exc}") from exc

    now = now if now is not None else time.time()
    if abs(now - ts) > TS_WINDOW_SECS:
        raise LanError(401, "stale_ts", f"timestamp outside ±{TS_WINDOW_SECS}s window")
    if env_kid != kid:
        raise LanError(401, "kid_mismatch")
    if nonces is not None and not nonces.check_and_store(env_kid, envelope["nonce"], now):
        raise LanError(401, "replay", "nonce already seen")

    key = derive_route_key(shared_secret, route)
    try:
        return AESGCM(key).decrypt(nonce, ct, f"{env_kid}|{ts}".encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - AEADTag 失败统一成协议错误
        raise LanError(401, "decrypt_failed", str(exc)) from exc


def gen_pair_code() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def gen_security_code(shared: bytes) -> str:
    """4 位十六进制人工核对码；两端都显示，一致才继续。"""
    return hashlib.sha256(shared).hexdigest()[:4]
