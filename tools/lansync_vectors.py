"""生成跨实现互操作向量（SPEC-v2 §4.6）。

桌面端是唯一权威实现，所以向量由 `lan_sync.crypto` 现算，写到两处：
`docs/lan-sync/vectors.json`（规格）与安卓测试资源里的同名副本。安卓 JVM 测试
用同一批固定输入在自己的 Kotlin 实现里重算再比对 —— 这是没有真机时唯一能证明
"两端说的是同一套字节"的手段。

    ../.venv-lansync/Scripts/python.exe tools/lansync_vectors.py            # 写文件
    ../.venv-lansync/Scripts/python.exe tools/lansync_vectors.py --check    # 只校验，不写
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DESKTOP = HERE.parent
REPO = DESKTOP.parent
sys.path.insert(0, str(DESKTOP))

from lan_sync import crypto  # noqa: E402

# 固定输入：任何一端改这些常量都必须同时改另一端。
DEVICE_A = "11111111-1111-4111-8111-111111111111"
DEVICE_B = "22222222-2222-4222-8222-222222222222"
CONTRIB_A = bytes(range(32))
CONTRIB_B = bytes(range(32, 64))
PAIR_CODE = "123456"
TS = 1_700_000_000
NONCE = bytes(range(12))
ROUTE = "devices/sync"
PLAINTEXT = b'{"since":0}'

TARGETS = [
    REPO / "docs" / "lan-sync" / "vectors.json",
    REPO / "anki-droid" / "anki-android" / "AnkiDroid" / "src" / "test" / "resources"
    / "lansync" / "vectors.json",
]


def build() -> dict:
    shared = crypto.combine_secrets(CONTRIB_A, CONTRIB_B, DEVICE_A, DEVICE_B)
    reversed_ = crypto.combine_secrets(CONTRIB_B, CONTRIB_A, DEVICE_B, DEVICE_A)
    assert shared == reversed_, "combine_secrets 不再按 device_id 定序"

    kid = crypto.kid_of(shared)
    key = crypto.derive_route_key(shared, ROUTE)
    envelope = crypto.seal(PLAINTEXT, shared, ROUTE, kid, now=TS, nonce=NONCE)
    assert crypto.b64d(envelope["nonce"]) == NONCE, "seal ignored the fixed nonce"

    wrap_key = crypto._pair_code_key(PAIR_CODE)
    pair_envelope = crypto.seal(CONTRIB_A, wrap_key, "pair/wrap", "pair", now=TS, nonce=NONCE)
    return {
        "_comment": "SPEC-v2 §4.6 互操作向量；由 anki-desktop/tools/lansync_vectors.py 生成，勿手改",
        "inputs": {
            "device_id_a": DEVICE_A,
            "device_id_b": DEVICE_B,
            "contribution_a_hex": CONTRIB_A.hex(),
            "contribution_b_hex": CONTRIB_B.hex(),
            "pair_code": PAIR_CODE,
            "ts": TS,
            "nonce_hex": NONCE.hex(),
            "route": ROUTE,
            "plaintext_utf8": PLAINTEXT.decode(),
        },
        "pairing": {
            "shared_secret_hex": shared.hex(),
            "kid": kid,
            "security_code": crypto.gen_security_code(shared),
            "pair_wrap_key_hex": wrap_key.hex(),
            # 包裹后的载荷就是 §4.2 的信封结构，kid 固定 "pair"，AAD 为 "pair|<ts>"
            "pair_wrapped_contribution_a": pair_envelope,
        },
        "envelope": {
            "route_key_hex": key.hex(),
            "aad": f"{kid}|{TS}",
            "json": envelope,
            # apkg/import 头里放的是整段信封 JSON 的 urlsafe-b64
            "header_urlsafe_b64": base64.urlsafe_b64encode(
                json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode("ascii"),
        },
        "checksum_sha256": None,
    }


def finalize(doc: dict) -> dict:
    body = json.dumps({k: v for k, v in doc.items() if k != "checksum_sha256"},
                      sort_keys=True, separators=(",", ":"))
    doc["checksum_sha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return doc


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def main() -> int:
    doc = finalize(build())
    text = render(doc)
    if "--check" in sys.argv:
        bad = [str(p) for p in TARGETS if not p.exists() or p.read_text(encoding="utf-8") != text]
        if bad:
            print("向量已过期或与生成结果不一致：\n  " + "\n  ".join(bad), file=sys.stderr)
            return 1
        print(f"vectors ok ({len(text)} bytes, 2 copies)")
        return 0
    for path in TARGETS:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
