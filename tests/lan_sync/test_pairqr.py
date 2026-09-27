"""配对二维码票据（SPEC-v2 §4.7）的本地编解码单测。

不碰网络：只验编码字节稳定、解码容错和安全字段校验。跨端字节对齐在
`tools/lansync_vectors.py` 的 `pair_qr` 段里钉，两端各自重算同一份文本。
"""

from __future__ import annotations

import pytest

from lan_sync import pairqr
from lan_sync.pairqr import PairQrError, decode_ticket, encode_ticket

ID = "aaaaaaaa-1111-4111-8111-111111111111"


def test_roundtrip_preserves_fields():
    text = encode_ticket(ID, "我的机子", "desktop", "192.168.1.20", 5611, "004200")
    t = decode_ticket(text)
    assert (t.device_id, t.name, t.kind, t.host, t.port, t.pair_code) == (
        ID, "我的机子", "desktop", "192.168.1.20", 5611, "004200")


def test_canonical_text_is_prefix_plus_compact_json_in_declared_key_order():
    text = encode_ticket(ID, "N", "android", "10.0.0.7", 5600, "123456")
    assert text.startswith(pairqr.PAIR_QR_MAGIC + " ")
    body = text[len(pairqr.PAIR_QR_MAGIC) + 1:]
    # 键序：t v id nk nm h p c —— 顺序变了就是改协议。
    assert body.index('"t"') < body.index('"v"') < body.index('"id"') < body.index('"nk"')
    assert body.index('"nm"') < body.index('"h"') < body.index('"p"') < body.index('"c"')
    assert ", " not in body and '": ' not in body  # 紧凑分隔符


def test_endpoint_and_repr_never_leak_pair_code():
    t = decode_ticket(encode_ticket(ID, "N", "desktop", "192.168.0.9", 5600, "654321"))
    assert t.endpoint == "192.168.0.9:5600"
    assert "654321" not in repr(t)


def test_foreign_qr_is_not_ours_not_an_exception():
    with pytest.raises(PairQrError) as exc:
        decode_ticket("https://example.com/")
    assert exc.value.code == "not_our_qr"


def test_unknown_fields_are_ignored():
    text = encode_ticket(ID, "N", "desktop", "192.168.1.5", 5600, "111111")
    mutated = text.rstrip("}") + ',"future":9}'
    t = decode_ticket(mutated)
    assert t.device_id == ID and t.pair_code == "111111"


@pytest.mark.parametrize("mutate,code", [
    ('{"t":"other/9"}', "bad_format"),
])
def test_wrong_type_tag_rejected(mutate, code):
    with pytest.raises(PairQrError) as exc:
        decode_ticket(f'{pairqr.PAIR_QR_MAGIC} {mutate}')
    assert exc.value.code == code


def test_old_protocol_rejected():
    body = ('{"t":"%s","v":1,"id":"%s","nk":"desktop","nm":"N",'
            '"h":"192.168.1.1","p":5600,"c":"123456"}') % (pairqr.PAIR_QR_MAGIC, ID)
    with pytest.raises(PairQrError) as exc:
        decode_ticket(f"{pairqr.PAIR_QR_MAGIC} {body}")
    assert exc.value.code == "old_protocol"


@pytest.mark.parametrize("field,value,code", [
    ("c", "12345", "bad_code"),          # 5 位不是 6 位
    ("c", "abcdef", "bad_code"),
    ("h", "8.8.8.8", "bad_address"),      # 公网
    ("h", "169.254.1.2", "bad_address"),  # 链路本地
    ("h", "127.0.0.1", "bad_address"),    # 回环
    ("id", "", "bad_id"),
    ("p", 70000, "bad_port"),
])
def test_decode_rejects_unsafe_or_malformed(field, value, code):
    good = {"t": pairqr.PAIR_QR_MAGIC, "v": 2, "id": ID, "nk": "desktop",
            "nm": "N", "h": "192.168.1.20", "p": 5600, "c": "123456"}
    good[field] = value
    import json
    text = f'{pairqr.PAIR_QR_MAGIC} ' + json.dumps(good, ensure_ascii=False,
                                                   separators=(",", ":"))
    with pytest.raises(PairQrError) as exc:
        decode_ticket(text)
    assert exc.value.code == code


@pytest.mark.parametrize("kw,code", [
    (dict(device_id="", name="N", kind="desktop", host="192.168.1.1", port=5600,
          pair_code="123456"), "bad_id"),
    (dict(device_id=ID, name="N", kind="desktop", host="192.168.1.1", port=5600,
          pair_code="12345"), "bad_code"),
    (dict(device_id=ID, name="N", kind="desktop", host="8.8.8.8", port=5600,
          pair_code="123456"), "bad_address"),
    (dict(device_id=ID, name="N", kind="smartfridge", host="192.168.1.1", port=5600,
          pair_code="123456"), "bad_kind"),
])
def test_encode_validates_own_inputs(kw, code):
    with pytest.raises(PairQrError) as exc:
        encode_ticket(**kw)
    assert exc.value.code == code
