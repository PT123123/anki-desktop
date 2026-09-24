"""控制面纯逻辑单测：协议编解码、信封加密、元数据库语义。

这些都不碰网络也不碰 Anki 后端，所以跑得快；越界的部分（HTTP/配对/同步轮/调度）统一在
`tools/lansync_e2e.py` 里跑两个真实例。
"""

from __future__ import annotations

import time

import pytest

from lan_sync import crypto
from lan_sync.anki_bridge import CollectionBridge, HubSeedRequired
from lan_sync.client import PeerClient
from lan_sync.hub import HubServer
from lan_sync.identity import Identity
from lan_sync.protocol import (
    MAGIC_V1,
    MAGIC_V2,
    MODE_APKG,
    MODE_HUB,
    PeerInfo,
    LanError,
    decode_announce,
    encode_announce,
    is_site_local_ipv4,
    pick_mode,
    subnet_broadcast,
)
from lan_sync.store import LOG_CAP, Store


# --------------------------------------------------------------------- 协议
def test_peerinfo_tolerates_unknown_fields():
    info = PeerInfo.from_json('{"device_id":"d1","name":"n","future_field":42}')
    assert info.device_id == "d1" and info.name == "n"


def test_peerinfo_reads_v1_aliases_and_downgrades_modes():
    v1 = PeerInfo.from_json('{"id":"d1","name":"phone","platform":"android",'
                            '"protocol":1,"port":5600,"sentAt":7}')
    assert v1.device_id == "d1" and v1.kind == "android" and v1.ts == 7
    # v1 只支持 apkg：不能让它冒充支持 hub 或配对
    assert v1.modes == [MODE_APKG] and v1.roles == [] and v1.kids == []


def test_peerinfo_v1_compat_output_carries_id():
    payload = PeerInfo(device_id="abcd1234ef", name="desk").to_json(v1_compat=True)
    assert '"id":"abcd1234ef"' in payload and '"platform":"desktop"' in payload


@pytest.mark.parametrize("magic", [MAGIC_V2, MAGIC_V1])
def test_announce_roundtrip(magic):
    info = PeerInfo(device_id="a" * 32, name="desk", port=5601)
    version, decoded = decode_announce(encode_announce(info, magic))
    assert decoded.device_id == info.device_id
    assert version == (2 if magic == MAGIC_V2 else 1)


def test_announce_ignores_foreign_and_broken_packets():
    assert decode_announce(b"HELLO there") is None
    assert decode_announce(b"ANKI-LAN/2 not-json") is None
    assert decode_announce(b"ANKI-LAN/2 ") is None
    assert decode_announce(b"") is None


def test_pick_mode_prefers_hub_and_requires_it_running():
    assert pick_mode([MODE_APKG, MODE_HUB], [MODE_APKG, MODE_HUB], True) == MODE_HUB
    assert pick_mode([MODE_APKG, MODE_HUB], [MODE_APKG, MODE_HUB], False) == MODE_APKG
    assert pick_mode([MODE_HUB], [MODE_APKG], True) is None


def test_ipv4_filters_and_subnet_broadcast():
    assert is_site_local_ipv4("192.168.1.20") and is_site_local_ipv4("10.0.0.5")
    for bad in ("127.0.0.1", "169.254.9.9", "8.8.8.8", "not-an-ip", "::1"):
        assert not is_site_local_ipv4(bad)
    assert subnet_broadcast("192.168.1.20") == "192.168.1.255"
    assert subnet_broadcast("10.7.3.9") == "10.7.3.255"
    assert subnet_broadcast("garbage") is None


# --------------------------------------------------------------------- 信封
def test_seal_open_roundtrip():
    secret = crypto.gen_secret()
    envelope = crypto.seal(b"payload", secret, "devices/sync", kid="k1")
    assert crypto.open_envelope(envelope, secret, "devices/sync", kid="k1") == b"payload"


def test_route_is_part_of_the_key_so_ciphertext_cannot_move_between_routes():
    secret = crypto.gen_secret()
    envelope = crypto.seal(b"payload", secret, "apkg/import", kid="k1")
    with pytest.raises(LanError) as err:
        crypto.open_envelope(envelope, secret, "apkg/export", kid="k1")
    assert err.value.code == "decrypt_failed"


def test_wrong_secret_and_kid_and_tamper_all_rejected():
    secret, other = crypto.gen_secret(), crypto.gen_secret()
    envelope = crypto.seal(b"x", secret, "round/notify", kid="k1")
    with pytest.raises(LanError):
        crypto.open_envelope(envelope, other, "round/notify", kid="k1")
    with pytest.raises(LanError) as err:
        crypto.open_envelope(envelope, secret, "round/notify", kid="k2")
    assert err.value.code == "kid_mismatch"
    tampered = dict(envelope, ct=envelope["ct"][:-4] + "AAAA")
    with pytest.raises(LanError) as err:
        crypto.open_envelope(tampered, secret, "round/notify", kid="k1")
    assert err.value.code == "decrypt_failed"


def test_stale_timestamp_rejected_and_window_is_bounded():
    secret = crypto.gen_secret()
    old = int(time.time()) - 400
    envelope = crypto.seal(b"x", secret, "r", kid="k1", now=old)
    with pytest.raises(LanError) as err:
        crypto.open_envelope(envelope, secret, "r", kid="k1")
    assert err.value.code == "stale_ts"


def test_replay_same_nonce_rejected_once():
    secret = crypto.gen_secret()
    cache = crypto.NonceCache()
    envelope = crypto.seal(b"x", secret, "r", kid="k1")
    crypto.open_envelope(envelope, secret, "r", kid="k1", nonces=cache)
    with pytest.raises(LanError) as err:
        crypto.open_envelope(envelope, secret, "r", kid="k1", nonces=cache)
    assert err.value.code == "replay"


def test_nonce_cache_prunes_old_entries():
    cache = crypto.NonceCache()
    now = time.time()
    assert cache.check_and_store("k", "n1", now)
    cache._seen[("k", "ancient")] = now - crypto.NONCE_CACHE_SECS - 1
    assert cache.check_and_store("k", "n2", now)
    assert ("k", "ancient") not in cache._seen


def test_pair_code_wrap_needs_the_exact_code():
    contribution = crypto.gen_secret()
    envelope = crypto.wrap_with_pair_code("123456", contribution)
    assert crypto.unwrap_with_pair_code("123456", envelope) == contribution
    with pytest.raises(LanError) as err:
        crypto.unwrap_with_pair_code("654321", envelope)
    assert err.value.code == "decrypt_failed"


def test_combine_secrets_is_order_independent():
    a, b = crypto.gen_secret(), crypto.gen_secret()
    shared_ab = crypto.combine_secrets(a, b, "device-A", "device-B")
    shared_ba = crypto.combine_secrets(b, a, "device-B", "device-A")
    assert shared_ab == shared_ba
    # 换一侧的贡献值必须换出完全不同的密钥
    assert crypto.combine_secrets(a, crypto.gen_secret(), "device-A", "device-B") != shared_ab


def test_kid_and_security_code_are_stable_and_short():
    secret = crypto.gen_secret()
    assert crypto.kid_of(secret) == crypto.kid_of(secret)
    assert len(crypto.kid_of(secret)) == 8
    assert len(crypto.gen_security_code(secret)) == 4
    assert set(crypto.gen_pair_code()) <= set("0123456789")


# --------------------------------------------------------------------- 存储
def test_identity_persists_across_reopen(tmp_path):
    store = Store(tmp_path / "sync.db")
    first = store.get_meta("device_id")
    assert first is None
    store.set_meta("device_id", "abc")
    store.close()
    assert Store(tmp_path / "sync.db").get_meta("device_id") == "abc"


def test_upsert_keeps_first_seen_and_paired_when_ip_changes(tmp_path):
    store = Store(tmp_path / "sync.db")
    store.upsert_device("p1", name="phone", endpoint="192.168.1.5:5600", via="udp",
                        now=100.0)
    store.set_paired("p1", "kid1", "ab12")
    store.upsert_device("p1", name="phone2", endpoint="192.168.1.9:5600", via="udp",
                        now=200.0)
    row = store.device("p1")
    assert row["first_seen"] == 100.0 and row["last_seen"] == 200.0
    assert row["paired"] and row["kid"] == "kid1" and row["security_code"] == "ab12"
    assert row["name"] == "phone2"
    # 新端点排在前，历史保留
    assert row["endpoints"] == ["192.168.1.9:5600", "192.168.1.5:5600"]


def test_manual_source_is_sticky(tmp_path):
    store = Store(tmp_path / "sync.db")
    store.upsert_device("p1", endpoint="1.1.1.1:5600", via="manual")
    store.upsert_device("p1", endpoint="1.1.1.1:5600", via="udp")
    assert store.device("p1")["added_via"] == "manual"


def test_empty_kid_does_not_erase_paired_kid(tmp_path):
    store = Store(tmp_path / "sync.db")
    store.upsert_device("p1", kid="kid1", endpoint="a:1")
    store.upsert_device("p1", kid="", endpoint="a:2")
    assert store.device("p1")["kid"] == "kid1"


def test_mdns_seen_only_set_by_mdns(tmp_path):
    store = Store(tmp_path / "sync.db")
    store.upsert_device("p1", endpoint="a:1", via="udp", now=50.0)
    assert not store.mdns_recent("p1", 45.0, now=60.0)
    store.upsert_device("p1", endpoint="a:1", via="mdns", now=100.0)
    assert store.mdns_recent("p1", 45.0, now=120.0)
    assert not store.mdns_recent("p1", 45.0, now=200.0)


def test_pair_code_single_use_and_expiry(tmp_path):
    store = Store(tmp_path / "sync.db")
    store.new_pair_code("123456", b"contribution", ttl_secs=300.0)
    assert store.take_pair_code("123456", now=time.time()) == b"contribution"
    with pytest.raises(LanError) as err:
        store.take_pair_code("123456")
    assert (err.value.status, err.value.code) == (409, "pair_consumed")

    store.new_pair_code("654321", b"other", ttl_secs=1.0)
    with pytest.raises(LanError) as err:
        store.take_pair_code("654321", now=time.time() + 10)
    assert (err.value.status, err.value.code) == (410, "pair_expired")


def test_unknown_code_is_indistinguishable_from_wrong_code(tmp_path):
    store = Store(tmp_path / "sync.db")
    store.new_pair_code("111111", b"x")
    for code in ("222222", "000000"):
        with pytest.raises(LanError) as err:
            store.take_pair_code(code)
        assert (err.value.status, err.value.code) == (401, "pair_invalid")


def test_secret_lookup_by_kid_and_forget(tmp_path):
    store = Store(tmp_path / "sync.db")
    store.upsert_device("p1", name="x", endpoint="a:1")
    store.put_secret("p1", "kid1", b"s" * 32)
    assert store.find_by_kid("kid1") == ("p1", b"s" * 32)
    assert store.paired_kids() == ["kid1"]
    assert store.find_by_kid("") is None and store.find_by_kid("nope") is None
    store.forget("p1")
    assert store.find_by_kid("kid1") is None and store.device("p1") is None


def test_public_rows_never_leak_secrets_or_security_code(tmp_path):
    store = Store(tmp_path / "sync.db")
    store.upsert_device("p1", name="x", kid="kid1", endpoint="a:1", via="mdns")
    store.put_secret("p1", "kid1", b"top-secret" + b"\0" * 22)
    store.set_paired("p1", "kid1", "abcd")
    rows = store.public_rows()
    assert [r["peer_id"] for r in rows] == ["p1"]
    assert rows[0]["kid"] == "kid1"
    for leaked in ("security_code", "endpoints", "top-secret"):
        assert leaked not in str(rows)


def test_public_rows_since_cursor(tmp_path):
    store = Store(tmp_path / "sync.db")
    store.upsert_device("p1", endpoint="a:1", now=10.0)
    store.set_paired("p1", "k", "s")
    assert store.public_rows(since=5.0) and not store.public_rows(since=50.0)


def test_log_capped_and_newest_first(tmp_path):
    store = Store(tmp_path / "sync.db")
    for index in range(LOG_CAP + 40):
        store.add_log("p1", "phone", "apkg", "round", index % 3 == 0, code=f"c{index}")
    logs = store.logs(limit=5)
    assert len(store.logs(limit=LOG_CAP + 100)) == LOG_CAP
    newest = LOG_CAP + 39
    assert logs[0]["code"] == f"c{newest}"
    assert logs[0]["ok"] == (newest % 3 == 0)
    assert [row["code"] for row in logs] == [f"c{newest - i}" for i in range(5)]


def test_corrupt_config_value_falls_back_to_string(tmp_path):
    store = Store(tmp_path / "sync.db")
    with store._lock, store._db:
        store._db.execute("INSERT INTO config(key, value) VALUES('k', 'not json{')")
    assert store.get_config("k") == "not json{"
    assert store.get_config("missing", "default") == "default"


# ---------------------------------------------------------------- hub 与全量
class _FakeCol:
    def __init__(self, notes):
        self._notes = notes

    def note_count(self):
        return self._notes


@pytest.mark.parametrize("required,expected", [
    ("FULL_UPLOAD", True),   # 服务端这个 hkey 下还没库：上传不覆盖任何人
    ("FULL_DOWNLOAD", False),
])
def test_safe_full_sync_directions_follow_rslib(required, expected):
    assert CollectionBridge._decide_full_sync(_FakeCol(7), required, None) is expected


def test_diverged_full_sync_refuses_to_pick_a_winner():
    """FULL_SYNC = 两边都有内容。悄悄选 upload 会把对端刚播下的库整库换掉。"""
    with pytest.raises(HubSeedRequired) as err:
        CollectionBridge._decide_full_sync(_FakeCol(7), "FULL_SYNC", None)
    assert err.value.code == "hub_seed_required"


@pytest.mark.parametrize("full,expected", [("upload", True), ("download", False)])
def test_explicit_seed_decision_overrides_refusal(full, expected):
    assert CollectionBridge._decide_full_sync(_FakeCol(7), "FULL_SYNC", full) is expected


def test_hub_has_exactly_one_shared_account_hence_one_namespace(tmp_path):
    hub = HubServer(tmp_path / "hub")
    first = hub.grant_shared()
    assert hub.grant_shared() == first, "两台设备各拿一个账号 = 两个互不可见的库"
    assert hub.rotate_shared() != first
    assert hub.load_users().keys() == {HubServer.SHARED}


def test_hub_writes_credentials_before_spawning(tmp_path):
    """syncserver 没有 SYNC_USERn 会直接拒绝启动，所以凭据必须先落盘。"""
    hub = HubServer(tmp_path / "hub")
    assert hub.load_users() == {}
    hub._ensure_shared()
    assert hub.load_users()[HubServer.SHARED]["username"].startswith("lan_")


# ------------------------------------------------------------------ 客户端
def test_notify_sends_payload_at_top_level():
    """hub 补同步靠服务端读到顶层 `hub`；曾经被包进 counts 里而整条路径静默失效。"""
    seen = {}

    def fake_post_envelope(host, port, peer_id, route, payload):
        seen.update(route=route, payload=payload)
        return {"queued": True}

    client = PeerClient(store=None, identity=Identity("d1", "desktop"))
    client.post_envelope = fake_post_envelope
    client.notify("h", 5600, "p1", {"hub": {"endpoint": "http://x:1/"}})
    assert seen["route"] == "round/notify"
    assert seen["payload"]["hub"]["endpoint"] == "http://x:1/"
    assert "counts" not in seen["payload"]
    assert "mod_ts" in seen["payload"]


# ------------------------------------------------------------------ 互操作向量
def _import_vectors():
    import json
    import subprocess
    import sys
    from pathlib import Path

    tools = Path(__file__).resolve().parents[2] / "tools"
    sys.path.insert(0, str(tools))
    import lansync_vectors as gen  # noqa: PLC0415

    path = gen.TARGETS[0]
    if not path.exists():
        pytest.skip(f"{path} 不存在：先跑 tools/lansync_vectors.py")
    return gen, json.loads(path.read_text(encoding="utf-8"))


def test_interop_vectors_match_this_implementation():
    """两端各自的实现必须从同一批输入算出同一批字节（SPEC-v2 §4.6）。"""
    gen, doc = _import_vectors()
    assert gen.finalize(gen.build()) == doc, "vectors.json 与本机实现不一致：重跑生成器或改回了格式"


def test_interop_vector_file_is_shared_with_android_copy():
    """安卓 JVM 测试读的是副本；两份必须逐字节相同，否则互操作断言各自为政。"""
    gen, _ = _import_vectors()
    texts = [p.read_text(encoding="utf-8") for p in gen.TARGETS if p.exists()]
    assert len(texts) == len(gen.TARGETS), [str(p) for p in gen.TARGETS if not p.exists()]
    assert len(set(texts)) == 1
