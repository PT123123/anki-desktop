"""桌面端局域网同步端到端台架（SPEC-v2 §10）。

同机起**两个真实实例**（各自的 `sync.db` + 各自的 `collection.anki2` + 各自的 HTTP 端口，
私有端口段，不碰 5600/46000），跑完：
配对 → 鉴权负例 → apkg 一轮 → hub 一轮（含内置 syncserver 子进程）→ 调度策略 → 日志。

台架纪律（探针阶段踩出来的）：
- 每条断言打 `[PASS|FAIL|SKIP] <臂名>::<检查> :: <具体值>`，末尾数结论条数；
- **控制断言**：先证明"起点确实是两笔不同的数据"，否则后面的收敛可能是空库假过；
- 上游没送达时**显式 SKIP 下游**，而不是让下游必然为真地假过。

用法：`python tools/lansync_e2e.py`（在 `anki-desktop` 目录下，用装好 anki 轮子的解释器）。
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests  # noqa: E402

from lan_sync import crypto  # noqa: E402
from lan_sync.engine import LanEngine  # noqa: E402
from lan_sync.protocol import (  # noqa: E402
    HEADER_ENVELOPE,
    HEADER_KID,
    HEADER_MAGIC,
    HEADER_XFER,
    MAGIC_V2,
    MODE_APKG,
    MODE_HUB,
)
from lan_sync.scheduler import Scheduler  # noqa: E402

WORK = Path(os.environ.get("LANSYNC_E2E_DIR",
                           Path(tempfile.gettempdir()) / "anki-lansync-e2e"))
# Windows 控制台默认 GBK，断言详情里有中文/替换字符会直接崩
for _stream in (sys.stdout, sys.stderr):
    _stream.reconfigure(encoding="utf-8", errors="replace")
PORT_A, PORT_B = 47620, 47621
UDP_A, UDP_B = 47631, 47632
HUB_A = 47640
# 种子 note 的精确文本（seed_collection 生成 `<marker>-<index>`）
NOTE_A, NOTE_B = "armA-alpha-0", "armB-beta-0"
NOTE_LATE = "armB-late-9"
CONCLUSIONS: list[tuple[str, str]] = []
SKIPPED = 0


def log(kind: str, name: str, detail: str = "") -> None:
    global SKIPPED
    if kind == "SKIP":
        SKIPPED += 1
    else:
        CONCLUSIONS.append((kind, name))
    print(f"[{kind}] {name} :: {detail}", flush=True)


def check(name: str, ok: bool, detail: str = "") -> bool:
    log("PASS" if ok else "FAIL", name, detail)
    return bool(ok)


def bail(prefix: str, checks: list[str], reason: str) -> None:
    """上游失败时：把依赖它的检查逐个记成 SKIP，而不是让它们假过。"""
    for name in checks:
        log("SKIP", f"{prefix}::{name}", f"依赖上游，原因：{reason}")


# ------------------------------------------------------------------ 数据准备
def seed_collection(path: Path, marker: str, count: int) -> None:
    from anki.collection import Collection

    path.parent.mkdir(parents=True, exist_ok=True)
    col = Collection(str(path))
    try:
        tid = col.models.all_names_and_ids()[0].id
        for index in range(count):
            note = col.new_note(tid)
            note.fields[0] = f"{marker}-{index}"
            col.add_note(note, 1)
    finally:
        col.close()


def note_ids(engine: LanEngine, text: str) -> list[int]:
    """按首字段精确定位。`flds` 用 \\x1f 分隔字段，所以整条 note 就是 `text\\x1f`。

    用 like 前缀会串味：`armA-alpha%` 同时命中 armA-alpha-0 和 -1，删除断言就会
    因为"预期 1 条实到 2 条"假失败。
    """
    key = text + "\x1f"
    with engine.bridge.exclusive() as col:
        return [row[0] for row in col.db.all("select id from notes where flds = ?", key)]


def has_note(engine: LanEngine, text: str) -> bool:
    key = text + "\x1f"
    with engine.bridge.exclusive() as col:
        return bool(col.db.scalar("select 1 from notes where flds = ? limit 1", key))


def count_notes(engine: LanEngine) -> int:
    return int(engine.bridge.counts()["notes"])


def add_note(engine: LanEngine, text: str) -> None:
    with engine.bridge.exclusive() as col:
        tid = col.models.all_names_and_ids()[0].id
        note = col.new_note(tid)
        note.fields[0] = text
        col.add_note(note, 1)


def wait_until(predicate, timeout: float = 60.0, every: float = 1.0) -> bool:
    """等一个后台事件（notify 引发的补同步在别的线程里跑）。到点返回 False。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(every)
    return predicate()


def log_codes(engine: LanEngine, direction: str) -> list[str]:
    return [row["code"] for row in engine.store.logs(limit=200)
            if row["direction"] == direction and not row["ok"]]


def make_engine(tag: str, port: int, udp: int, marker: str, notes: int) -> LanEngine:
    seed_collection(WORK / f"col-{tag}" / "collection.anki2", marker, notes)
    engine = LanEngine(
        data_dir=WORK / f"data-{tag}",
        collection_path=WORK / f"col-{tag}" / "collection.anki2",
        bind_host="127.0.0.1", http_port_start=port, http_port_end=port,
        udp_port=udp, mdns=False, hub_port_start=HUB_A, hub_port_end=HUB_A + 5,
    )
    engine.set_cfg("enabled", True)
    engine.start()
    return engine


def base(engine: LanEngine) -> str:
    return f"http://127.0.0.1:{engine.port}"


def sealed_request(target: LanEngine, peer_id: str, route: str, payload: dict,
                   now: int | None = None) -> dict:
    kid, secret = target.store.get_secret(peer_id)
    envelope = crypto.seal(json.dumps(payload).encode(), secret, route, kid=kid, now=now)
    return envelope


def post_envelope(url: str, envelope: dict, kid: str) -> requests.Response:
    return requests.post(url, data=json.dumps(envelope).encode(),
                         headers={HEADER_MAGIC: MAGIC_V2, HEADER_KID: kid}, timeout=20)


# ------------------------------------------------------------------- 各臂
def arm_pair(a: LanEngine, b: LanEngine) -> bool:
    session = a.begin_pairing()
    code = session["pair_code"]
    check("E1::pair-code-is-6-digits", len(code) == 6 and code.isdigit(), code)
    check("E1::pair-code-not-on-the-wire", "contribution" not in json.dumps(session), "本机响应不含贡献值")

    result = b.pair_with(f"127.0.0.1:{a.port}", code)
    b_id, a_id = b.identity.device_id, a.identity.device_id
    check("E1::both-sides-know-each-other",
          a.peer_state(b_id) is not None and b.peer_state(a_id) is not None,
          f"A sees {len(a.peers())} peer(s), B sees {len(b.peers())}")
    check("E1::paired-flag-both-sides",
          bool(a.peer_state(b_id) and a.peer_state(b_id).paired)
          and bool(b.peer_state(a_id) and b.peer_state(a_id).paired), "paired=True")
    kid_a = a.store.get_secret(b_id)
    kid_b = b.store.get_secret(a_id)
    check("E1::same-kid-derived-both-sides", kid_a is not None and kid_a[0] == kid_b[0],
          f"kid A={kid_a and kid_a[0]} B={kid_b and kid_b[0]}")
    same_secret = kid_a and kid_b and a.store.get_secret(b_id)[1] == b.store.get_secret(a_id)[1]
    check("E1::shared-secret-equal-both-sides", bool(same_secret), "combine_secrets 定序生效")

    sec_a = (a.store.device(b_id) or {}).get("security_code")
    check("E1::security-codes-match", sec_a == result["security_code"],
          f"A={sec_a} B={result['security_code']}")

    reused = False
    try:
        b.pair_with(f"127.0.0.1:{a.port}", code)
    except Exception as exc:  # noqa: BLE001
        reused = getattr(exc, "code", "") in ("pair_invalid", "pair_consumed", "decrypt_failed")
    check("E1::pair-code-single-use", reused, "第二次用同一码被拒")

    wrong = None
    try:
        b.pair_with(f"127.0.0.1:{a.port}", "000000")
    except Exception as exc:  # noqa: BLE001
        wrong = getattr(exc, "code", type(exc).__name__)
    check("E1::wrong-code-rejected-401", wrong == "pair_invalid" or wrong == "decrypt_failed",
          str(wrong))
    return bool(same_secret) and sec_a == result["security_code"]


def arm_auth(a: LanEngine, b: LanEngine) -> None:
    b_id = b.identity.device_id

    resp = requests.get(base(a) + "/apkg/export", timeout=20)
    check("E2::no-unauthenticated-get-route", resp.status_code == 404,
          f"{resp.status_code} v2 根本没有不带信封的取包入口")

    resp = requests.post(base(a) + "/apkg/export", data=b"{}",
                         headers={HEADER_KID: "deadbeef"}, timeout=20)
    check("E2::missing-magic-403", resp.status_code == 403
          and resp.json().get("error") == "need_magic", f"{resp.status_code} {resp.text[:60]}")

    resp = requests.post(base(a) + "/devices/sync", data=b"{}",
                         headers={HEADER_MAGIC: MAGIC_V2, HEADER_KID: "deadbeef"}, timeout=20)
    check("E2::unknown-kid-403", resp.status_code == 403, f"{resp.status_code} {resp.text[:60]}")

    resp = requests.post(base(a) + "/devices/sync", data=b"{}",
                         headers={HEADER_MAGIC: MAGIC_V2, HEADER_KID: "00000000"}, timeout=20)
    check("E2::zero-kid-403", resp.status_code == 403, resp.text[:60])

    kid = a.store.get_secret(b_id)[0]
    good = sealed_request(b, a_id_for(b), "devices/sync", {"since": 0.0})
    replay = post_envelope(base(a) + "/devices/sync", good, kid)
    check("E2::valid-envelope-accepted", replay.status_code == 200,
          f"{replay.status_code} {replay.text[:60]}")
    again = post_envelope(base(a) + "/devices/sync", good, kid)
    check("E2::replay-rejected-401", again.status_code == 401
          and again.json().get("error") == "replay", f"{again.status_code} {again.text[:60]}")

    stale = sealed_request(b, a_id_for(b), "devices/sync", {"since": 0.0},
                           now=int(time.time()) - 400)
    resp = post_envelope(base(a) + "/devices/sync", stale, kid)
    check("E2::stale-timestamp-401", resp.status_code == 401
          and resp.json().get("error") == "stale_ts", resp.text[:60])

    # 密钥按路由派生：把 apkg/import 路由的信封打到 devices/sync 上必须解不开
    cross_route = sealed_request(b, a_id_for(b), "apkg/import", {"bytes": 1})
    resp = post_envelope(base(a) + "/devices/sync", cross_route, kid)
    check("E2::ciphertext-cannot-move-between-routes", resp.status_code == 401,
          f"{resp.status_code} {resp.text[:60]}")

    resp = requests.post(base(a) + "/apkg/import", data=b"not-an-apkg",
                         headers={HEADER_MAGIC: MAGIC_V2, HEADER_KID: kid}, timeout=20)
    check("E2::import-needs-envelope", resp.status_code in (400, 401), resp.text[:60])

    envelope = sealed_request(b, a_id_for(b), "apkg/import", {"bytes": 10 ** 13})
    resp = requests.post(base(a) + "/apkg/import", data=b"x",
                         headers={HEADER_MAGIC: MAGIC_V2, HEADER_KID: kid,
                                  HEADER_ENVELOPE: base64.urlsafe_b64encode(
                                      json.dumps(envelope).encode()).decode("ascii"),
                                  "Content-Length": "1"}, timeout=20)
    check("E2::declared-oversize-507", resp.status_code == 507,
          f"{resp.status_code} {resp.text[:60]}")

    resp = requests.get(base(a) + "/export", headers={"X-Ankiplus-Lansync": "ANKIPLUS-LAN/1"},
                        timeout=20)
    check("E2::v1-plaintext-off-by-default", resp.status_code == 403, resp.text[:60])

    a.set_cfg("allow_v1_plaintext", True)
    try:
        resp = requests.get(base(a) + "/export", timeout=20)
        check("E2::v1-export-still-needs-magic", resp.status_code == 403,
              f"{resp.status_code} 开着降级也不能让浏览器标签页拖走整库")
        resp = requests.get(base(a) + "/export",
                            headers={"X-Ankiplus-Lansync": "ANKIPLUS-LAN/1"}, timeout=20)
        check("E2::v1-export-ok-when-explicitly-allowed", resp.status_code == 200
              and resp.content[:2] == b"PK", f"{resp.status_code} {len(resp.content)}B")
    finally:
        a.set_cfg("allow_v1_plaintext", False)

    resp = requests.get(base(a) + "/state", timeout=20)
    check("E2::state-is-loopback-readable", resp.status_code == 200, "127.0.0.1 能读本机状态")

    resp = requests.get(base(a) + "/info", timeout=20)
    info = resp.json()
    check("E2::info-has-v1-aliases", info.get("id") == a.identity.device_id
          and "device_id" in info, "v1 同伴也读得懂")
    check("E2::info-leaks-no-secrets", "secret" not in json.dumps(info).lower(),
          json.dumps(info)[:80])


def a_id_for(engine: LanEngine) -> str:
    """engine 的对端 id（台架只有两台，直接取 paired 列表里唯一一项）。"""
    return next(iter(row["peer_id"] for row in engine.store.devices() if row["paired"]))


def arm_apkg(a: LanEngine, b: LanEngine) -> bool:
    a_id, b_id = a.identity.device_id, b.identity.device_id
    a.register_peer(b.info(), "127.0.0.1", b.port, "manual")
    b.register_peer(a.info(), "127.0.0.1", a.port, "manual")
    check("E0::premise-two-different-collections",
          has_note(a, NOTE_A) and not has_note(b, NOTE_A)
          and has_note(b, NOTE_B) and not has_note(a, NOTE_B),
          "起点确实不收敛，后面的收敛断言才有意义")

    result = b.sync_round(a_id)
    check("E3::apkg-mode-picked", result["mode"] == "apkg", str(result["mode"]))
    delivered = has_note(b, NOTE_A) and has_note(a, NOTE_B)
    check("E3::round-trip-union-both-ways", delivered,
          f"B has {NOTE_A}={has_note(b, NOTE_A)} A has {NOTE_B}={has_note(a, NOTE_B)}")
    if not delivered:
        bail("E3", ["deletion-does-not-propagate-in-apkg"], "上一轮没送达，删除断言会假过")
        return False

    # 已实测语义：.apkg 累积合并 => 删除永远不会传播。这条断言把缺陷钉住，别让它悄悄"修好"。
    ids = note_ids(b, NOTE_A)
    if not check("E3::note-id-found-in-B", len(ids) == 1, str(ids)):
        bail("E3", ["deletion-does-not-propagate-in-apkg"], "定位不到那条 note")
        return delivered
    with b.bridge.exclusive() as locked:
        locked.remove_notes(ids)
    check("E3::deleted-on-B", not has_note(b, NOTE_A), f"removed {ids}")
    a.sync_round(b_id)
    back = has_note(b, NOTE_A)
    check("E3::deletion-does-not-propagate-in-apkg", back,
          "已知语义缺陷：A 推来的包把它复活了")
    return delivered


def arm_hub(a: LanEngine, b: LanEngine) -> bool:
    a.set_cfg("hub_role", True)
    a.hub.host = "127.0.0.1"
    try:
        endpoint = a.hub.start()
    except Exception as exc:  # noqa: BLE001
        check("E4::hub-server-starts", False, f"{type(exc).__name__}: {exc}")
        bail("E4", ["grant-issued", "hub-round-converges", "deletion-propagates-in-hub"],
             "hub 服务端没起来")
        return False
    check("E4::hub-server-listens", a.hub.running, endpoint)

    a.register_peer(b.info(), "127.0.0.1", b.port, "manual")
    b.register_peer(a.info(), "127.0.0.1", a.port, "manual")
    info = json.loads(a.info_json())
    check("E4::hub-advertised-in-info", "hub" in info["roles"] and info["hub_port"] > 0,
          f"roles={info['roles']} hub_port={info['hub_port']}")
    # modes = "能作为发起端参与哪个数据面"（桌面两者皆可），roles = "我在不在 serve"。
    # 把两件事混在一起会导致只有 hub 宿主能走 hub 模式 —— 那正好是错的。
    check("E4::client-side-hub-capability-advertised", MODE_HUB in info["modes"],
          str(info["modes"]))
    # B 此时还没开自己的 hub，它对 A 的公告必须判出 hub：只看 peer 的 roles/hub_port
    b_info = json.loads(b.info_json())
    check("E4::non-hoster-does-not-serve", "hub" not in b_info["roles"]
          and b_info["hub_port"] == 0, f"roles={b_info['roles']} hub_port={b_info['hub_port']}")

    mode = b.negotiate_mode(b.peer_state(a.identity.device_id))
    check("E4::hub-preferred-over-apkg", mode == MODE_HUB, str(mode))
    # 我自己在 serve 时也必须走 hub，绝不退 apkg：整库推过去会把对端删掉的卡片复活。
    host_mode = a.negotiate_mode(a.peer_state(b.identity.device_id))
    check("E4::hub-host-never-pushes-apkg", host_mode == MODE_HUB, str(host_mode))
    # 对端只认 apkg（例如没实现 hub 的旧 v2 端）时才允许退回 apkg
    from lan_sync.engine import PeerState

    legacy = PeerState(peer_id="x" * 36, host="127.0.0.1", port=1, protocol=2,
                       modes=[MODE_APKG], roles=["p2p"])
    check("E4::apkg-fallback-for-hub-incompetent-peer",
          a.negotiate_mode(legacy) == MODE_APKG, str(a.negotiate_mode(legacy)))

    grant = b.client.hub_grant("127.0.0.1", a.port, a.identity.device_id)
    check("E4::grant-has-credentials", bool(grant.get("username") and grant.get("password")),
          str(grant.get("endpoint")))

    unpaired = LanEngine(data_dir=WORK / "data-C", collection_path=WORK / "col-C" / "collection.anki2",
                         bind_host="127.0.0.1", http_port_start=PORT_B + 5,
                         http_port_end=PORT_B + 5, udp_port=UDP_B + 5, mdns=False)
    unpaired.set_cfg("enabled", True)
    unpaired.start()
    seed_collection(WORK / "col-C" / "collection.anki2", "armC", 1)
    denied = None
    try:
        unpaired.client.hub_grant("127.0.0.1", a.port, unpaired.identity.device_id)
    except Exception as exc:  # noqa: BLE001
        denied = getattr(exc, "code", type(exc).__name__)
    check("E4::grant-requires-pairing", denied == "not_paired", str(denied))

    # 命名空间还空着：B 这一轮是安全的引导式 FULL_UPLOAD
    result = b.sync_round(a.identity.device_id, mode=MODE_HUB)
    converged = has_note(a, NOTE_B)
    if not check("E4::hub-delivered-B-to-A", converged, f"A has {NOTE_B}={converged}"):
        bail("E4", ["deletion-propagates-in-hub"], "hub 没把 B 的数据送到 A，删除传播会假过")
        return False
    check("E4::round-reported-hub", result["mode"] == MODE_HUB, str(result.get("mode")))

    # A 收到 notify 后的补同步面对的是"两边都有内容"，必须**拒绝**悄悄覆盖。
    # 悄悄 full_upload 会把刚播下的库整库换掉 —— 这条断言钉住那个数据丢失路径。
    refused = wait_until(lambda: "hub_seed_required" in log_codes(a, "sync"), timeout=30)
    check("E4::diverged-host-refused-silent-clobber", refused,
          f"A 的失败码={log_codes(a, 'sync')}")
    if not refused:
        bail("E4", ["explicit-adopt-converges", "two-way-incremental-after-adopt",
                    "deletion-propagates-in-hub"], "没有 seed 分歧可裁决，后续前提不成立")
        return False
    check("E4::refusal-left-local-data-intact", has_note(a, NOTE_A) and has_note(a, NOTE_B),
          "拒绝期间本机一条没少")

    # 显式裁决：A 加入 hub。E3 的 apkg 轮已经把两边合成并集，所以这一步不丢数据
    # （这正是文档要写清的前置：先合流，再选种子，之后才谈删除传播）。
    a.hub_seed(b.identity.device_id, upload=False)
    adopted = wait_until(lambda: count_notes(b) == count_notes(a), timeout=30)
    check("E4::explicit-adopt-converges", adopted, f"A={count_notes(a)} B={count_notes(b)}")

    add_note(b, NOTE_LATE)
    b.sync_round(a.identity.device_id, mode=MODE_HUB)
    both = wait_until(lambda: has_note(a, NOTE_LATE), timeout=60)
    check("E4::two-way-incremental-after-adopt", both, f"A has {NOTE_LATE}={has_note(a, NOTE_LATE)}")

    with b.bridge.exclusive() as locked:
        locked.remove_notes(note_ids(b, NOTE_B))
    b.sync_round(a.identity.device_id, mode=MODE_HUB)
    # A 拉自己那一半仍在后台线程（handle_notify -> _hub_sync_as_server），必须等它
    gone = wait_until(lambda: not has_note(a, NOTE_B), timeout=60)
    check("E4::deletion-propagates-in-hub", gone,
          f"A 上 {NOTE_B} 是否还在 = {has_note(a, NOTE_B)}（graves 生效）")
    # 复活检查：hub 模式下删除之后不该再被任何一轮带回来
    b.sync_round(a.identity.device_id, mode=MODE_HUB)
    check("E4::deleted-note-stays-deleted", not has_note(a, NOTE_B),
          "再来一轮仍然没有复活（对照 apkg 臂的 resurrection）")
    return gone


def arm_scheduler(a: LanEngine, b: LanEngine) -> None:
    # _dirty 的键是**对端** id。这里必须以 A 为观察者、用 b_id 当键；
    # 拿自己的 id 当 peer 会让 due_peers 永远过滤掉，四条断言全成假失败。
    peer = b.identity.device_id
    # 上一臂为了等后台 ack 可能耗掉几十秒，peer 会被判 offline 而被 due_peers 过滤掉。
    # 本臂考的是"什么时候同步"的策略，不掺活体检测，所以这里显式续一次期。
    a.register_peer(b.info(), "127.0.0.1", b.port, "manual")
    a.clear_dirty([peer])
    a.mark_dirty(peer, reason="test")
    check("E5::debounce-holds", a.due_peers(debounce=5.0, min_interval=0.0) == [],
          "刚标脏还在去抖窗口内")
    a._dirty[peer] = time.time() - 10  # noqa: SLF001 - 台架直接把时钟往前拨
    check("E5::due-after-debounce", a.due_peers(debounce=5.0, min_interval=0.0) == [peer],
          f"过窗即排上 dirty={list(a._dirty)}")  # noqa: SLF001
    a._last_round[peer] = time.time()  # noqa: SLF001
    check("E5::min-interval-blocks", a.due_peers(debounce=5.0, min_interval=15.0) == [],
          "15s 最小间隔内不重复同步")
    a._last_round[peer] = time.time() - 20  # noqa: SLF001
    check("E5::min-interval-expires", a.due_peers(debounce=5.0, min_interval=15.0) == [peer],
          "间隔过了就重新排上")

    a.clear_dirty([peer])
    a.note_local_write(caused_by=peer)
    check("E5::write-skips-source-peer", peer not in a._dirty,  # noqa: SLF001
          f"导入引发的本地写不回推来源，dirty={list(a._dirty)}")  # noqa: SLF001
    a.note_local_write(caused_by="")
    check("E5::local-write-dirties-peers", peer in a._dirty,  # noqa: SLF001
          "来源为空的本地写入会排上所有已配对 peer")
    a.clear_dirty([peer])

    scheduler = Scheduler(a)
    a.request_immediate("harness")
    actions = scheduler.step()
    check("E5::immediate-reason-consumed", actions["reasons"] == ["harness"]
          and a.consume_immediate() == [], str(actions))
    a.set_cfg("enabled", False)
    scheduler.step()
    check("E5::disable-closes-listener", a.server is None and not a.enabled(), "关开关即收端口")
    a.set_cfg("enabled", True)
    a.start()
    check("E5::restart-recovers-port", a.port > 0, str(a.port))


def arm_history(a: LanEngine, b: LanEngine) -> None:
    logs = a.store.logs(limit=50)
    modes = {row["mode"] for row in logs}
    check("E6::log-modes-are-labelled", "apkg" in modes and "hub" in modes,
          f"modes={sorted(modes)}")
    check("E6::log-has-timings", any(row["duration_ms"] > 0 for row in logs),
          f"{sum(1 for r in logs if r['duration_ms'] > 0)} 条带耗时")
    check("E6::log-names-peer", any(row["peer_name"] for row in logs),
          str({r["peer_name"] for r in logs})[:60])
    round_rows = [row for row in logs if row["direction"] == "round"]
    check("E6::rounds-recorded", len(round_rows) >= 2, f"{len(round_rows)} 条 round 记录")
    failing = [row for row in logs if not row["ok"]]
    check("E6::failures-carry-a-code", all(row["code"] for row in failing),
          f"{len(failing)} 条失败记录 code={sorted({r['code'] for r in failing})[:5]}")
    check("E6::bytes-accounted", any(row["bytes_out"] or row["bytes_in"] for row in logs),
          f"in={sum(r['bytes_in'] for r in logs)} out={sum(r['bytes_out'] for r in logs)}")
    for name in ("pair", "grant"):
        check(f"E6::{name}-logged", any(row["direction"] == name for row in logs), "")


# ------------------------------------------------------------------- main
def main() -> int:
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    print(f"# lansync e2e workdir: {WORK}", flush=True)

    a = make_engine("A", PORT_A, UDP_A, "armA-alpha", 2)
    b = make_engine("B", PORT_B, UDP_B, "armB-beta", 3)
    check("E0::two-instances-up", a.port == PORT_A and b.port == PORT_B,
          f"A={a.port} B={b.port} 私有端口段，不碰 5600/46000")
    check("E0::distinct-identities", a.identity.device_id != b.identity.device_id,
          f"{a.identity.device_id[:8]} vs {b.identity.device_id[:8]}")

    try:
        paired = arm_pair(a, b)
        if not paired:
            bail("E2-E6", ["鉴权负例", "apkg 一轮", "hub 一轮", "调度策略", "日志"],
                 "配对没成功，后面全部跳过")
        else:
            arm_auth(a, b)
            if arm_apkg(a, b):
                arm_hub(a, b)
            else:
                bail("E4", ["hub 全部断言"], "apkg 轮没让两边收敛，hub 臂的对照失去前提")
            arm_scheduler(a, b)
            arm_history(a, b)
    finally:
        for engine in (a, b):
            try:
                engine.stop()  # 顺带回收 hub 的 syncserver 子进程
                engine.store.close()
            except Exception:  # noqa: BLE001
                log("SKIP", "cleanup", "某个实例没干净关闭")

    passed = sum(1 for kind, _ in CONCLUSIONS if kind == "PASS")
    failed = sum(1 for kind, _ in CONCLUSIONS if kind == "FAIL")
    print(f"CONCLUSIONS: {passed} pass, {failed} fail, {SKIPPED} skip "
          f"(total {len(CONCLUSIONS)} counted)", flush=True)
    for kind, name in CONCLUSIONS:
        if kind == "FAIL":
            print(f"  FAILED: {name}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
