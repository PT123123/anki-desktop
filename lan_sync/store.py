"""独立元数据库 `sync.db`（SPEC-v2 §7）：身份、互信表、配对密钥、配对码、配置、同步日志。

业务库（collection.anki2 / media）零改动；密钥单独放一张表，任何 `/devices` 响应都不带它。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA_VERSION = 2
LOG_CAP = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices(
    peer_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT '',
    protocol INTEGER NOT NULL DEFAULT 2,
    endpoints TEXT NOT NULL DEFAULT '[]',
    kid TEXT NOT NULL DEFAULT '',
    security_code TEXT NOT NULL DEFAULT '',
    paired INTEGER NOT NULL DEFAULT 0,
    added_via TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL DEFAULT 0,
    mdns_seen_at REAL NOT NULL DEFAULT 0,
    superseded_by TEXT
);
CREATE TABLE IF NOT EXISTS device_secrets(
    peer_id TEXT PRIMARY KEY,
    kid TEXT NOT NULL,
    secret BLOB NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS pair_codes(
    code TEXT PRIMARY KEY,
    contribution BLOB NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sync_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    peer_id TEXT NOT NULL,
    peer_name TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT '',
    direction TEXT NOT NULL DEFAULT '',
    ok INTEGER NOT NULL DEFAULT 0,
    code TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    bytes_in INTEGER NOT NULL DEFAULT 0,
    details TEXT NOT NULL DEFAULT '{}'
);
"""


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock, self._db:
            self._db.executescript(_SCHEMA)
            self._db.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema', ?)",
                (str(SCHEMA_VERSION),),
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---------------------------------------------------------- meta/config
    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_config(self, key: str, default=None):
        with self._lock:
            row = self._db.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except ValueError:
            return row["value"]

    def set_config(self, key: str, value) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO config(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )

    # ------------------------------------------------------------- devices
    def upsert_device(self, peer_id: str, *, name: str = "", kind: str = "",
                      protocol: int = 2, endpoint: str = "", kid: str = "",
                      via: str = "", now: float | None = None) -> None:
        """换 IP 时保留历史：只补 endpoints/last_seen，不重置 paired 与 first_seen。"""
        now = now if now is not None else time.time()
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT endpoints, first_seen FROM devices WHERE peer_id=?", (peer_id,)
            ).fetchone()
            endpoints = json.loads(row["endpoints"]) if row else []
            if endpoint and endpoint not in endpoints:
                endpoints = [endpoint] + endpoints[:7]
            first_seen = row["first_seen"] if row else now
            self._db.execute(
                """
                INSERT INTO devices(peer_id, name, kind, protocol, endpoints, kid,
                                    added_via, first_seen, last_seen, mdns_seen_at,
                                    superseded_by)
                VALUES(?,?,?,?,?,?,?,?,?,?,NULL)
                ON CONFLICT(peer_id) DO UPDATE SET
                    name=excluded.name, kind=excluded.kind, protocol=excluded.protocol,
                    endpoints=excluded.endpoints,
                    kid=CASE WHEN excluded.kid<>'' THEN excluded.kid ELSE devices.kid END,
                    added_via=CASE WHEN devices.added_via='manual' THEN 'manual'
                                   ELSE excluded.added_via END,
                    first_seen=devices.first_seen,
                    last_seen=excluded.last_seen,
                    -- mDNS 新鲜度要在首次上报时就落下：否则第一次见面的 peer 没有行可 UPDATE，
                    -- 之后的广播仲裁会以为它"从没经 mDNS 出现过"
                    mdns_seen_at=CASE WHEN excluded.added_via='mdns'
                                      THEN excluded.last_seen ELSE devices.mdns_seen_at END
                """,
                (peer_id, name, kind, protocol, json.dumps(endpoints), kid,
                 via, first_seen, now, now if via == "mdns" else 0.0),
            )

    def touch_mdns(self, peer_id: str, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        with self._lock, self._db:
            self._db.execute("UPDATE devices SET mdns_seen_at=? WHERE peer_id=?",
                             (now, peer_id))

    def mdns_recent(self, peer_id: str, within: float, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        with self._lock:
            row = self._db.execute(
                "SELECT mdns_seen_at FROM devices WHERE peer_id=?", (peer_id,)
            ).fetchone()
        return bool(row) and (now - row["mdns_seen_at"]) <= within

    def set_paired(self, peer_id: str, kid: str, security_code: str = "",
                   paired: bool = True) -> None:
        with self._lock, self._db:
            self._db.execute(
                "UPDATE devices SET paired=?, kid=?, security_code=? WHERE peer_id=?",
                (1 if paired else 0, kid, security_code, peer_id),
            )

    def devices(self, include_unpaired: bool = True) -> list[dict]:
        with self._lock:
            sql = "SELECT * FROM devices"
            if not include_unpaired:
                sql += " WHERE paired=1"
            rows = self._db.execute(sql + " ORDER BY last_seen DESC").fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["endpoints"] = json.loads(item.get("endpoints") or "[]")
            item["paired"] = bool(item.get("paired"))
            out.append(item)
        return out

    def forget(self, peer_id: str) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM devices WHERE peer_id=?", (peer_id,))
            self._db.execute("DELETE FROM device_secrets WHERE peer_id=?", (peer_id,))

    # ------------------------------------------------------------- secrets
    def put_secret(self, peer_id: str, kid: str, secret: bytes) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO device_secrets(peer_id, kid, secret, created_at) "
                "VALUES(?,?,?,?) ON CONFLICT(peer_id) DO UPDATE SET "
                "kid=excluded.kid, secret=excluded.secret, created_at=excluded.created_at",
                (peer_id, kid, sqlite3.Binary(secret), time.time()),
            )

    def get_secret(self, peer_id: str) -> tuple[str, bytes] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT kid, secret FROM device_secrets WHERE peer_id=?", (peer_id,)
            ).fetchone()
        return (row["kid"], bytes(row["secret"])) if row else None

    def find_by_kid(self, kid: str) -> tuple[str, bytes] | None:
        """服务端入口：信封头里的 kid -> 是哪个设备 + 共享密钥。"""
        if not kid:
            return None
        with self._lock:
            row = self._db.execute(
                "SELECT peer_id, secret FROM device_secrets WHERE kid=?", (kid,)
            ).fetchone()
        return (row["peer_id"], bytes(row["secret"])) if row else None

    def paired_kids(self) -> list[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT kid FROM device_secrets WHERE kid<>'' ORDER BY created_at"
            ).fetchall()
        return [row["kid"] for row in rows]

    def device(self, peer_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM devices WHERE peer_id=?", (peer_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["endpoints"] = json.loads(item.get("endpoints") or "[]")
        item["paired"] = bool(item.get("paired"))
        return item

    # 只有这些字段能出网；security_code 与 endpoints 之外的本机信息不外发
    _PUBLIC_FIELDS = ("peer_id", "name", "kind", "protocol", "kid", "paired", "last_seen")

    def public_rows(self, since: float = 0.0, only_paired: bool = True) -> list[dict]:
        with self._lock:
            sql = "SELECT * FROM devices"
            args: list = []
            where = []
            if only_paired:
                where.append("paired=1")
            if since:
                where.append("last_seen > ?")
                args.append(since)
            if where:
                sql += " WHERE " + " AND ".join(where)
            rows = self._db.execute(sql, args).fetchall()
        return [{key: dict(row)[key] for key in self._PUBLIC_FIELDS} for row in rows]

    # ---------------------------------------------------------- pair codes
    def new_pair_code(self, code: str, contribution: bytes,
                      ttl_secs: float = 300.0) -> float:
        now = time.time()
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO pair_codes(code, contribution, created_at, expires_at, consumed) "
                "VALUES(?,?,?,?,0)",
                (code, sqlite3.Binary(contribution), now, now + ttl_secs),
            )
        return now + ttl_secs

    def take_pair_code(self, code: str, now: float | None = None) -> bytes:
        """校验 + 一次性消费；失败时按 SPEC 抛对应错误码。"""
        now = now if now is not None else time.time()
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT contribution, expires_at, consumed FROM pair_codes WHERE code=?",
                (code,),
            ).fetchone()
            if not row:
                # 不区分"码不存在"和"码错"，避免探测有效码
                raise _pair_bad("unknown or already used code")
            if row["consumed"]:
                raise _pair_bad("code already consumed", 409, "pair_consumed")
            if now > row["expires_at"]:
                self._db.execute("DELETE FROM pair_codes WHERE code=?", (code,))
                raise _pair_bad("code expired", 410, "pair_expired")
            self._db.execute("UPDATE pair_codes SET consumed=1 WHERE code=?", (code,))
            return bytes(row["contribution"])

    def expire_pair_codes(self, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        with self._lock, self._db:
            cur = self._db.execute("DELETE FROM pair_codes WHERE expires_at < ?", (now,))
        return cur.rowcount

    # --------------------------------------------------------------- log
    def add_log(self, peer_id: str, peer_name: str, mode: str, direction: str, ok: bool,
                code: str = "", duration_ms: int = 0, bytes_out: int = 0,
                bytes_in: int = 0, details: dict | None = None) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO sync_log(ts, peer_id, peer_name, mode, direction, ok, code, "
                "duration_ms, bytes_out, bytes_in, details) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), peer_id, peer_name, mode, direction, 1 if ok else 0, code,
                 duration_ms, bytes_out, bytes_in, json.dumps(details or {})),
            )
            self._db.execute(
                "DELETE FROM sync_log WHERE id NOT IN "
                "(SELECT id FROM sync_log ORDER BY id DESC LIMIT ?)",
                (LOG_CAP,),
            )

    def logs(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM sync_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["ok"] = bool(item["ok"])
            item["details"] = json.loads(item.get("details") or "{}")
            out.append(item)
        return out


def _pair_bad(message: str, status: int = 401, code: str = "pair_invalid"):
    from .protocol import LanError

    return LanError(status, code, message)
