"""Persistent transaction state.

* SQLite (WAL) holds the change records, the pointer to the last confirmed
  policy and an append-only audit trail. It is the single source of truth
  shared by the agent, the guard and the boot service.
* Policies are stored content-addressed (snapshots/<semantic hash>.json).
  A snapshot file is written and fsync'd (file and directory) BEFORE any
  database row refers to it, so the database never points at a file that
  is not on disk.
* One cross-process lock (flock) serialises every state transition. The
  lock file records its holder, so a long-held lock can be diagnosed.

Change states:  prepared -> pending -> confirmed
                                    -> rolled_back
                prepared -> failed  (commit never happened)
                noop                 (same semantic hash as the active policy)
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import sqlite3
import time
import uuid
from typing import Iterator, Optional

STATE_DIR = os.environ.get("MYFW_STATE_DIR", "/var/lib/myfw")
STATES = ("prepared", "pending", "confirmed", "rolled_back", "failed", "noop")

SCHEMA = """
CREATE TABLE IF NOT EXISTS changes(
  id TEXT PRIMARY KEY,
  created REAL NOT NULL,
  updated REAL NOT NULL,
  actor_uid INTEGER,
  actor TEXT,
  state TEXT NOT NULL CHECK(state IN ('prepared','pending','confirmed','rolled_back','failed','noop')),
  policy_hash TEXT NOT NULL,
  previous_hash TEXT,
  generation INTEGER,
  deadline REAL,
  boot_id TEXT,
  reason TEXT,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  change_id TEXT,
  actor_uid INTEGER,
  event TEXT NOT NULL,
  detail TEXT
);
"""


def boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip()
    except OSError:
        return "unknown"


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Store:
    def __init__(self, root: Optional[str] = None):
        self.root = root or STATE_DIR
        self.snap_dir = os.path.join(self.root, "snapshots")
        os.makedirs(self.snap_dir, mode=0o750, exist_ok=True)
        self.db_path = os.path.join(self.root, "state.db")
        self.db = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)

    # ------------------------------------------------------------ snapshots
    def put_snapshot(self, policy_hash: str, canonical: dict) -> str:
        path = os.path.join(self.snap_dir, f"{policy_hash}.json")
        if os.path.exists(path):
            return path
        tmp = f"{path}.tmp-{os.getpid()}"
        with open(tmp, "w") as f:
            json.dump(canonical, f, sort_keys=True, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp, path)
        _fsync_dir(self.snap_dir)
        return path

    def get_snapshot(self, policy_hash: str) -> dict:
        with open(os.path.join(self.snap_dir, f"{policy_hash}.json")) as f:
            return json.load(f)

    def has_snapshot(self, policy_hash: str) -> bool:
        return os.path.exists(os.path.join(self.snap_dir, f"{policy_hash}.json"))

    # ---------------------------------------------------------------- lock
    @contextlib.contextmanager
    def lock(self, op: str, timeout: float = 30.0) -> Iterator[None]:
        path = os.path.join(self.root, "txn.lock")
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o640)
        start = time.monotonic()
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() - start > timeout:
                        holder = os.pread(fd, 512, 0).decode(errors="replace").strip()
                        raise TimeoutError(f"state lock busy for {timeout:.0f}s (held by: {holder or '?'})")
                    time.sleep(0.05)
            os.ftruncate(fd, 0)
            os.pwrite(fd, f"pid={os.getpid()} op={op} since={time.time():.0f}\n".encode(), 0)
            yield
        finally:
            with contextlib.suppress(OSError):
                os.ftruncate(fd, 0)
            os.close(fd)

    # ---------------------------------------------------------------- meta
    def meta(self, key: str) -> Optional[str]:
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # ------------------------------------------------------------- changes
    @staticmethod
    def new_id() -> str:
        return time.strftime("chg-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]

    def create_change(self, cid: str, actor_uid: int, actor: str, policy_hash: str,
                      previous_hash: Optional[str], state: str = "prepared", reason: str = "") -> None:
        now = time.time()
        self.db.execute(
            "INSERT INTO changes(id,created,updated,actor_uid,actor,state,policy_hash,previous_hash,"
            "boot_id,reason) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (cid, now, now, actor_uid, actor, state, policy_hash, previous_hash, boot_id(), reason))
        self.audit(cid, actor_uid, f"change:{state}", {"policy_hash": policy_hash, "reason": reason})

    def update_change(self, cid: str, **fields) -> None:
        if "state" in fields and fields["state"] not in STATES:
            raise ValueError(fields["state"])
        if "detail" in fields and not isinstance(fields["detail"], str):
            fields["detail"] = json.dumps(fields["detail"], sort_keys=True)
        fields["updated"] = time.time()
        cols = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE changes SET {cols} WHERE id=?", (*fields.values(), cid))

    def change(self, cid: str) -> Optional[dict]:
        r = self.db.execute("SELECT * FROM changes WHERE id=?", (cid,)).fetchone()
        return dict(r) if r else None

    def pending(self) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM changes WHERE state='pending' ORDER BY created")]

    def history(self, limit: int = 20) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM changes ORDER BY created DESC LIMIT ?", (limit,))]

    def audit(self, cid: Optional[str], actor_uid: Optional[int], event: str, detail=None) -> None:
        self.db.execute("INSERT INTO audit(ts,change_id,actor_uid,event,detail) VALUES(?,?,?,?,?)",
                        (time.time(), cid, actor_uid, event,
                         json.dumps(detail, sort_keys=True) if detail is not None else None))

    def audit_log(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))]
