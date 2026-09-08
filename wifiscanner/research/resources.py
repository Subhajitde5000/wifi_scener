"""Lab Resource Manager — §17.

Centralized registry for wireless adapters, monitor interfaces, APs,
controlled endpoints, sensors, VMs, datasets, replay sources and capture
interfaces.

Responsibilities
----------------
* Register resources with capabilities (monitor_mode, injection, rssi, …)
* Track health / availability / current allocation / owner / heartbeat
* Prevent conflicting allocations (one experiment per exclusive resource)
* Auto-release when an experiment terminates unexpectedly (heartbeat timeout)
* Provide allocation token that experiment engine checks before privileged ops

Resources are *lab-scoped*: the manager refuses to allocate an “out-of-scope”
target (e.g. scan-lab sentinel, inject third-party BSSID).

The manager is intentionally separate from the detector/pipeline so the
laboratory authorization layer can be audited independently.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

from ..privacy import ensure_secure_storage
from ..util import log

RESOURCE_SCHEMA = """
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS lab_resources(
  id TEXT PRIMARY KEY,
  kind TEXT,            -- adapter|monitor|ap|sensor|vm|dataset|replay|capture
  name TEXT,
  capabilities TEXT,    -- JSON list
  health TEXT DEFAULT 'unknown',  -- unknown|ok|degraded|offline
  available INTEGER DEFAULT 1,
  allocated_to TEXT,    -- experiment/run id
  owner TEXT,
  config TEXT,          -- JSON
  last_heartbeat REAL,
  created_at REAL,
  metadata TEXT
);
CREATE TABLE IF NOT EXISTS allocations(
  token TEXT PRIMARY KEY,
  resource_id TEXT,
  experiment_id TEXT,
  run_id TEXT,
  allocated_at REAL,
  expires_at REAL,
  released_at REAL,
  reason TEXT,
  FOREIGN KEY(resource_id) REFERENCES lab_resources(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_res_kind ON lab_resources(kind);
CREATE INDEX IF NOT EXISTS idx_res_alloc ON lab_resources(allocated_to);
CREATE INDEX IF NOT EXISTS idx_alloc_run ON allocations(run_id);
"""

HEARTBEAT_TIMEOUT_S = 120  # orphaned if no heartbeat for 2 min
DEFAULT_LEASE_S = 3600


@dataclass
class LabResource:
    id: str
    kind: str
    name: str
    capabilities: List[str] = field(default_factory=list)
    health: str = "unknown"
    available: bool = True
    allocated_to: str = ""
    owner: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    last_heartbeat: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def has(self, capability: str) -> bool:
        return capability in self.capabilities


class ResourceManager:
    """Thread-safe resource manager with heartbeat reaper."""

    def __init__(self, path: str = "research.sqlite"):
        self.path = path
        is_mem = path == ":memory:"
        if not is_mem:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(RESOURCE_SCHEMA)
        self.db.commit()
        if not is_mem:
            ensure_secure_storage(path, fix=True)
        self._lock = threading.RLock()
        self._reaper: Optional[threading.Thread] = None
        self._stop_reaper = threading.Event()

    # -- registration

    def register(self, kind: str, name: str, capabilities: Optional[List[str]] = None,
                 owner: str = "", config: Optional[dict] = None,
                 metadata: Optional[dict] = None) -> LabResource:
        res = LabResource(
            id=f"res-{uuid.uuid4().hex[:8]}",
            kind=kind, name=name,
            capabilities=capabilities or [],
            health="ok", available=True,
            owner=owner, config=config or {},
            metadata=metadata or {},
        )
        with self._lock, self.db:
            self.db.execute(
                "INSERT INTO lab_resources VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (res.id, res.kind, res.name, json.dumps(res.capabilities),
                 res.health, int(res.available), res.allocated_to, res.owner,
                 json.dumps(res.config), res.last_heartbeat, res.created_at,
                 json.dumps(res.metadata)))
        log.info("resource %s registered: %s/%s caps=%s", res.id, kind, name, res.capabilities)
        return res

    def get(self, res_id: str) -> Optional[LabResource]:
        row = self.db.execute("SELECT * FROM lab_resources WHERE id=?", (res_id,)).fetchone()
        return self._row_to_res(row) if row else None

    def list(self, kind: str = "", available: Optional[bool] = None) -> List[LabResource]:
        conds = []
        args: List[Any] = []
        if kind:
            conds.append("kind=?")
            args.append(kind)
        if available is not None:
            conds.append("available=?")
            args.append(int(available))
        where = "WHERE " + " AND ".join(conds) if conds else ""
        rows = self.db.execute(f"SELECT * FROM lab_resources {where} ORDER BY created_at", args).fetchall()
        return [self._row_to_res(r) for r in rows]

    def heartbeat(self, res_id: str, health: str = "ok") -> bool:
        with self._lock, self.db:
            cur = self.db.execute("UPDATE lab_resources SET last_heartbeat=?, health=? WHERE id=?",
                                  (time.time(), health, res_id))
            return cur.rowcount > 0

    def update_health(self, res_id: str, health: str) -> bool:
        return self.heartbeat(res_id, health)

    # -- allocation

    def allocate(self, resource_id: str, experiment_id: str, run_id: str,
                 lease_s: float = DEFAULT_LEASE_S, reason: str = "") -> Optional[str]:
        """Allocate an available resource; returns token or None if unavailable."""
        with self._lock:
            res = self.get(resource_id)
            if not res:
                log.warning("allocate: unknown resource %s", resource_id)
                return None
            if not res.available or res.allocated_to:
                log.warning("allocate: resource %s busy (allocated_to=%s)", resource_id, res.allocated_to)
                return None
            token = f"alloc-{uuid.uuid4().hex[:8]}"
            now = time.time()
            with self.db:
                self.db.execute("UPDATE lab_resources SET available=0, allocated_to=?, last_heartbeat=? WHERE id=?",
                                (run_id, now, resource_id))
                self.db.execute("INSERT INTO allocations VALUES(?,?,?,?,?,?,?,?)",
                                (token, resource_id, experiment_id, run_id, now, now + lease_s, None, reason))
            log.info("resource %s allocated to %s (token %s, lease %.0fs)", resource_id, run_id, token, lease_s)
            return token

    def release(self, token: str) -> bool:
        with self._lock:
            row = self.db.execute("SELECT * FROM allocations WHERE token=?", (token,)).fetchone()
            if not row or row["released_at"]:
                return False
            with self.db:
                self.db.execute("UPDATE allocations SET released_at=? WHERE token=?", (time.time(), token))
                self.db.execute("UPDATE lab_resources SET available=1, allocated_to='' WHERE id=?", (row["resource_id"],))
            log.info("allocation %s released (resource %s)", token, row["resource_id"])
            return True

    def release_by_run(self, run_id: str) -> int:
        """Release all allocations for a run (e.g. on experiment failure/timeout)."""
        rows = self.db.execute("SELECT token FROM allocations WHERE run_id=? AND released_at IS NULL", (run_id,)).fetchall()
        n = 0
        for r in rows:
            if self.release(r["token"]):
                n += 1
        return n

    def allocations(self, run_id: str = "") -> List[dict]:
        if run_id:
            rows = self.db.execute("SELECT * FROM allocations WHERE run_id=? ORDER BY allocated_at", (run_id,)).fetchall()
        else:
            rows = self.db.execute("SELECT * FROM allocations ORDER BY allocated_at DESC LIMIT 100").fetchall()
        return [dict(r) for r in rows]

    # -- orphan reaper

    def reap_orphans(self) -> int:
        """Release allocations whose resource heartbeat is stale or lease expired."""
        now = time.time()
        stale = now - HEARTBEAT_TIMEOUT_S
        rows = self.db.execute(
            "SELECT a.token, a.resource_id, r.last_heartbeat, a.expires_at FROM allocations a "
            "JOIN lab_resources r ON a.resource_id=r.id WHERE a.released_at IS NULL").fetchall()
        n = 0
        for r in rows:
            if r["last_heartbeat"] < stale or (r["expires_at"] and now > r["expires_at"]):
                if self.release(r["token"]):
                    n += 1
                    log.warning("reaped orphan allocation %s (resource %s stale)", r["token"], r["resource_id"])
        return n

    def start_reaper(self, interval_s: float = 30.0) -> None:
        if self._reaper and self._reaper.is_alive():
            return
        self._stop_reaper.clear()

        def _loop():
            while not self._stop_reaper.wait(interval_s):
                try:
                    self.reap_orphans()
                except Exception as exc:
                    log.warning("reaper error: %s", exc)

        self._reaper = threading.Thread(target=_loop, name="resource-reaper", daemon=True)
        self._reaper.start()
        log.info("resource reaper started (interval %.0fs, timeout %.0fs)", interval_s, HEARTBEAT_TIMEOUT_S)

    def stop_reaper(self) -> None:
        self._stop_reaper.set()
        if self._reaper:
            self._reaper.join(timeout=1.0)

    def _row_to_res(self, row: sqlite3.Row) -> LabResource:
        return LabResource(
            id=row["id"], kind=row["kind"], name=row["name"],
            capabilities=json.loads(row["capabilities"] or "[]"),
            health=row["health"] or "unknown",
            available=bool(row["available"]),
            allocated_to=row["allocated_to"] or "",
            owner=row["owner"] or "",
            config=json.loads(row["config"] or "{}"),
            last_heartbeat=row["last_heartbeat"] or 0,
            created_at=row["created_at"] or 0,
            metadata=json.loads(row["metadata"] or "{}"),
        )

    def close(self):
        self.stop_reaper()
        self.db.commit()
        self.db.close()
