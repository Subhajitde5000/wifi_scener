"""Evidence & Artifact Management — §28 + §34 (Audit/Provenance).

Every artifact has an ID, experiment/run linkage, type, checksum,
provenance and retention state. Evidence kinds include pcap, packet refs,
decoded frames, IDS events, logs, measurements, datasets, detector outputs.

The store is append-only; normal users cannot silently rewrite history
(§34). Mutations are versioned and the original row is retained.

Retention states: hot | warm | cold | expired (purged by background job).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..privacy import ensure_secure_storage
from ..util import log

EVIDENCE_SCHEMA = """
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS evidence(
  id TEXT PRIMARY KEY,
  experiment_id TEXT,
  run_id TEXT,
  project_id TEXT,
  kind TEXT,            -- pcap|packet|frame|ids-event|log|measurement|dataset|detector-output|screenshot
  title TEXT,
  path TEXT,
  sha256 TEXT,
  provenance TEXT,      -- LIVE/CAPTURED/REPLAYED/SIMULATED/SYNTHETIC/DERIVED
  created_at REAL,
  creator TEXT,
  size_bytes INTEGER,
  retention TEXT DEFAULT 'hot',
  metadata TEXT,        -- JSON
  superseded_by TEXT
);
CREATE TABLE IF NOT EXISTS evidence_audit(
  id TEXT PRIMARY KEY, evidence_id TEXT, action TEXT, actor TEXT, ts REAL, detail TEXT,
  FOREIGN KEY(evidence_id) REFERENCES evidence(id)
);
CREATE INDEX IF NOT EXISTS idx_ev_run ON evidence(run_id);
CREATE INDEX IF NOT EXISTS idx_ev_exp ON evidence(experiment_id);
CREATE INDEX IF NOT EXISTS idx_ev_proj ON evidence(project_id);
CREATE INDEX IF NOT EXISTS idx_ev_kind ON evidence(kind);
"""


def _file_hash(path: str) -> tuple[str, int]:
    if not path or not os.path.exists(path):
        return "", 0
    h = hashlib.sha256()
    size = 0
    try:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for fn in sorted(files):
                    fp = os.path.join(root, fn)
                    h.update(fn.encode())
                    try:
                        with open(fp, "rb") as fh:
                            for chunk in iter(lambda: fh.read(8192), b""):
                                h.update(chunk)
                                size += len(chunk)
                    except OSError:
                        continue
            return h.hexdigest()[:16], size
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest()[:16], size
    except OSError:
        return "", 0


@dataclass
class Evidence:
    id: str
    experiment_id: str = ""
    run_id: str = ""
    project_id: str = ""
    kind: str = "artifact"
    title: str = ""
    path: str = ""
    sha256: str = ""
    provenance: str = "SYNTHETIC"
    created_at: float = field(default_factory=time.time)
    creator: str = ""
    size_bytes: int = 0
    retention: str = "hot"
    metadata: Dict[str, Any] = field(default_factory=dict)
    superseded_by: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceStore:
    """Append-only evidence ledger."""

    def __init__(self, path: str = "research.sqlite"):
        self.path = path
        is_mem = path == ":memory:"
        if not is_mem:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(EVIDENCE_SCHEMA)
        self.db.commit()
        if not is_mem:
            ensure_secure_storage(path, fix=True)

    def add(self, kind: str, title: str, path: str = "", provenance: str = "SYNTHETIC",
            experiment_id: str = "", run_id: str = "", project_id: str = "",
            creator: str = "", metadata: Optional[dict] = None) -> Evidence:
        sha, size = _file_hash(path)
        ev = Evidence(
            id=f"ev-{uuid.uuid4().hex[:8]}",
            experiment_id=experiment_id, run_id=run_id, project_id=project_id,
            kind=kind, title=title, path=path, sha256=sha,
            provenance=provenance, creator=creator, size_bytes=size,
            metadata=metadata or {},
        )
        with self.db:
            self.db.execute(
                """INSERT INTO evidence
                   (id,experiment_id,run_id,project_id,kind,title,path,sha256,provenance,created_at,creator,size_bytes,retention,metadata,superseded_by)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ev.id, ev.experiment_id, ev.run_id, ev.project_id, ev.kind, ev.title, ev.path, ev.sha256,
                 ev.provenance, ev.created_at, ev.creator, ev.size_bytes, ev.retention, json.dumps(ev.metadata), ev.superseded_by))
            self.db.execute("INSERT INTO evidence_audit VALUES(?,?,?,?,?,?)",
                            (f"ea-{uuid.uuid4().hex[:8]}", ev.id, "created", creator or "system", time.time(), json.dumps({"provenance": provenance, "sha256": sha})))
        log.info("evidence %s added: %s/%s [%s] %s", ev.id, kind, title, provenance, path or "")
        return ev

    def get(self, ev_id: str) -> Optional[Evidence]:
        row = self.db.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
        return self._row_to_ev(row) if row else None

    def list(self, run_id: str = "", experiment_id: str = "", project_id: str = "", kind: str = "") -> List[Evidence]:
        conds = []
        args: List[Any] = []
        if run_id:
            conds.append("run_id=?")
            args.append(run_id)
        if experiment_id:
            conds.append("experiment_id=?")
            args.append(experiment_id)
        if project_id:
            conds.append("project_id=?")
            args.append(project_id)
        if kind:
            conds.append("kind=?")
            args.append(kind)
        where = "WHERE " + " AND ".join(conds) if conds else ""
        rows = self.db.execute(f"SELECT * FROM evidence {where} ORDER BY created_at", args).fetchall()
        return [self._row_to_ev(r) for r in rows]

    def verify(self, ev_id: str) -> bool:
        ev = self.get(ev_id)
        if not ev or not ev.path:
            return False
        sha, _ = _file_hash(ev.path)
        return sha == ev.sha256

    def supersede(self, ev_id: str, new_path: str, actor: str = "system") -> Optional[Evidence]:
        old = self.get(ev_id)
        if not old:
            return None
        new = self.add(kind=old.kind, title=old.title, path=new_path, provenance=old.provenance,
                       experiment_id=old.experiment_id, run_id=old.run_id, project_id=old.project_id,
                       creator=actor, metadata={**old.metadata, "supersedes": ev_id})
        with self.db:
            self.db.execute("UPDATE evidence SET superseded_by=?, retention=? WHERE id=?", (new.id, "superseded", ev_id))
            self.db.execute("INSERT INTO evidence_audit VALUES(?,?,?,?,?,?)",
                            (f"ea-{uuid.uuid4().hex[:8]}", ev_id, "superseded", actor, time.time(), json.dumps({"new_id": new.id})))
        log.info("evidence %s superseded by %s", ev_id, new.id)
        return new

    def audit_trail(self, ev_id: str) -> List[dict]:
        rows = self.db.execute("SELECT * FROM evidence_audit WHERE evidence_id=? ORDER BY ts", (ev_id,)).fetchall()
        return [dict(r) for r in rows]

    def set_retention(self, ev_id: str, retention: str, actor: str = "system") -> bool:
        with self.db:
            cur = self.db.execute("UPDATE evidence SET retention=? WHERE id=?", (retention, ev_id))
            if cur.rowcount:
                self.db.execute("INSERT INTO evidence_audit VALUES(?,?,?,?,?,?)",
                                (f"ea-{uuid.uuid4().hex[:8]}", ev_id, f"retention->{retention}", actor, time.time(), "{}"))
            return cur.rowcount > 0

    def _row_to_ev(self, row: sqlite3.Row) -> Evidence:
        return Evidence(
            id=row["id"], experiment_id=row["experiment_id"] or "", run_id=row["run_id"] or "",
            project_id=row["project_id"] or "", kind=row["kind"] or "artifact",
            title=row["title"] or "", path=row["path"] or "", sha256=row["sha256"] or "",
            provenance=row["provenance"] or "SYNTHETIC", created_at=row["created_at"] or 0,
            creator=row["creator"] or "", size_bytes=row["size_bytes"] or 0,
            retention=row["retention"] or "hot",
            metadata=json.loads(row["metadata"] or "{}"),
            superseded_by=row["superseded_by"] or "",
        )

    def close(self):
        self.db.commit()
        self.db.close()
