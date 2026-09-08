"""Dataset Platform — §9.

Every dataset has an ID, version, provenance, schema, checksum, size and
retention policy. The registry distinguishes LIVE / CAPTURED / REPLAYED /
SIMULATED / SYNTHETIC (§3) and never mixes them without explicit labeling.

Supported dataset kinds
-----------------------
* live      — direct sensor observation (Store observations)
* captured  — PCAP/PCAPNG held offline (traffic/wpalab)
* imported  — user-supplied PCAP/PCAPNG
* replayed  — replay of a captured dataset
* synthetic — lab-generated with ground truth (all 10 labs)
* derived   — feature dataset produced by FeaturePipeline
* labeled   — dataset with ground_truth labels attached

Each dataset row points at the artifact on disk (pcap/dir) and stores a
SHA-256 (first 16 hex) so reproducibility manifests can pin it.
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

DATASET_SCHEMA = """
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS datasets(
  id TEXT PRIMARY KEY,
  version TEXT,
  kind TEXT,            -- live|captured|imported|replayed|synthetic|derived|labeled
  provenance TEXT,      -- LIVE/CAPTURED/REPLAYED/SIMULATED/SYNTHETIC
  title TEXT,
  source TEXT,          -- file path or sensor id
  experiment_id TEXT,
  run_id TEXT,
  project_id TEXT,
  created_at REAL,
  creator TEXT,
  schema_json TEXT,     -- JSON description of columns/features
  labels TEXT,          -- JSON list of label names
  metadata TEXT,        -- JSON free-form
  sha256 TEXT,
  size_bytes INTEGER,
  retention_days REAL,
  artifact_path TEXT
);
CREATE TABLE IF NOT EXISTS dataset_versions(
  dataset_id TEXT, version TEXT, sha256 TEXT, artifact_path TEXT, ts REAL,
  PRIMARY KEY(dataset_id, version),
  FOREIGN KEY(dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ds_kind ON datasets(kind);
CREATE INDEX IF NOT EXISTS idx_ds_prov ON datasets(provenance);
CREATE INDEX IF NOT EXISTS idx_ds_exp ON datasets(experiment_id);
"""


def _sha256_file(path: str) -> str:
    if not path or not os.path.exists(path):
        return ""
    h = hashlib.sha256()
    try:
        if os.path.isdir(path):
            # hash manifest + sorted file list for directories
            for root, _, files in os.walk(path):
                for fn in sorted(files):
                    fp = os.path.join(root, fn)
                    h.update(fn.encode())
                    try:
                        with open(fp, "rb") as fh:
                            for chunk in iter(lambda: fh.read(8192), b""):
                                h.update(chunk)
                    except OSError:
                        continue
        else:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return ""


@dataclass
class Dataset:
    id: str
    version: str = "1.0.0"
    kind: str = "synthetic"
    provenance: str = "SYNTHETIC"
    title: str = ""
    source: str = ""
    experiment_id: str = ""
    run_id: str = ""
    project_id: str = ""
    created_at: float = field(default_factory=time.time)
    creator: str = ""
    schema: Dict[str, Any] = field(default_factory=dict)
    labels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    sha256: str = ""
    size_bytes: int = 0
    retention_days: float = 90.0
    artifact_path: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["created_at_h"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at))
        return d


class DatasetStore:
    """Versioned dataset registry."""

    def __init__(self, path: str = "research.sqlite"):
        self.path = path
        is_mem = path == ":memory:"
        if not is_mem:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(DATASET_SCHEMA)
        self.db.commit()
        if not is_mem:
            ensure_secure_storage(path, fix=True)

    def register(self, title: str, kind: str = "synthetic", provenance: str = "SYNTHETIC",
                 source: str = "", artifact_path: str = "", experiment_id: str = "",
                 run_id: str = "", project_id: str = "", creator: str = "",
                 schema: Optional[dict] = None, labels: Optional[List[str]] = None,
                 metadata: Optional[dict] = None, retention_days: float = 90.0) -> Dataset:
        artifact = artifact_path or source
        sha = _sha256_file(artifact)
        size = 0
        if artifact and os.path.exists(artifact):
            if os.path.isdir(artifact):
                size = sum(os.path.getsize(os.path.join(r, f))
                           for r, _, fs in os.walk(artifact) for f in fs)
            else:
                try:
                    size = os.path.getsize(artifact)
                except OSError:
                    size = 0
        ds = Dataset(
            id=f"ds-{uuid.uuid4().hex[:8]}",
            version="1.0.0", kind=kind, provenance=provenance,
            title=title, source=source, artifact_path=artifact,
            experiment_id=experiment_id, run_id=run_id, project_id=project_id,
            creator=creator, schema=schema or {}, labels=labels or [],
            metadata=metadata or {}, sha256=sha, size_bytes=size,
            retention_days=retention_days,
        )
        with self.db:
            self.db.execute(
                """INSERT INTO datasets
                   (id,version,kind,provenance,title,source,experiment_id,run_id,project_id,
                    created_at,creator,schema_json,labels,metadata,sha256,size_bytes,retention_days,artifact_path)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ds.id, ds.version, ds.kind, ds.provenance, ds.title, ds.source,
                 ds.experiment_id, ds.run_id, ds.project_id,
                 ds.created_at, ds.creator, json.dumps(ds.schema),
                 json.dumps(ds.labels), json.dumps(ds.metadata),
                 ds.sha256, ds.size_bytes, ds.retention_days, ds.artifact_path))
            self.db.execute("INSERT INTO dataset_versions VALUES(?,?,?, ?,?)",
                            (ds.id, ds.version, ds.sha256, ds.artifact_path, ds.created_at))
        log.info("dataset %s (%s) registered: %s [%s]", ds.id, ds.provenance, title, kind)
        return ds

    def bump_version(self, dataset_id: str, new_artifact: str) -> Optional[Dataset]:
        ds = self.get(dataset_id)
        if not ds:
            return None
        # semantic bump: 1.0.0 -> 1.0.1 -> 1.1.0 etc. simple patch bump
        parts = ds.version.split(".")
        try:
            parts[-1] = str(int(parts[-1]) + 1)
        except ValueError:
            parts.append("1")
        new_ver = ".".join(parts)
        sha = _sha256_file(new_artifact)
        size = os.path.getsize(new_artifact) if os.path.isfile(new_artifact) else 0
        with self.db:
            self.db.execute("UPDATE datasets SET version=?, sha256=?, artifact_path=?, size_bytes=?, created_at=? WHERE id=?",
                            (new_ver, sha, new_artifact, size, time.time(), dataset_id))
            self.db.execute("INSERT INTO dataset_versions VALUES(?,?,?, ?,?)",
                            (dataset_id, new_ver, sha, new_artifact, time.time()))
        ds.version = new_ver
        ds.sha256 = sha
        ds.artifact_path = new_artifact
        ds.size_bytes = size
        return ds

    def get(self, dataset_id: str) -> Optional[Dataset]:
        row = self.db.execute("SELECT * FROM datasets WHERE id=?", (dataset_id,)).fetchone()
        return self._row_to_ds(row) if row else None

    def list(self, kind: str = "", provenance: str = "", project_id: str = "") -> List[Dataset]:
        conds = []
        args: List[Any] = []
        if kind:
            conds.append("kind=?")
            args.append(kind)
        if provenance:
            conds.append("provenance=?")
            args.append(provenance)
        if project_id:
            conds.append("project_id=?")
            args.append(project_id)
        where = "WHERE " + " AND ".join(conds) if conds else ""
        rows = self.db.execute(f"SELECT * FROM datasets {where} ORDER BY created_at DESC", args).fetchall()
        return [self._row_to_ds(r) for r in rows]

    def versions(self, dataset_id: str) -> List[dict]:
        rows = self.db.execute("SELECT version, sha256, artifact_path, ts FROM dataset_versions WHERE dataset_id=? ORDER BY ts",
                               (dataset_id,)).fetchall()
        return [dict(r) for r in rows]

    def verify(self, dataset_id: str) -> bool:
        ds = self.get(dataset_id)
        if not ds or not ds.artifact_path:
            return False
        return _sha256_file(ds.artifact_path) == ds.sha256

    def _row_to_ds(self, row: sqlite3.Row) -> Dataset:
        return Dataset(
            id=row["id"], version=row["version"] or "1.0.0",
            kind=row["kind"] or "synthetic", provenance=row["provenance"] or "SYNTHETIC",
            title=row["title"] or "", source=row["source"] or "",
            experiment_id=row["experiment_id"] or "", run_id=row["run_id"] or "",
            project_id=row["project_id"] or "", created_at=row["created_at"] or 0,
            creator=row["creator"] or "",
            schema=json.loads(row["schema_json"] or "{}"),
            labels=json.loads(row["labels"] or "[]"),
            metadata=json.loads(row["metadata"] or "{}"),
            sha256=row["sha256"] or "", size_bytes=row["size_bytes"] or 0,
            retention_days=row["retention_days"] or 90,
            artifact_path=row["artifact_path"] or "",
        )

    def close(self):
        self.db.commit()
        self.db.close()
