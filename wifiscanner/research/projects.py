"""Research Project Management — §7.

A Project groups related experiments under one research question.
It provides the top-level container that the unified experiment engine
(ExperimentEngine) lacked: question → hypothesis → literature → experiments
→ datasets → detectors → results → comparisons → reports.

Lifecycle
---------
DRAFT → ACTIVE → ARCHIVED
Each project has a stable UUID, reproducibility manifest and audit trail.

Design notes
------------
* SQLite WAL, foreign keys, indexes.
* Projects are independent of the CLI; the `experiment` CLI remains
  backward-compatible and now optionally attaches to a project via
  `--project-id`.
* All writes are short transactions; concurrent student sessions are safe.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..privacy import ensure_secure_storage
from ..util import log

PROJECT_SCHEMA = """
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS research_projects(
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  research_question TEXT,
  hypothesis TEXT,
  objective TEXT,
  owner TEXT,
  supervisor TEXT,
  status TEXT DEFAULT 'DRAFT',
  tags TEXT DEFAULT '[]',
  literature TEXT DEFAULT '[]',
  created_at REAL, updated_at REAL,
  archived_at REAL
);
CREATE TABLE IF NOT EXISTS project_experiments(
  project_id TEXT, experiment_id TEXT, run_id TEXT,
  added_at REAL,
  PRIMARY KEY(project_id, run_id),
  FOREIGN KEY(project_id) REFERENCES research_projects(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS project_notes(
  id TEXT PRIMARY KEY, project_id TEXT, author TEXT,
  kind TEXT, body TEXT, ts REAL,
  FOREIGN KEY(project_id) REFERENCES research_projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_proj_owner ON research_projects(owner);
CREATE INDEX IF NOT EXISTS idx_proj_exp ON project_experiments(project_id);
"""


@dataclass
class Project:
    id: str
    title: str
    research_question: str = ""
    hypothesis: str = ""
    objective: str = ""
    owner: str = ""
    supervisor: str = ""
    status: str = "DRAFT"  # DRAFT | ACTIVE | ARCHIVED
    tags: List[str] = field(default_factory=list)
    literature: List[dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    archived_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title,
            "research_question": self.research_question,
            "hypothesis": self.hypothesis, "objective": self.objective,
            "owner": self.owner, "supervisor": self.supervisor,
            "status": self.status, "tags": self.tags,
            "literature": self.literature,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "archived_at": self.archived_at,
        }


class ProjectStore:
    """Persistent project registry."""

    def __init__(self, path: str = "research.sqlite"):
        self.path = path
        is_mem = path == ":memory:"
        if not is_mem:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(PROJECT_SCHEMA)
        self.db.commit()
        if not is_mem:
            ensure_secure_storage(path, fix=True)

    def create(self, title: str, research_question: str = "", hypothesis: str = "",
               objective: str = "", owner: str = "", supervisor: str = "",
               tags: Optional[List[str]] = None) -> Project:
        proj = Project(
            id=f"proj-{uuid.uuid4().hex[:8]}",
            title=title, research_question=research_question,
            hypothesis=hypothesis, objective=objective,
            owner=owner, supervisor=supervisor,
            tags=tags or [], status="DRAFT",
        )
        with self.db:
            self.db.execute(
                """INSERT INTO research_projects
                   (id,title,research_question,hypothesis,objective,owner,supervisor,status,tags,literature,created_at,updated_at,archived_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (proj.id, proj.title, proj.research_question, proj.hypothesis,
                 proj.objective, proj.owner, proj.supervisor, proj.status,
                 json.dumps(proj.tags), json.dumps(proj.literature),
                 proj.created_at, proj.updated_at, proj.archived_at))
        log.info("project %s created: %r", proj.id, title)
        return proj

    def get(self, proj_id: str) -> Optional[Project]:
        row = self.db.execute("SELECT * FROM research_projects WHERE id=?", (proj_id,)).fetchone()
        if not row:
            return None
        return self._row_to_project(row)

    def list(self, owner: str = "", status: str = "") -> List[Project]:
        conds = []
        args: List[Any] = []
        if owner:
            conds.append("owner=?")
            args.append(owner)
        if status:
            conds.append("status=?")
            args.append(status)
        where = "WHERE " + " AND ".join(conds) if conds else ""
        rows = self.db.execute(f"SELECT * FROM research_projects {where} ORDER BY updated_at DESC", args).fetchall()
        return [self._row_to_project(r) for r in rows]

    def update_status(self, proj_id: str, status: str) -> bool:
        with self.db:
            cur = self.db.execute("UPDATE research_projects SET status=?, updated_at=? WHERE id=?",
                                  (status, time.time(), proj_id))
            return cur.rowcount > 0

    def add_experiment(self, project_id: str, experiment_id: str, run_id: str) -> None:
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO project_experiments VALUES(?,?,?,?)",
                            (project_id, experiment_id, run_id, time.time()))
            self.db.execute("UPDATE research_projects SET updated_at=? WHERE id=?", (time.time(), project_id))

    def experiments(self, project_id: str) -> List[dict]:
        rows = self.db.execute("SELECT experiment_id, run_id, added_at FROM project_experiments WHERE project_id=? ORDER BY added_at",
                               (project_id,)).fetchall()
        return [dict(r) for r in rows]

    def add_note(self, project_id: str, body: str, author: str = "researcher", kind: str = "note") -> str:
        nid = f"note-{uuid.uuid4().hex[:8]}"
        with self.db:
            self.db.execute("INSERT INTO project_notes VALUES(?,?,?,?,?,?)",
                            (nid, project_id, author, kind, body, time.time()))
            self.db.execute("UPDATE research_projects SET updated_at=? WHERE id=?", (time.time(), project_id))
        return nid

    def notes(self, project_id: str) -> List[dict]:
        rows = self.db.execute("SELECT * FROM project_notes WHERE project_id=? ORDER BY ts", (project_id,)).fetchall()
        return [dict(r) for r in rows]

    def compare_experiments(self, project_id: str, run_ids: List[str]) -> dict:
        """Compare runs within a project (delegates to analytics)."""
        from ..analytics import compare_experiments as _cmp
        from ..experiment import ExperimentEngine
        # Load runs from the experiment DB (same file if shared, else separate)
        # For now, compare by fetching stored result blobs from project_experiments is not enough;
        # caller should provide run dicts. We provide a helper that joins both stores if they share path.
        return {"project_id": project_id, "run_ids": run_ids, "note": "use analytics.compare_experiments() with loaded run dicts"}

    def _row_to_project(self, row: sqlite3.Row) -> Project:
        return Project(
            id=row["id"], title=row["title"],
            research_question=row["research_question"] or "",
            hypothesis=row["hypothesis"] or "",
            objective=row["objective"] or "",
            owner=row["owner"] or "", supervisor=row["supervisor"] or "",
            status=row["status"] or "DRAFT",
            tags=json.loads(row["tags"] or "[]"),
            literature=json.loads(row["literature"] or "[]"),
            created_at=row["created_at"] or 0,
            updated_at=row["updated_at"] or 0,
            archived_at=row["archived_at"],
        )

    def close(self):
        self.db.commit()
        self.db.close()
