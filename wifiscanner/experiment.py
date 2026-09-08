"""Research-grade Experiment Framework — unified lifecycle for every lab.

This module implements requirement §4 (Experiment Engine) and §8-§10
(Instructor/Student lifecycle) of the Advanced Cybersecurity Research Lab.

It provides a single, reusable abstraction that every existing lab
(wpa-lab, mac-lab, track-lab, stealth-lab, response-lab, scan-lab,
cred-lab, priv-lab, rf-lab, handshake-lab, lab) can be expressed as,
plus any future wireless, network or system experiment.

Design principles
-----------------
* Real data first — experiments distinguish LIVE / CAPTURED / REPLAYED /
  SIMULATED / SYNTHETIC (§3). The framework never presents simulated output
  as measurement; each artifact is tagged with its provenance.
* Modular — frontend / API / auth / resource-manager / monitoring /
  packet-processing / detection / event-pipeline / storage / analytics are
  separate; this engine only orchestrates lifecycle and persistence.
* Reproducibility — every run stores seed, config, software versions,
  dataset hash and timeline so a second run with identical inputs yields
  identical ground truth and scoring.
* Observability — every experiment emits an auditable timeline:
  START → CONFIG → LAB_EVENT → PACKET/EVIDENCE → DETECTION → ANALYSIS →
  RESPONSE → RESULT → RESET (§13).
* Safety separation — authorization (allowed targets, interfaces,
  student/instructor roles) is enforced by the lab layer; the engine
  itself is capability-agnostic and can be extended without weakening
  guardrails.

Usage
-----
>>> from wifiscanner.experiment import ExperimentEngine, ExperimentDef
>>> eng = ExperimentEngine(db="lab.sqlite")
>>> exp_id = eng.register(ExperimentDef(
...     id="exp-wpa-001", title="WPA2 MIC verification",
...     objective="Verify candidate passphrase against 4-way handshake MIC",
...     category="wireless/crypto", data_provenance="CAPTURED",
...     prerequisites=["pcap with handshake", "lab key material"]))
>>> run = eng.start(exp_id, config={"pcap": "lesson.pcap", "password": "lab-secret"})
>>> run.log_event("packet-evidence", {"frames": 42, "handshake": "M1-M4"})
>>> run.finish(result={"verdict": "accepted", "decrypted": 12})
>>> eng.score(exp_id, run.id, answers={"q1": "correct"})
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .util import log


# ------------------------------------------------------------------ enums

class Provenance(str, Enum):
    LIVE = "LIVE"               # live RF / host telemetry
    CAPTURED = "CAPTURED"       # pcap / log captured in lab, held offline
    REPLAYED = "REPLAYED"       # replay of captured data
    SIMULATED = "SIMULATED"     # deterministic simulation (e.g. scan-lab, rf-lab)
    SYNTHETIC = "SYNTHETIC"     # generated dataset with ground truth


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RESET = "reset"


class Role(str, Enum):
    STUDENT = "student"
    INSTRUCTOR = "instructor"
    ADMIN = "admin"


# ----------------------------------------------------------------- models

@dataclass
class ExperimentDef:
    """Static definition of an experiment (the worksheet)."""
    id: str
    title: str
    objective: str
    category: str = "general"          # wireless/crypto/network/system/privacy/...
    data_provenance: str = Provenance.SYNTHETIC
    prerequisites: List[str] = field(default_factory=list)
    target_resources: List[str] = field(default_factory=list)
    parameters_schema: Dict[str, Any] = field(default_factory=dict)
    default_config: Dict[str, Any] = field(default_factory=dict)
    instructor_notes: str = ""
    max_duration_s: float = 3600
    version: str = "1.0.0"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["data_provenance"] = str(self.data_provenance)
        return d


@dataclass
class TimelineEvent:
    ts: float
    phase: str          # START / CONFIG / LAB_EVENT / PACKET / DETECTION / ANALYSIS / RESPONSE / RESULT / RESET
    kind: str
    detail: str
    evidence_ref: str = ""
    actor: str = "system"

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
            "phase": self.phase, "kind": self.kind,
            "detail": self.detail, "evidence": self.evidence_ref, "actor": self.actor,
        }


@dataclass
class ExperimentRun:
    """One execution instance of an experiment."""
    id: str
    experiment_id: str
    status: str = RunStatus.PENDING
    config: Dict[str, Any] = field(default_factory=dict)
    seed: Optional[int] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    timeline: List[TimelineEvent] = field(default_factory=list)
    observations: List[dict] = field(default_factory=list)
    artifacts: List[dict] = field(default_factory=list)
    result: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)
    reproducibility_hash: str = ""
    student_id: str = ""
    score: Optional[dict] = None

    def log_event(self, phase: str, detail: Any, kind: str = "event",
                  evidence_ref: str = "", actor: str = "system") -> TimelineEvent:
        ev = TimelineEvent(time.time(), phase.upper(), kind,
                           json.dumps(detail) if isinstance(detail, dict) else str(detail),
                           evidence_ref, actor)
        self.timeline.append(ev)
        self.logs.append(f"[{ev.phase}] {ev.detail}")
        return ev

    def add_observation(self, obs: dict) -> None:
        obs = dict(obs)
        obs.setdefault("ts", time.time())
        self.observations.append(obs)
        self.log_event("LAB_EVENT", obs, kind="observation")

    def add_artifact(self, path: str, kind: str = "file", provenance: str = Provenance.SYNTHETIC,
                     sha256: str = "") -> None:
        entry: dict = {
            "path": path, "kind": kind, "provenance": str(provenance),
            "sha256": sha256 or _file_hash(path),
            "ts": time.time(),
        }
        self.artifacts.append(entry)
        self.log_event("PACKET", {"artifact": path, "kind": kind, "provenance": str(provenance)},
                       kind="artifact", evidence_ref=path)

    def finish(self, result: dict, status: str = RunStatus.COMPLETED) -> None:
        self.result = dict(result)
        self.status = status
        self.finished_at = time.time()
        self.log_event("RESULT", result, kind="result")
        self.reproducibility_hash = self._hash()

    def fail(self, error: str) -> None:
        self.status = RunStatus.FAILED
        self.finished_at = time.time()
        self.log_event("RESULT", {"error": error}, kind="failure")

    def reset(self) -> None:
        self.status = RunStatus.RESET
        self.log_event("RESET", {"previous_result": self.result}, kind="reset")
        self.timeline.clear()
        self.observations.clear()
        self.artifacts.clear()
        self.result.clear()

    def _hash(self) -> str:
        h = hashlib.sha256()
        h.update(json.dumps(self.config, sort_keys=True).encode())
        h.update(str(self.seed or 0).encode())
        h.update(self.experiment_id.encode())
        return h.hexdigest()[:16]

    @property
    def duration_s(self) -> float:
        if self.finished_at:
            return round(self.finished_at - self.started_at, 2)
        return round(time.time() - self.started_at, 2)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "experiment_id": self.experiment_id,
            "status": self.status, "config": self.config, "seed": self.seed,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "duration_s": self.duration_s,
            "timeline": [e.to_dict() for e in self.timeline],
            "observations": self.observations,
            "artifacts": self.artifacts,
            "result": self.result, "logs": self.logs,
            "reproducibility_hash": self.reproducibility_hash,
            "student_id": self.student_id, "score": self.score,
        }


def _file_hash(path: str) -> str:
    if not path or not os.path.exists(path):
        return ""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return ""


# --------------------------------------------------------------- engine

EXPERIMENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS experiments(
  id TEXT PRIMARY KEY,
  title TEXT, objective TEXT, category TEXT,
  provenance TEXT, prerequisites TEXT,
  target_resources TEXT, parameters_schema TEXT,
  default_config TEXT, instructor_notes TEXT,
  max_duration_s REAL, version TEXT,
  created_at REAL
);
CREATE TABLE IF NOT EXISTS runs(
  id TEXT PRIMARY KEY,
  experiment_id TEXT, status TEXT,
  config TEXT, seed INTEGER,
  started_at REAL, finished_at REAL,
  timeline TEXT, observations TEXT,
  artifacts TEXT, result TEXT,
  logs TEXT, reproducibility_hash TEXT,
  student_id TEXT, score TEXT,
  FOREIGN KEY(experiment_id) REFERENCES experiments(id)
);
CREATE TABLE IF NOT EXISTS analytics(
  run_id TEXT, metric TEXT, value REAL, meta TEXT,
  ts REAL
);
CREATE INDEX IF NOT EXISTS idx_runs_exp ON runs(experiment_id, started_at);
CREATE INDEX IF NOT EXISTS idx_analytics_run ON analytics(run_id);
"""


class ExperimentEngine:
    """Persistent experiment registry + lifecycle manager.

    Backed by SQLite (WAL mode). Safe for concurrent student sessions:
    each run is an independent row; writes are short transactions.
    """

    def __init__(self, db: str = ":memory:"):
        self.db_path = db
        os.makedirs(os.path.dirname(os.path.abspath(db)) or ".", exist_ok=True) if db != ":memory:" else None
        self.db = sqlite3.connect(db, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        self.db.executescript(EXPERIMENT_SCHEMA)
        self.db.commit()
        self._mem_runs: Dict[str, ExperimentRun] = {}

    # ---- definitions

    def register(self, definition: ExperimentDef) -> str:
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO experiments VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (definition.id, definition.title, definition.objective,
                 definition.category, str(definition.data_provenance),
                 json.dumps(definition.prerequisites),
                 json.dumps(definition.target_resources),
                 json.dumps(definition.parameters_schema),
                 json.dumps(definition.default_config),
                 definition.instructor_notes,
                 definition.max_duration_s, definition.version,
                 time.time()),
            )
        log.info("experiment registered: %s (%s)", definition.id, definition.title)
        return definition.id

    def get_definition(self, exp_id: str) -> Optional[ExperimentDef]:
        row = self.db.execute("SELECT * FROM experiments WHERE id=?", (exp_id,)).fetchone()
        if not row:
            return None
        return ExperimentDef(
            id=row["id"], title=row["title"], objective=row["objective"],
            category=row["category"], data_provenance=row["provenance"],
            prerequisites=json.loads(row["prerequisites"] or "[]"),
            target_resources=json.loads(row["target_resources"] or "[]"),
            parameters_schema=json.loads(row["parameters_schema"] or "{}"),
            default_config=json.loads(row["default_config"] or "{}"),
            instructor_notes=row["instructor_notes"] or "",
            max_duration_s=row["max_duration_s"] or 3600,
            version=row["version"] or "1.0.0",
        )

    def list_definitions(self) -> List[ExperimentDef]:
        rows = self.db.execute("SELECT id FROM experiments ORDER BY category, id").fetchall()
        return [self.get_definition(r["id"]) for r in rows]  # type: ignore

    # ---- runs

    def start(self, experiment_id: str, config: Optional[dict] = None,
              seed: Optional[int] = None, student_id: str = "") -> ExperimentRun:
        definition = self.get_definition(experiment_id)
        if not definition:
            raise ValueError(f"unknown experiment {experiment_id!r}")
        merged = dict(definition.default_config)
        if config:
            merged.update(config)
        run_id = f"{experiment_id}-{uuid.uuid4().hex[:8]}"
        run = ExperimentRun(
            id=run_id, experiment_id=experiment_id,
            status=RunStatus.RUNNING, config=merged,
            seed=seed if seed is not None else secrets.randbits(31),
            student_id=student_id,
        )
        run.log_event("START", {"experiment": experiment_id, "config": merged, "seed": run.seed},
                      kind="start")
        run.log_event("CONFIG", merged, kind="configuration")
        self._persist_run(run)
        self._mem_runs[run_id] = run
        return run

    def finish(self, run: ExperimentRun, result: dict,
               status: str = RunStatus.COMPLETED) -> ExperimentRun:
        run.finish(result, status)
        self._persist_run(run)
        return run

    def fail(self, run: ExperimentRun, error: str) -> ExperimentRun:
        run.fail(error)
        self._persist_run(run)
        return run

    def reset(self, run_id: str) -> Optional[ExperimentRun]:
        run = self.get_run(run_id)
        if not run:
            return None
        run.reset()
        self._persist_run(run)
        return run

    def get_run(self, run_id: str) -> Optional[ExperimentRun]:
        if run_id in self._mem_runs:
            return self._mem_runs[run_id]
        row = self.db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return None
        return self._row_to_run(row)

    def list_runs(self, experiment_id: str = "", limit: int = 100) -> List[ExperimentRun]:
        if experiment_id:
            rows = self.db.execute(
                "SELECT * FROM runs WHERE experiment_id=? ORDER BY started_at DESC LIMIT ?",
                (experiment_id, limit)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_run(r) for r in rows]

    def score(self, experiment_id: str, run_id: str, answers: dict,
              rubric: Optional[dict] = None) -> dict:
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"unknown run {run_id!r}")
        # Generic rubric: compare answers to expected keys if provided,
        # otherwise score based on result completeness.
        total = 0
        possible = 100
        feedback: List[str] = []
        if rubric:
            for q, expected in rubric.items():
                total_q = 100 / len(rubric)
                if answers.get(q) == expected:
                    total += total_q
                    feedback.append(f"✓ {q}: correct")
                else:
                    feedback.append(f"✗ {q}: expected {expected!r}, got {answers.get(q)!r}")
        else:
            # Heuristic: result present + timeline observed + artifacts
            if run.result:
                total += 40
                feedback.append("✓ result produced")
            if len(run.timeline) >= 3:
                feedback.append(f"✓ timeline observed ({len(run.timeline)} events)")
                total += 30
            if run.artifacts:
                feedback.append(f"✓ artifacts generated ({len(run.artifacts)})")
                total += 30
        score = {"score": round(total, 1), "possible": possible,
                 "points": round(total, 1), "feedback": feedback,
                 "run_id": run_id, "experiment_id": experiment_id}
        run.score = score
        self._persist_run(run)
        return score

    # ---- analytics helpers

    def record_metric(self, run_id: str, metric: str, value: float, meta: str = "") -> None:
        with self.db:
            self.db.execute("INSERT INTO analytics VALUES(?,?,?,?,?)",
                            (run_id, metric, float(value), meta, time.time()))

    def get_metrics(self, run_id: str) -> List[dict]:
        rows = self.db.execute("SELECT metric, value, meta, ts FROM analytics WHERE run_id=?",
                               (run_id,)).fetchall()
        return [dict(r) for r in rows]

    def compare_runs(self, run_ids: List[str]) -> dict:
        runs = [self.get_run(rid) for rid in run_ids if self.get_run(rid)]
        if not runs:
            return {"error": "no valid runs"}
        return {
            "runs": [r.to_dict() for r in runs if r],
            "metrics": {r.id: self.get_metrics(r.id) for r in runs if r},
            "comparison": {
                "durations": {r.id: r.duration_s for r in runs if r},
                "artifacts": {r.id: len(r.artifacts) for r in runs if r},
                "observations": {r.id: len(r.observations) for r in runs if r},
            }
        }

    # ---- persistence

    def _persist_run(self, run: ExperimentRun) -> None:
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run.id, run.experiment_id, run.status,
                 json.dumps(run.config), run.seed,
                 run.started_at, run.finished_at,
                 json.dumps([e.to_dict() for e in run.timeline]),
                 json.dumps(run.observations),
                 json.dumps(run.artifacts),
                 json.dumps(run.result),
                 json.dumps(run.logs),
                 run.reproducibility_hash,
                 run.student_id,
                 json.dumps(run.score) if run.score else ""),
            )

    def _row_to_run(self, row: sqlite3.Row) -> ExperimentRun:
        timeline_raw = json.loads(row["timeline"] or "[]")
        timeline = [TimelineEvent(
            ts=e.get("ts", 0), phase=e.get("phase", ""),
            kind=e.get("kind", ""), detail=e.get("detail", ""),
            evidence_ref=e.get("evidence", ""), actor=e.get("actor", "system"))
            for e in timeline_raw]
        return ExperimentRun(
            id=row["id"], experiment_id=row["experiment_id"],
            status=row["status"], config=json.loads(row["config"] or "{}"),
            seed=row["seed"], started_at=row["started_at"],
            finished_at=row["finished_at"],
            timeline=timeline,
            observations=json.loads(row["observations"] or "[]"),
            artifacts=json.loads(row["artifacts"] or "[]"),
            result=json.loads(row["result"] or "{}"),
            logs=json.loads(row["logs"] or "[]"),
            reproducibility_hash=row["reproducibility_hash"] or "",
            student_id=row["student_id"] or "",
            score=json.loads(row["score"]) if row["score"] else None,
        )

    def close(self) -> None:
        self.db.commit()
        self.db.close()


# ------------------------------------------------------------------
# Pre-registered experiment catalogue (extends existing labs)

CATALOGUE: List[ExperimentDef] = [
    ExperimentDef(
        id="wireless-survey-001", title="Passive RF Survey & Client Attribution",
        objective="Survey nearby APs and count associated clients without joining",
        category="wireless/survey", data_provenance=Provenance.LIVE,
        prerequisites=["wireless interface", "iw or nmcli"],
        target_resources=["wlan0", "sensor-grid"],
        parameters_schema={"duration": {"type": "float", "default": 60, "unit": "s"},
                           "channels": {"type": "list[int]", "default": "all"}},
        instructor_notes="Demonstrate To-DS/From-DS header attribution on encrypted traffic.",
    ),
    ExperimentDef(
        id="wireless-ids-001", title="Wireless IDS — Deauth & Harvest Detection",
        objective="Detect deauth floods and handshake-harvest chains",
        category="wireless/ids", data_provenance=Provenance.LIVE,
        prerequisites=["monitor-mode capture or pcap"],
        target_resources=["wlan0mon", "pcap"],
        instructor_notes="Feed synthetic attack pcap via ids-selftest; verify all 5 signatures fire.",
    ),
    ExperimentDef(
        id="crypto-wpa-001", title="WPA2 MIC Verification & Decryption",
        objective="Verify passphrase via MIC and decrypt CCMP/GCMP lab capture",
        category="wireless/crypto", data_provenance=Provenance.CAPTURED,
        prerequisites=["lab pcap with handshake", "lab passphrase/PMK"],
        target_resources=["lesson.pcap"],
        instructor_notes="Exercise 2: wrong key → MIC mismatch; Exercise 4: no handshake → no PTK.",
    ),
    ExperimentDef(
        id="privacy-mac-001", title="MAC Randomization Correlation",
        objective="Correlate rotated MACs using evidence engine",
        category="privacy/tracking", data_provenance=Provenance.SYNTHETIC,
        prerequisites=["synthetic probe dataset"],
        target_resources=["sensor-*.pcap"],
        instructor_notes="Twin trap: simultaneous presence is hard anti-evidence.",
    ),
    ExperimentDef(
        id="system-stealth-001", title="Stealth Implant Detection",
        objective="Detect concealed implant from host telemetry",
        category="system/monitoring", data_provenance=Provenance.SIMULATED,
        prerequisites=["4-day telemetry scenario"],
        target_resources=["lab-ws-07"],
        instructor_notes="Concealment 60pts > name-mimic 40: ps-vs-ss discrepancy is key.",
    ),
    ExperimentDef(
        id="network-scan-001", title="Scope-Controlled Network Scanning",
        objective="Scan virtual estate respecting authorization scope",
        category="network/scanning", data_provenance=Provenance.SIMULATED,
        prerequisites=["virtual estate inventory"],
        target_resources=["10.77.*"],
        instructor_notes="Sentinel refuses out-of-scope before probing; rate-limit shapes timing.",
    ),
    ExperimentDef(
        id="creds-tls-001", title="Cleartext vs TLS Credential Exposure",
        objective="Dissect six plaintext auth surfaces and prove TLS opacity",
        category="network/credentials", data_provenance=Provenance.CAPTURED,
        prerequisites=["lab capture with twin legs"],
        target_resources=["lesson.pcap"],
        instructor_notes="Six surfaces: Basic/Form/FTP/Telnet/SNMPv1/Cookie; TLS leg shows only SNI.",
    ),
]


def bootstrap_catalogue(engine: ExperimentEngine) -> int:
    n = 0
    for definition in CATALOGUE:
        engine.register(definition)
        n += 1
    return n
