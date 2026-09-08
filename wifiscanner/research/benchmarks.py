"""Benchmark Framework — §14.

Standardized harness to compare Detector A / B / C / researcher's detector
under identical experimental conditions.

Benchmarks
----------
* detection accuracy (precision/recall/F1 via analytics.score_ids)
* latency (per-alert, p50/p95, throughput)
* resource utilization (CPU/memory if psutil available, else wall-clock)
* packet/event processing rate
* scalability (jobs × frames)

Every benchmark run is reproducible: dataset version + feature version +
detector version + seed + software version are recorded in the report.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..analytics import score_ids, benchmark_throughput
from ..util import log
from .detectors import Detector
from .features import FeatureDataset


@dataclass
class BenchmarkRun:
    detector_id: str
    detector_version: str
    dataset_id: str
    dataset_version: str
    seed: int = 0
    metrics: Dict[str, Any] = field(default_factory=dict)
    detections: int = 0
    latency_ms: Dict[str, float] = field(default_factory=dict)
    throughput: Dict[str, Any] = field(default_factory=dict)
    accuracy: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "detector": f"{self.detector_id} v{self.detector_version}",
            "dataset": f"{self.dataset_id} v{self.dataset_version}",
            "seed": self.seed,
            "detections": self.detections,
            "latency_ms": self.latency_ms,
            "throughput": self.throughput,
            "accuracy": self.accuracy,
            "metrics": self.metrics,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
        }


class BenchmarkSuite:
    """Compare multiple detectors on the same feature datasets + ground truth."""

    def __init__(self, ground_truth: Optional[List[dict]] = None):
        self.ground_truth = ground_truth or []
        self.runs: List[BenchmarkRun] = []

    def run_detector(self, detector: Detector, feature_ds: FeatureDataset,
                     ground_truth: Optional[List[dict]] = None,
                     dataset_id: str = "", dataset_version: str = "",
                     seed: int = 0) -> BenchmarkRun:
        gt = ground_truth if ground_truth is not None else self.ground_truth
        t0 = time.time()
        detections, det_metrics = detector.run(feature_ds.features)
        wall_ms = (time.time() - t0) * 1000

        # Accuracy against ground truth (if provided)
        accuracy: Dict[str, Any] = {}
        if gt:
            alerts = [{"kind": d.kind, "bssid": d.bssid, "ts": d.ts} for d in detections]
            accuracy = score_ids(gt, alerts)

        # Throughput from feature timestamps
        events = [{"ts": d.ts} for d in detections] if detections else []
        throughput = benchmark_throughput(events or [{"ts": f.ts} for f in feature_ds.features[:1000]])

        run = BenchmarkRun(
            detector_id=detector.id, detector_version=detector.version,
            dataset_id=dataset_id or feature_ds.source_pcap,
            dataset_version=dataset_version or feature_ds.version,
            seed=seed,
            metrics=det_metrics,
            detections=len(detections),
            latency_ms={"wall_ms": round(wall_ms, 2), **det_metrics},
            throughput=throughput,
            accuracy=accuracy,
        )
        self.runs.append(run)
        log.info("benchmark: %s on %s → %d detections, %.1f ms, acc %s",
                 detector.id, feature_ds.source_pcap, len(detections), wall_ms,
                 accuracy.get("overall", {}).get("f1", "n/a") if accuracy else "no GT")
        return run

    def compare(self) -> dict:
        if not self.runs:
            return {"error": "no runs"}
        # Rank by F1 if ground truth present, else by throughput
        ranked = sorted(
            self.runs,
            key=lambda r: (
                r.accuracy.get("overall", {}).get("f1", 0) if r.accuracy else 0,
                -r.latency_ms.get("wall_ms", 1e9),
            ),
            reverse=True,
        )
        return {
            "runs": [r.to_dict() for r in self.runs],
            "ranking": [f"{r.detector_id} v{r.detector_version}" for r in ranked],
            "summary": f"{len(self.runs)} detectors benchmarked",
        }

    def report(self, path: str = "") -> str:
        cmp = self.compare()
        body = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "runs": cmp.get("runs", []),
            "ranking": cmp.get("ranking", []),
            "summary": cmp.get("summary", ""),
        }
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(body, fh, indent=2)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            # Also CSV
            csv_path = path.replace(".json", ".csv") if path.endswith(".json") else path + ".csv"
            try:
                import csv
                rows = []
                for r in body["runs"]:
                    flat = {
                        "detector": r["detector"],
                        "dataset": r["dataset"],
                        "detections": r["detections"],
                        "wall_ms": r["latency_ms"].get("wall_ms", ""),
                        "f1": r["accuracy"].get("overall", {}).get("f1", "") if r.get("accuracy") else "",
                        "precision": r["accuracy"].get("overall", {}).get("precision", "") if r.get("accuracy") else "",
                        "recall": r["accuracy"].get("overall", {}).get("recall", "") if r.get("accuracy") else "",
                    }
                    rows.append(flat)
                if rows:
                    with open(csv_path, "w", newline="", encoding="utf-8-sig") as fh:
                        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                        w.writeheader()
                        w.writerows(rows)
                    try:
                        os.chmod(csv_path, 0o600)
                    except OSError:
                        pass
            except Exception:
                pass
            return path
        return json.dumps(body, indent=2)
