"""Analytics & Research Metrics — detection accuracy, benchmarks, comparison.

Implements §5 (Research Features): configurable parameters, baselines,
ground truths, precision/recall, FP/FN analysis, latency, resource
utilization, experiment comparison, dataset export and visualization
helpers.

This module is purely analytical — it consumes outputs from experiments
(IDS alerts, pcap stats, correlation decisions, scan results) and
produces scored, explainable metrics that let PhD students answer WHY
a result occurred.
"""
from __future__ import annotations

import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class DetectionMetrics:
    """Standard confusion-matrix metrics for any detector."""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    latency_ms: List[float] = field(default_factory=list)

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        d = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def avg_latency_ms(self) -> float:
        return sum(self.latency_ms) / len(self.latency_ms) if self.latency_ms else 0

    @property
    def p95_latency_ms(self) -> float:
        if not self.latency_ms:
            return 0
        s = sorted(self.latency_ms)
        return s[int(len(s) * 0.95)]

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "p95_latency_ms": round(self.p95_latency_ms, 2),
        }


def score_ids(ground_truth: List[dict], alerts: List[dict],
              window_s: float = 10.0) -> Dict[str, Any]:
    """Score IDS alerts against ground-truth attack intervals.

    ground_truth: [{"kind": "deauth-flood", "bssid": "AA:..", "start": ts, "end": ts}, ...]
    alerts:       [{"kind": "deauth-flood", "bssid": "AA:..", "ts": ts}, ...]

    An alert is TP if it falls within [start - window, end + window] of a
    matching ground-truth interval; otherwise FP. Unmatched ground truth → FN.
    """
    matched: Set[int] = set()
    metrics: Dict[str, DetectionMetrics] = defaultdict(DetectionMetrics)
    overall = DetectionMetrics()

    for alert in alerts:
        ak, ab, ats = alert.get("kind", ""), (alert.get("bssid") or "").upper(), alert.get("ts", alert.get("time", 0))
        if isinstance(ats, str):
            try:
                ats = float(ats)
            except ValueError:
                ats = 0
        found = False
        for i, gt in enumerate(ground_truth):
            if i in matched:
                continue
            if gt.get("kind") != ak:
                continue
            if gt.get("bssid", "").upper() != ab and gt.get("bssid"):
                continue
            start, end = gt.get("start", 0), gt.get("end", gt.get("start", 0))
            if (start - window_s) <= ats <= (end + window_s):
                matched.add(i)
                metrics[ak].tp += 1
                overall.tp += 1
                if isinstance(start, (int, float)) and isinstance(ats, (int, float)):
                    metrics[ak].latency_ms.append(max(0, (ats - start) * 1000))
                    overall.latency_ms.append(max(0, (ats - start) * 1000))
                found = True
                break
        if not found:
            metrics[ak].fp += 1
            overall.fp += 1

    for i, gt in enumerate(ground_truth):
        if i not in matched:
            metrics[gt.get("kind", "unknown")].fn += 1
            overall.fn += 1

    return {
        "overall": overall.to_dict(),
        "by_kind": {k: v.to_dict() for k, v in metrics.items()},
        "ground_truth_count": len(ground_truth),
        "alert_count": len(alerts),
        "matched": len(matched),
        "unmatched_ground_truth": [ground_truth[i] for i in range(len(ground_truth)) if i not in matched],
    }


def score_correlation(ground_truth: Dict[str, Set[str]], predicted: List[Set[str]]) -> Dict[str, Any]:
    """Score clustering / correlation against ground-truth groups.

    ground_truth: {"device_group": {"MAC1", "MAC2", ...}, ...}
    predicted:    [{"MAC1", "MAC2"}, {"MAC3"}, ...]
    """
    gt_pairs: Set[frozenset] = set()
    for members in ground_truth.values():
        ms = list(members)
        for i in range(len(ms)):
            for j in range(i + 1, len(ms)):
                gt_pairs.add(frozenset((ms[i].upper(), ms[j].upper())))

    pred_pairs: Set[frozenset] = set()
    for cluster in predicted:
        ms = list(cluster)
        for i in range(len(ms)):
            for j in range(i + 1, len(ms)):
                pred_pairs.add(frozenset((ms[i].upper(), ms[j].upper())))

    tp = len(gt_pairs & pred_pairs)
    fp = len(pred_pairs - gt_pairs)
    fn = len(gt_pairs - pred_pairs)
    m = DetectionMetrics(tp=tp, fp=fp, fn=fn)
    return {
        "pairs": {"tp": tp, "fp": fp, "fn": fn,
                  "precision": round(m.precision, 4), "recall": round(m.recall, 4),
                  "f1": round(m.f1, 4)},
        "clusters_predicted": len(predicted),
        "clusters_ground_truth": len(ground_truth),
        "pair_count_gt": len(gt_pairs), "pair_count_pred": len(pred_pairs),
    }


def benchmark_throughput(events: List[dict], window_s: float = 1.0) -> dict:
    """Compute throughput / latency benchmarks from a timestamped event list."""
    if not events:
        return {"events": 0, "throughput_per_s": 0, "duration_s": 0}
    ts_sorted = sorted([float(e.get("ts", e.get("time", 0))) for e in events])
    duration = max(ts_sorted) - min(ts_sorted) if len(ts_sorted) > 1 else window_s
    # sliding window peak
    peak = 0
    j = 0
    for i, t in enumerate(ts_sorted):
        while j < len(ts_sorted) and ts_sorted[j] - t <= window_s:
            j += 1
        peak = max(peak, j - i)
    return {
        "events": len(events),
        "duration_s": round(duration, 2),
        "throughput_per_s": round(len(events) / max(duration, 0.1), 1),
        "peak_per_window": peak,
        "window_s": window_s,
    }


def compare_experiments(runs: List[dict]) -> dict:
    """Compare multiple experiment runs (different configs/seeds).

    Each run: {"id": str, "config": dict, "result": dict, "metrics": dict, "duration_s": float}
    Returns a side-by-side table + delta analysis.
    """
    if not runs:
        return {"error": "no runs to compare"}
    # Collect all metric keys
    all_keys: Set[str] = set()
    for r in runs:
        all_keys.update((r.get("metrics") or {}).keys())
        all_keys.update((r.get("result") or {}).keys())
    table: List[dict] = []
    for key in sorted(all_keys):
        row: dict = {"metric": key}
        vals = []
        for r in runs:
            v = (r.get("metrics") or {}).get(key)
            if v is None:
                v = (r.get("result") or {}).get(key, "")
            row[r.get("id", str(id(r)))] = v
            if isinstance(v, (int, float)):
                vals.append(float(v))
        if len(vals) >= 2:
            row["delta"] = round(max(vals) - min(vals), 4)
            row["mean"] = round(sum(vals) / len(vals), 4)
            if min(vals) != 0:
                row["delta_pct"] = round((max(vals) - min(vals)) / abs(min(vals)) * 100, 1)
        table.append(row)
    return {
        "runs": [r.get("id") for r in runs],
        "configs": {r.get("id"): r.get("config") for r in runs},
        "durations": {r.get("id"): r.get("duration_s") for r in runs},
        "table": table,
        "summary": f"{len(runs)} runs compared across {len(all_keys)} metrics",
    }


def roc_curve(scores: List[Tuple[float, bool]], thresholds: Optional[List[float]] = None) -> List[dict]:
    """Compute ROC points from (score, is_positive) pairs."""
    if thresholds is None:
        uniq = sorted(set(s for s, _ in scores))
        thresholds = uniq + [max(uniq) + 1] if uniq else [0.5]
    points = []
    positives = sum(1 for _, y in scores if y)
    negatives = len(scores) - positives
    for thr in thresholds:
        tp = sum(1 for s, y in scores if s >= thr and y)
        fp = sum(1 for s, y in scores if s >= thr and not y)
        points.append({
            "threshold": thr,
            "tpr": tp / positives if positives else 0,
            "fpr": fp / negatives if negatives else 0,
            "tp": tp, "fp": fp,
        })
    return points


def export_comparison_csv(comparison: dict, path: str) -> str:
    """Write comparison table to CSV (0600)."""
    import csv as _csv
    import os as _os
    from .privacy import secure_file
    table = comparison.get("table", [])
    if not table:
        return ""
    fieldnames = list(table[0].keys())
    _os.makedirs(_os.path.dirname(_os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = _csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(table)
    secure_file(path)
    return path
