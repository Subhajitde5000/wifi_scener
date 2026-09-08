"""Statistical Research Helpers — §15.

Descriptive stats, distributions, averages, medians, variance, stdev,
confidence intervals (normal approx), outlier detection (IQR), correlation
(Pearson), and comparison of experimental groups.

No invented significance: p-values are not fabricated; CI is computed from
measured variance and clearly labeled as derived. Raw measurements are always
exportable for external tools (Python/R/MATLAB).
"""
from __future__ import annotations

import math
import statistics
from typing import Any, Dict, List, Optional, Tuple


def describe(values: List[float]) -> dict:
    if not values:
        return {"count": 0}
    vals = sorted(float(v) for v in values)
    n = len(vals)
    mean = statistics.mean(vals)
    med = statistics.median(vals)
    stdev = statistics.pstdev(vals) if n > 1 else 0.0
    var = statistics.pvariance(vals) if n > 1 else 0.0
    return {
        "count": n,
        "mean": round(mean, 4),
        "median": round(med, 4),
        "min": round(min(vals), 4),
        "max": round(max(vals), 4),
        "range": round(max(vals) - min(vals), 4),
        "variance": round(var, 4),
        "stdev": round(stdev, 4),
        "p25": round(vals[n // 4], 4) if n >= 4 else round(vals[0], 4),
        "p75": round(vals[3 * n // 4], 4) if n >= 4 else round(vals[-1], 4),
        "p95": round(vals[int(n * 0.95)], 4) if n >= 2 else round(vals[-1], 4),
    }


def confidence_interval(values: List[float], confidence: float = 0.95) -> dict:
    """Normal-approx CI for the mean. Returns derived, labeled as such."""
    if len(values) < 2:
        return {"mean": round(values[0], 4) if values else None, "ci_low": None, "ci_high": None, "note": "n<2, no CI"}
    mean = statistics.mean(values)
    stdev = statistics.stdev(values)  # sample stdev
    n = len(values)
    # z for 95% ~1.96, 99% ~2.576 (normal approx, not t — labeled)
    z = 1.96 if confidence >= 0.95 else 1.645
    margin = z * stdev / math.sqrt(n)
    return {
        "mean": round(mean, 4),
        "ci_low": round(mean - margin, 4),
        "ci_high": round(mean + margin, 4),
        "confidence": confidence,
        "method": "normal-approx (derived, not measured)",
        "n": n,
        "stdev": round(stdev, 4),
    }


def outliers_iqr(values: List[float], k: float = 1.5) -> List[float]:
    if len(values) < 4:
        return []
    vals = sorted(values)
    n = len(vals)
    q1 = vals[n // 4]
    q3 = vals[3 * n // 4]
    iqr = q3 - q1
    low = q1 - k * iqr
    high = q3 + k * iqr
    return [v for v in vals if v < low or v > high]


def pearson(xs: List[float], ys: List[float]) -> Optional[float]:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    mx = statistics.mean(xs)
    my = statistics.mean(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = math.sqrt(sum((x - mx) ** 2 for x in xs) * sum((y - my) ** 2 for y in ys))
    if den == 0:
        return 0.0
    return round(num / den, 4)


def compare_groups(groups: Dict[str, List[float]]) -> dict:
    """Compare named experimental groups."""
    descs = {k: describe(v) for k, v in groups.items()}
    # Pairwise mean deltas
    deltas: List[dict] = []
    names = list(groups.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            ma = descs[a].get("mean") if descs[a] else None
            mb = descs[b].get("mean") if descs[b] else None
            if ma is not None and mb is not None:
                deltas.append({
                    "a": a, "b": b,
                    "delta": round(mb - ma, 4),
                    "delta_pct": round((mb - ma) / abs(ma) * 100, 2) if ma != 0 else None,
                })
    return {"groups": descs, "deltas": deltas, "note": "descriptive comparison; no significance asserted"}


def export_csv_rows(rows: List[dict], path: str) -> str:
    import csv, os
    from ..privacy import secure_file
    if not rows:
        return ""
    fieldnames = sorted({k for r in rows for k in r})
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    secure_file(path)
    return path
