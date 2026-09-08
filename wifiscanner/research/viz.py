"""Visualization helpers — §35 (stdlib-only).

Every chart is backed by real measurements. No synthetic data is invented
for presentation. Helpers emit:
  * ASCII sparkline / histogram for terminal
  * SVG chart for HTML reports (no external JS)
  * CSV export for Python/R/MATLAB

The research workstation (research/web.py) calls these to render
RSSI histories, confusion matrices and ROC helpers without external deps.
"""
from __future__ import annotations

import math
import statistics
from typing import Dict, List, Optional, Tuple

_BARS = " ▁▂▃▄▅▆▇█"


def sparkline(values: List[float], width: int = 40) -> str:
    if not values:
        return ""
    lo, hi = min(values), max(values)
    span = hi - lo if hi != lo else 1.0
    # bucket to width
    step = max(1, len(values) // width)
    buckets = [values[i:i+step] for i in range(0, len(values), step)]
    avgs = [statistics.mean(b) for b in buckets][:width]
    chars = []
    for v in avgs:
        idx = int((v - lo) / span * (len(_BARS) - 1))
        chars.append(_BARS[max(0, min(len(_BARS) - 1, idx))])
    return "".join(chars) + f"  [{lo:.1f} .. {hi:.1f}]"


def hist_ascii(values: List[float], bins: int = 10) -> str:
    if not values:
        return "(no data)"
    lo, hi = min(values), max(values)
    span = hi - lo if hi != lo else 1.0
    counts = [0] * bins
    for v in values:
        idx = min(bins - 1, int((v - lo) / span * bins))
        counts[idx] += 1
    mx = max(counts) or 1
    lines = []
    for i, c in enumerate(counts):
        b_lo = lo + i * span / bins
        b_hi = lo + (i + 1) * span / bins
        bar = "█" * int(c / mx * 20)
        lines.append(f"{b_lo:7.1f}–{b_hi:<7.1f} |{bar:<20}| {c}")
    return "\n".join(lines)


def confusion_matrix_ascii(cm: Dict[str, int]) -> str:
    # cm keys: tp, tn, fp, fn
    tp, tn, fp, fn = cm.get("tp", 0), cm.get("tn", 0), cm.get("fp", 0), cm.get("fn", 0)
    return (
        f"              Predicted\n"
        f"               +      -\n"
        f"Actual   +  | TP {tp:4}  FN {fn:4} |\n"
        f"         -  | FP {fp:4}  TN {tn:4} |\n"
    )


def svg_line(values: List[float], width: int = 600, height: int = 180,
             title: str = "", color: str = "#38bdf8") -> str:
    """Minimal single-series SVG line chart (no JS)."""
    if not values:
        return f'<svg width="{width}" height="{height}"><text x="10" y="20">no data</text></svg>'
    lo, hi = min(values), max(values)
    span = hi - lo if hi != lo else 1.0
    # map to coordinates with 30px padding
    pad = 30
    pts = []
    n = len(values)
    for i, v in enumerate(values):
        x = pad + (width - 2 * pad) * i / max(1, n - 1)
        y = height - pad - (height - 2 * pad) * (v - lo) / span
        pts.append(f"{x:.1f},{y:.1f}")
    poly = " ".join(pts)
    return (
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg" '
        f'style="background:#0b1220;border-radius:8px">'
        f'<text x="{width//2}" y="18" text-anchor="middle" fill="#94a3b8" font-size="12">{title}</text>'
        f'<polyline fill="none" stroke="{color}" stroke-width="1.8" points="{poly}"/>'
        f'<text x="{pad}" y="{height-8}" fill="#64748b" font-size="10">{lo:.1f}</text>'
        f'<text x="{width-pad}" y="{height-8}" text-anchor="end" fill="#64748b" font-size="10">{hi:.1f}</text>'
        f'</svg>'
    )


def svg_bars(categories: List[str], values: List[float], width: int = 600, height: int = 220,
             title: str = "") -> str:
    if not categories or not values:
        return svg_line([], width, height, title)
    mx = max(values) or 1.0
    pad = 36
    bw = (width - 2 * pad) / len(values)
    bars = []
    for i, (c, v) in enumerate(zip(categories, values)):
        x = pad + i * bw + 4
        w = bw - 8
        h = (height - 2 * pad) * v / mx
        y = height - pad - h
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="#38bdf8" rx="3"/>'
                    f'<text x="{x+bw/2-4:.1f}" y="{height-12}" text-anchor="middle" fill="#94a3b8" font-size="10">{c[:10]}</text>')
    return (
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg" '
        f'style="background:#0b1220;border-radius:8px">'
        f'<text x="{width//2}" y="18" text-anchor="middle" fill="#94a3b8" font-size="12">{title}</text>'
        + "".join(bars) +
        f'</svg>'
    )
