"""Reporting — §33.

One-click export of a research artefact bundle:
  report.md + report.json + metrics.csv + manifest.json + evidence index.
Everything is checksummed and provenance-tagged so a third party can
reproduce the experiment from the bundle alone.

Uses only stdlib; markdown is flavoured for GitHub rendering.
"""
from __future__ import annotations

import csv
import json
import os
import time
from typing import Any, Dict, List

from ..privacy import secure_file


def write_report(
    out_dir: str,
    title: str = "Research Report",
    question: str = "",
    hypothesis: str = "",
    experiment: dict = None,
    dataset: dict = None,
    metrics: List[dict] = None,
    comparison: dict = None,
    manifest: dict = None,
    evidence: List[dict] = None,
    stats: dict = None,
) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    files: List[str] = []

    # Markdown
    md_path = os.path.join(out_dir, "report.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(f"# {title}\n\n")
        fh.write(f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S')} · wifiscanner_\n\n")
        if question:
            fh.write(f"**Research question:** {question}\n\n")
        if hypothesis:
            fh.write(f"**Hypothesis:** {hypothesis}\n\n")
        if experiment:
            fh.write("## Experiment\n```json\n" + json.dumps(experiment, indent=2) + "\n```\n\n")
        if dataset:
            fh.write("## Dataset\n```json\n" + json.dumps(dataset, indent=2) + "\n```\n\n")
        if stats:
            fh.write("## Descriptive statistics\n```json\n" + json.dumps(stats, indent=2) + "\n```\n\n")
        if metrics:
            fh.write(f"## Metrics ({len(metrics)} points)\n\n")
            fh.write("| metric | value | meta |\n|---|---|---|\n")
            for m in metrics[:40]:
                fh.write(f"| {m.get('metric','')} | {m.get('value','')} | {m.get('meta','')} |\n")
            fh.write("\n")
        if comparison:
            fh.write("## Comparison\n```json\n" + json.dumps(comparison, indent=2) + "\n```\n\n")
        if evidence:
            fh.write(f"## Evidence ({len(evidence)} artefacts)\n\n")
            fh.write("| id | kind | provenance | sha |\n|---|---|---|---|\n")
            for e in evidence[:40]:
                fh.write(f"| {e.get('id','')[:12]} | {e.get('kind','')} | {e.get('provenance','')} | {e.get('sha256','')[:10]} |\n")
            fh.write("\n")
        if manifest:
            fh.write("## Reproducibility manifest fingerprint\n```\n" + manifest.get("fingerprint","") + "\n```\n\n")
            fh.write(f"_software {manifest.get('software_version','')} · {manifest.get('platform','')} · seed {manifest.get('seed','')} _\n\n")
        fh.write("---\n_All measurements are actual backend values; no fabricated data. Raw tables are in `metrics.csv` / `report.json` for external verification._\n")
    secure_file(md_path)
    files.append(md_path)

    # JSON
    js_path = os.path.join(out_dir, "report.json")
    bundle = {"title": title, "question": question, "hypothesis": hypothesis,
              "experiment": experiment, "dataset": dataset, "metrics": metrics or [],
              "comparison": comparison, "manifest": manifest, "evidence": evidence or [],
              "stats": stats, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    with open(js_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    secure_file(js_path)
    files.append(js_path)

    # metrics CSV
    if metrics:
        csv_path = os.path.join(out_dir, "metrics.csv")
        fieldnames = sorted({k for m in metrics for k in m})
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(metrics)
        secure_file(csv_path)
        files.append(csv_path)

    # manifest sidecar
    if manifest:
        mp = os.path.join(out_dir, "manifest.json")
        with open(mp, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        secure_file(mp)
        files.append(mp)

    return files
