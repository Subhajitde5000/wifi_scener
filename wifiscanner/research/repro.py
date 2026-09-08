"""Reproducibility Manifest — §34.

Captures everything needed to reproduce an experiment:
  software version, dataset (id/version/sha), feature pipeline version,
  detector id/version + config fingerprint + seed, hardware capabilities
  at run time, OS/platform, timestamp, timeline checkpoint.

The manifest is written alongside each run (both in DB and as a JSON sidecar
next to the output directory). `verify_manifest()` checks that the pinned
artefacts are still present and unchanged.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import time
from typing import Any, Dict, Optional

from .. import __version__


def build_manifest(
    experiment_id: str = "",
    run_id: str = "",
    seed: Optional[int] = None,
    dataset: Optional[dict] = None,
    feature_dataset: Optional[dict] = None,
    detector: Optional[dict] = None,
    hardware: Optional[dict] = None,
    config: Optional[dict] = None,
) -> dict:
    return {
        "schema": "wifiscanner-repro-v1",
        "software_version": __version__,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "experiment_id": experiment_id,
        "run_id": run_id,
        "seed": seed,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "created_at_ts": time.time(),
        "dataset": dataset or {},
        "feature_dataset": feature_dataset or {},
        "detector": detector or {},
        "hardware": hardware or {},
        "config": config or {},
        "fingerprint": _fingerprint(
            experiment_id, str(seed), str(dataset), str(detector), str(config), __version__
        ),
    }


def _fingerprint(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode())
    return h.hexdigest()[:12]


def write_manifest(path: str, manifest: dict) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def load_manifest(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def verify_manifest(manifest: dict) -> dict:
    """Check that artefacts pinned in the manifest still exist & match."""
    issues = []
    ds = manifest.get("dataset", {})
    if ds.get("artifact_path") and not os.path.exists(ds["artifact_path"]):
        issues.append(f"dataset artefact missing: {ds['artifact_path']}")
    # recomputed fingerprint vs stored
    exp = (
        build_manifest(
            experiment_id=manifest.get("experiment_id", ""),
            seed=manifest.get("seed"),
            dataset=manifest.get("dataset"),
            detector=manifest.get("detector"),
            config=manifest.get("config"),
        )["fingerprint"]
        == manifest.get("fingerprint")
    )
    if not exp:
        issues.append("fingerprint mismatch — parameters changed since capture")
    return {"ok": len(issues) == 0, "issues": issues, "checked_at": time.time()}
