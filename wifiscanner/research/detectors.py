"""Detector SDK — §12.

Researchers implement `Detector` (or Analyzer/FeatureExtractor) without
modifying the core. The SDK provides lifecycle, versioning, input/output
schemas, configuration validation, metrics, test harness and benchmark harness.

Example
-------
>>> from wifiscanner.research.detectors import Detector, DetectorRegistry
>>> class MyDeauth(Detector):
...     id = "my-deauth-001"
...     version = "1.0.0"
...     def detect(self, features):  # List[FrameFeatures]
...         return [a for a in features if a.subtype==12]
>>> registry = DetectorRegistry()
>>> registry.register(MyDeauth())
>>> results = registry.get("my-deauth-001").detect(feature_ds.features)
"""
from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..util import log
from .features import FrameFeatures


@dataclass
class Detection:
    ts: float
    kind: str
    bssid: str = ""
    src: str = ""
    dst: str = ""
    confidence: int = 50
    severity: str = "medium"  # info/medium/high/critical
    evidence: str = ""
    status: str = "unconfirmed"
    detector_id: str = ""
    detector_version: str = ""
    features_ref: str = ""  # provenance pointer

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
            "kind": self.kind, "bssid": self.bssid, "src": self.src, "dst": self.dst,
            "confidence": self.confidence, "severity": self.severity,
            "evidence": self.evidence, "status": self.status,
            "detector_id": self.detector_id, "detector_version": self.detector_version,
            "features_ref": self.features_ref,
        }


class Detector(ABC):
    """Base class for all detectors. Override `detect`."""

    id: str = "detector-base"
    version: str = "1.0.0"
    title: str = "Base Detector"
    description: str = ""
    input_schema: Dict[str, Any] = {"features": "List[FrameFeatures]"}
    output_schema: Dict[str, Any] = {"detections": "List[Detection]"}
    default_config: Dict[str, Any] = {}
    kind: str = "signature"  # signature/behavioral/statistical/ml

    def __init__(self, config: Optional[dict] = None):
        self.config = {**self.default_config, **(config or {})}
        self._validate_config()
        self.created_at = time.time()
        self.run_count = 0
        self.total_latency_ms = 0.0

    def _validate_config(self) -> None:
        # Subclasses may override for strict validation
        pass

    @abstractmethod
    def detect(self, features: List[FrameFeatures]) -> List[Detection]:
        ...

    def run(self, features: List[FrameFeatures]) -> Tuple[List[Detection], dict]:
        t0 = time.time()
        detections = self.detect(features)
        latency = (time.time() - t0) * 1000
        self.run_count += 1
        self.total_latency_ms += latency
        # Tag detections
        for d in detections:
            d.detector_id = self.id
            d.detector_version = self.version
        metrics = {
            "detections": len(detections),
            "latency_ms": round(latency, 2),
            "avg_latency_ms": round(self.total_latency_ms / self.run_count, 2) if self.run_count else 0,
            "detector_id": self.id,
            "detector_version": self.version,
            "input_frames": len(features),
        }
        log.info("detector %s v%s: %d frames → %d detections in %.1f ms", self.id, self.version, len(features), len(detections), latency)
        return detections, metrics

    def fingerprint(self) -> str:
        h = hashlib.sha256()
        h.update(self.id.encode())
        h.update(self.version.encode())
        h.update(json.dumps(self.config, sort_keys=True).encode())
        return h.hexdigest()[:12]

    def test_harness(self, features: List[FrameFeatures], expected_kinds: Optional[List[str]] = None) -> dict:
        """Run detector + check that it at least emits expected kinds (if provided)."""
        detections, metrics = self.run(features)
        kinds = {d.kind for d in detections}
        passed = True
        if expected_kinds:
            missing = [k for k in expected_kinds if k not in kinds]
            passed = not missing
            metrics["expected_kinds"] = expected_kinds
            metrics["missing_kinds"] = missing
            metrics["passed"] = passed
        return {"passed": passed, "metrics": metrics, "detections": [d.to_dict() for d in detections]}

    def benchmark(self, feature_sets: List[List[FrameFeatures]], repeats: int = 3) -> dict:
        """Latency/throughput benchmark across multiple datasets."""
        latencies: List[float] = []
        throughputs: List[float] = []
        for feats in feature_sets:
            for _ in range(repeats):
                t0 = time.time()
                self.detect(feats)
                lat = (time.time() - t0) * 1000
                latencies.append(lat)
                throughputs.append(len(feats) / max(lat / 1000, 0.001))
        latencies.sort()
        throughputs.sort()
        return {
            "repeats": repeats * len(feature_sets),
            "latency_ms": {
                "mean": round(sum(latencies) / len(latencies), 2) if latencies else 0,
                "p50": round(latencies[len(latencies)//2], 2) if latencies else 0,
                "p95": round(latencies[int(len(latencies)*0.95)], 2) if latencies else 0,
                "min": round(min(latencies), 2) if latencies else 0,
                "max": round(max(latencies), 2) if latencies else 0,
            },
            "throughput_fps": {
                "mean": round(sum(throughputs) / len(throughputs), 1) if throughputs else 0,
                "p95": round(throughputs[int(len(throughputs)*0.95)], 1) if throughputs else 0,
            },
            "detector": f"{self.id} v{self.version}",
        }


class DetectorRegistry:
    """In-memory registry (backed by on-disk if needed)."""

    def __init__(self):
        self._store: Dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        if not detector.id or detector.id == "detector-base":
            raise ValueError("detector must have a non-default id")
        if detector.id in self._store:
            raise ValueError(f"detector {detector.id!r} already registered")
        self._store[detector.id] = detector
        log.info("detector registered: %s v%s (%s)", detector.id, detector.version, detector.kind)

    def get(self, detector_id: str) -> Optional[Detector]:
        return self._store.get(detector_id)

    def list(self) -> List[Detector]:
        return list(self._store.values())

    def unregister(self, detector_id: str) -> bool:
        return self._store.pop(detector_id, None) is not None


# ------------------------------------------------------------------ built-in detectors

class DeauthFloodDetector(Detector):
    id = "builtin-deauth-flood"
    version = "1.0.0"
    title = "Deauthentication Flood Detector"
    description = "Counts deauth/disassoc (subtype 12/10) per BSSID in a sliding window."
    default_config = {"window_s": 10.0, "threshold": 5}
    kind = "signature"

    def detect(self, features: List[FrameFeatures]) -> List[Detection]:
        window = float(self.config.get("window_s", 10.0))
        thr = int(self.config.get("threshold", 5))
        by_bssid: Dict[str, List[float]] = {}
        out: List[Detection] = []
        for f in features:
            if f.frame_type != "mgmt" or f.subtype not in (10, 12):
                continue
            key = f.bssid or f.dst or "unknown"
            lst = by_bssid.setdefault(key, [])
            lst.append(f.ts)
            # trim window
            cutoff = f.ts - window
            while lst and lst[0] < cutoff:
                lst.pop(0)
            if len(lst) == thr:  # fire once per window
                out.append(Detection(
                    ts=f.ts, kind="deauth-flood", bssid=key,
                    confidence=70, severity="high",
                    evidence=f"{len(lst)} deauth/disassoc in {window:.0f}s",
                ))
        return out


class BeaconMutationDetector(Detector):
    id = "builtin-beacon-mutation"
    version = "1.0.0"
    title = "Beacon Fingerprint Mutation Detector"
    description = "Detects BSSID whose RSN/WPS/channel changes mid-air."
    kind = "behavioral"

    def detect(self, features: List[FrameFeatures]) -> List[Detection]:
        seen: Dict[str, Tuple[str, int]] = {}
        out: List[Detection] = []
        for f in features:
            if f.subtype != 8:  # beacon
                continue
            sig = (f.bss_security or "", f.channel or 0)
            prev = seen.get(f.bssid)
            if prev and prev != sig:
                out.append(Detection(
                    ts=f.ts, kind="beacon-mutation", bssid=f.bssid,
                    confidence=65, severity="medium",
                    evidence=f"{prev} → {sig}",
                ))
            seen[f.bssid] = sig
        return out


# Pre-registered catalogue for convenience
BUILTIN_DETECTORS: List[Detector] = [
    DeauthFloodDetector(),
    BeaconMutationDetector(),
]
