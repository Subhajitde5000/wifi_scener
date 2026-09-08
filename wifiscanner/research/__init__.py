"""Research-grade wireless cybersecurity experimentation platform.

This package implements the unified infrastructure required by §6-50 of the
master directive. It extends the existing wifiscanner toolkit without
replacing working functionality.

Modules
-------
projects   — research project lifecycle (question → hypothesis → experiments)
datasets   — versioned dataset registry (live/captured/replayed/simulated/synthetic)
ground_truth — labeled truth + correction provenance
features   — reusable 802.11 feature extraction pipeline
detectors  — plugin SDK for custom detectors/analyzers
resources  — lab resource manager (allocation, heartbeat, orphan release)
evidence   — unified artifact ledger (checksum, provenance, retention)
hardware   — OS/driver capability discovery + hardware abstraction
benchmarks — standardized benchmark harness (accuracy/latency/throughput)
stats      — descriptive stats + CI + comparison helpers
web        — student workspace + instructor console (unified)

All persistence is SQLite WAL with foreign keys, indexes and migrations.
All file artefacts are 0600, provenance-tagged, hash-verified.
"""
from __future__ import annotations

__version__ = "5.1.0"

from .projects import Project, ProjectStore
from .datasets import Dataset, DatasetStore
from .features import FeaturePipeline, FrameFeatures, FeatureDataset
from .detectors import Detector, DetectorRegistry
from .resources import ResourceManager, LabResource
from .evidence import EvidenceStore, Evidence
from .hardware import CapabilityProbe
from .benchmarks import BenchmarkSuite, BenchmarkRun
from .stats import describe, confidence_interval, compare_groups
from .repro import build_manifest

__all__ = [
    "Project", "ProjectStore",
    "Dataset", "DatasetStore",
    "FeaturePipeline", "FrameFeatures", "FeatureDataset",
    "Detector", "DetectorRegistry",
    "ResourceManager", "LabResource",
    "EvidenceStore", "Evidence",
    "CapabilityProbe",
    "BenchmarkSuite", "BenchmarkRun",
    "describe", "confidence_interval", "compare_groups",
    "build_manifest",
]
