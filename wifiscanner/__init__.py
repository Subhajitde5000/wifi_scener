"""wifiscanner — research-grade passive Wi-Fi survey & laboratory platform.

Version 5.1.0 — Wireless Cybersecurity Research & Experimentation Platform.

Core invariants kept from 4.x:
  • Engine / AccessPoint / Station / export_all remain stable imports.
  • All CLI commands remain backward-compatible.
  • Zero mandatory dependencies beyond stdlib.

New in 5.1 (research platform):
  • wifiscanner.experiment — unified experiment lifecycle engine (14 states)
  • wifiscanner.pipeline   — async event pipeline / telemetry bus
  • wifiscanner.analytics  — detection scoring, benchmarks, comparison
  • wifiscanner.defense.AdvancedWatchdog — 12-signature IDS
  • wifiscanner.research   — projects / datasets / features / detectors /
                             benchmarks / resources / evidence / hardware /
                             reproducibility / reporting / visualization
  • wifiscanner.research.web — unified student + instructor workstation
  • `wifiscanner research` CLI + `wifiscanner experiment` engine
"""

__version__ = "5.1.0"

from .engine import Engine
from .export import export_all
from .models import AccessPoint, Station

__all__ = ["AccessPoint", "Station", "Engine", "export_all", "__version__"]
