"""wifiscanner — research-grade passive Wi-Fi survey & laboratory platform.

Version 5.0.0 — Advanced Cybersecurity Research Lab edition.

Core invariants kept from 4.x:
  • Engine / AccessPoint / Station / export_all remain stable imports.
  • All CLI commands remain backward-compatible.
  • Zero mandatory dependencies beyond stdlib.

New in 5.0 (research-grade):
  • wifiscanner.experiment — unified experiment lifecycle engine
  • wifiscanner.pipeline   — async event pipeline / telemetry bus
  • wifiscanner.analytics  — detection scoring, benchmarks, comparison
  • wifiscanner.defense.AdvancedWatchdog — 12-signature IDS
"""

__version__ = "5.0.0"

from .engine import Engine
from .export import export_all
from .models import AccessPoint, Station

__all__ = ["AccessPoint", "Station", "Engine", "export_all", "__version__"]
