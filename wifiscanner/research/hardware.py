"""Hardware Abstraction + Capability Discovery — §18 + §5.

Separates Core → HAL → Linux/macOS/Windows backends and exposes what the
current hardware actually supports. Every capability check is real (probes
the OS), never invented.

Capabilities
------------
monitor_mode, packet_capture, channel_control, radiotap, injection,
rssi, interface_control, promiscuous, ap_mode

The probe is cheap and cached; callers can poll at startup or on
interface hot-plug. Results are stored in the resource manager so the
instructor console can show a live capability matrix.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..backends.survey import available_backends, list_interfaces
from ..util import log, os_name, is_root

CAPABILITIES = [
    "monitor_mode", "packet_capture", "channel_control",
    "radiotap", "injection", "rssi", "interface_control",
    "promiscuous", "ap_mode",
]


@dataclass
class HardwareCapabilities:
    platform: str = ""
    is_root: bool = False
    backends: List[str] = field(default_factory=list)
    interfaces: List[dict] = field(default_factory=list)
    caps: Dict[str, bool] = field(default_factory=dict)
    details: Dict[str, str] = field(default_factory=dict)
    probed_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        ok = [k for k, v in self.caps.items() if v]
        miss = [k for k, v in self.caps.items() if not v]
        return f"{self.platform} root={self.is_root} backends={self.backends} caps: +{ok} -{miss}"


class CapabilityProbe:
    """Probes real OS/hardware capabilities."""

    def __init__(self):
        self._cached: Optional[HardwareCapabilities] = None
        self._cache_ts: float = 0

    def probe(self, refresh: bool = False) -> HardwareCapabilities:
        if self._cached and not refresh and (time.time() - self._cache_ts) < 5:
            return self._cached

        plat = os_name()
        root = is_root()
        backs = available_backends()
        ifaces = []
        try:
            ifaces = list_interfaces()
        except Exception as exc:
            log.warning("capability probe: list_interfaces failed: %s", exc)

        # Real capability checks
        caps: Dict[str, bool] = {}
        details: Dict[str, str] = {}

        # scapy (packet_capture, radiotap)
        try:
            from ..backends.sniffer import scapy_available
            has_scapy = scapy_available()
        except Exception:
            has_scapy = False
        caps["packet_capture"] = has_scapy
        caps["radiotap"] = has_scapy

        # monitor_mode: iw list | grep monitor  (Linux) ; otherwise false
        mon = False
        if plat == "linux" and shutil.which("iw"):
            try:
                out = subprocess.run(["iw", "list"], capture_output=True, text=True, timeout=5)
                mon = "monitor" in out.stdout.lower()
                details["iw_list"] = "monitor supported" if mon else "monitor not listed"
            except Exception as exc:
                details["iw_list"] = f"error: {exc}"
        caps["monitor_mode"] = mon

        # channel_control: same as monitor on Linux
        caps["channel_control"] = mon and root

        # injection: scapy + monitor + root + iw check
        caps["injection"] = has_scapy and mon and root
        if caps["injection"]:
            details["injection"] = "scapy+monitor+root present — dry-run gate still enforced"
        else:
            details["injection"] = "missing: " + ", ".join(
                k for k in ("scapy", "monitor", "root") if not {"scapy": has_scapy, "monitor": mon, "root": root}[k]
            )

        # rssi: available if any survey backend present
        caps["rssi"] = bool(backs)

        # interface_control: ip/iw present
        caps["interface_control"] = bool(shutil.which("ip") or shutil.which("iw") or shutil.which("ifconfig"))
        caps["promiscuous"] = caps["interface_control"] and root
        caps["ap_mode"] = mon  # AP mode implies monitor-capable driver

        # Survey-specific
        caps["survey"] = bool(backs)

        hc = HardwareCapabilities(
            platform=plat, is_root=root, backends=backs,
            interfaces=ifaces, caps=caps, details=details,
        )
        self._cached = hc
        self._cache_ts = time.time()
        log.info("hardware probe: %s", hc.summary())
        return hc

    def require(self, capability: str) -> None:
        """Raise if capability missing (caller gets clear hardware error)."""
        hc = self.probe()
        if not hc.caps.get(capability):
            raise RuntimeError(
                f"hardware capability {capability!r} not available on this host "
                f"(platform={hc.platform}, root={hc.is_root}, details={hc.details.get(capability, hc.details)})"
            )

    def report(self) -> dict:
        hc = self.probe()
        return {
            "platform": hc.platform,
            "root": hc.is_root,
            "backends": hc.backends,
            "interfaces": hc.interfaces,
            "capabilities": hc.caps,
            "details": hc.details,
            "probed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(hc.probed_at)),
        }
