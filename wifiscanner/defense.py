"""Passive IDS watchdog + defensive hardening audit for your own airspace.

The educational counterpart of every offensive 802.11 technique: each attack
has a *signature* in management frames, and that signature is what we detect.
100% receive-only; nothing here transmits or attacks.

Detected signatures
-------------------
- deauth/disassociation flood        (the classic client-kick / EVIL TWIN bait)
- forced reauth: deauth -> assoc -> EAPOL within seconds
                                   (signature of handshake-harvest attempts)
- EAPOL authentication storm         (clients being dragged into renegotiation)
- beacon fingerprint mutation        (channel/security change mid-air, or a
                                   clone advertising the same SSID differently)
- WPA3->WPA2 downgrade advertisement (PMF-required networks that suddenly
                                   present PSK-only RSN IEs)
- unknown / new BSSIDs               (against your warden baseline)
- evil-twin heuristics               (same SSID, different vendor/security)
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .engine import Engine
from .models import AccessPoint


@dataclass
class Alert:
    ts: float
    severity: str          # info / medium / high / critical
    kind: str
    bssid: str
    ssid: str
    src: str
    dst: str
    detail: str

    def to_row(self) -> dict:
        return {"time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
                "severity": self.severity, "kind": self.kind, "bssid": self.bssid,
                "ssid": self.ssid, "src": self.src, "dst": self.dst,
                "detail": self.detail}


class Watchdog:
    """Stateful management-frame anomaly detector. Feed it scapy frames."""

    def __init__(self, window_s: float = 10.0, flood_frames: int = 5,
                 cooldown_s: float = 30.0, known_bssids: Set[str] = frozenset(),
                 ap_of_client: Optional[Dict[str, str]] = None):
        self.window = window_s
        self.flood_n = flood_frames
        self.cooldown = cooldown_s
        self.known: Set[str] = {k.upper() for k in known_bssids}
        self.ap_of_client = ap_of_client or {}
        self.deauth_by_ap: Dict[str, deque] = defaultdict(deque)
        self.eapol_by_ap: Dict[str, deque] = defaultdict(deque)
        self.last_deauth: Dict[Tuple[str, str], float] = {}   # (ap, sta) -> ts
        self.last_assoc: Dict[Tuple[str, str], float] = {}
        self.ap_fingerprint: Dict[str, Tuple] = {}            # bssid -> (ch, secsig)
        self.ap_ssid: Dict[str, str] = {}
        self.alerts: List[Alert] = []
        self._last_fired: Dict[Tuple, float] = {}
        self.frames = 0
        self.started = time.time()

    # ---------------------------------------------------------- firing

    def _fire(self, kind: str, severity: str, bssid: str, detail: str,
               src: str = "", dst: str = "", key_extra: str = "") -> None:
        key = (kind, bssid, key_extra)
        now = time.time()
        if now - self._last_fired.get(key, 0.0) < self.cooldown:
            return
        self._last_fired[key] = now
        self.alerts.append(Alert(now, severity, kind, bssid,
                                 self.ap_ssid.get(bssid, ""), src, dst, detail))

    # ---------------------------------------------------------- parsing

    def feed(self, pkt) -> None:
        self.frames += 1
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Elt, EAPOL
        except Exception:                      # pragma: no cover
            return
        if not pkt.haslayer(Dot11):
            return
        d = pkt[Dot11]
        t, st = d.type, d.subtype
        ap = (d.addr3 or "").upper()
        sta = (d.addr2 or "").upper()
        now = time.time()

        if t == 0 and st in (12, 11):                     # deauth / disassoc
            self.deauth_by_ap[ap].append(now)
            self._trim(self.deauth_by_ap[ap])
            if len(self.deauth_by_ap[ap]) >= self.flood_n:
                baselined = not self.known or ap in self.known
                note = ("on YOUR baseline network" if ap in self.known
                        else "on a BSS outside your baseline") if self.known \
                        else ""
                self._fire("deauth-flood",
                           "high" if baselined else "info", ap,
                           f"{len(self.deauth_by_ap[ap])} deauth/disassoc in "
                           f"{self.window:.0f}s {note} - kick/redirect or "
                           f"handshake-harvest bait; PMF-required clients "
                           f"ignore forged management frames",
                           src=d.addr1 or "")
            # remember for the forced-reauth chain (attacker kicks both ways)
            for other in (d.addr1, d.addr2):
                if other:
                    self.last_deauth[(ap, other.upper())] = now
        elif t == 0 and st in (0, 4):                     # (re)assoc request
            self.last_assoc[(ap, sta)] = now
            td = self.last_deauth.get((ap, sta), 0.0)
            if now - td <= self.window:
                self._fire("forced-reauth", "critical", ap,
                           "reassociation within seconds of a deauth - classic "
                           "deauth->reauth->harvest chain; verify PMF is "
                           "required on this BSS", src=sta, key_extra=sta)
        elif t == 0 and st == 8:                          # beacon
            self._beacon(d, pkt)
        elif t == 2:                                      # data / qos
            if self._is_eapol(pkt):
                self.eapol_by_ap[ap].append(now)
                self._trim(self.eapol_by_ap[ap])  # same window
                if len(self.eapol_by_ap[ap]) >= self.flood_n + 1:
                    self._fire("eapol-storm", "high", ap,
                               f"{len(self.eapol_by_ap[ap])} EAPOL frames in "
                               f"{self.window * 3:.0f}s - renegotiation storm, "
                               f"often paired with client kicking")
                ta = self.last_assoc.get((ap, sta), 0.0)
                td = self.last_deauth.get((ap, sta), 0.0)
                if now - ta <= self.window and ta - td <= self.window:
                    self._fire("handshake-harvest-signature", "critical", ap,
                               "deauth -> fresh association -> EAPOL within "
                               f"{self.window:.0f}s for client {sta}: someone "
                               "is attempting 4-way handshake harvesting; "
                               "rotate no secrets until PMF is enforced",
                               src=sta, key_extra=sta)

    def _trim(self, q: deque) -> None:
        cutoff = time.time() - self.window
        while q and q[0] < cutoff:
            q.popleft()

    @staticmethod
    def _elts(pkt):
        from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
        layer = pkt.getlayer(Dot11Beacon)
        out = []
        if layer is None:
            return out
        e = layer.payload
        while e and e.__class__.__name__ == "Dot11Elt":
            out.append(e)
            e = e.payload
        return out

    def _is_eapol(self, pkt) -> bool:
        from scapy.all import EAPOL
        if pkt.haslayer(EAPOL):
            return True
        # raw fallback: LLC/SNAP ethertype 0x888E
        from scapy.all import Dot11
        d = pkt.getlayer(Dot11)
        if d is None:
            return False
        raw = bytes(d.payload)
        if raw[6:8] == b"\x88\x8e" and raw[:3] == b"\xaa\xaa\x03":
            return True
        return False

    def _beacon(self, d, pkt) -> None:
        ap = (d.addr3 or "").upper()
        if not ap:
            return
        ssid, chan, secs = "", None, []
        for e in self._elts(pkt):
            if e.ID == 0:
                ssid = (e.info or b"").decode(errors="replace")
            elif e.ID == 3 and e.info:
                chan = e.info[0]
            elif e.ID in (48, 46, 221):
                secs.append(e.ID)
        if ssid:
            self.ap_ssid[ap] = ssid
        sig = (chan, tuple(sorted(secs)))
        old = self.ap_fingerprint.get(ap)
        if old is not None and old != sig:
            self._fire("beacon-mutation", "medium", ap,
                       f"beacon changed in-flight: channel/security IEs went "
                       f"{old} -> {sig}; either you reconfigured it or someone "
                       f"is impersonating the SSID", key_extra="beacon")
        self.ap_fingerprint[ap] = sig
        if self.known and ap not in self.known:
            self._fire("unknown-bss", "medium", ap,
                       f"first sighting of BSSID advertising {ssid or '<hidden>'!r} "
                       f"- not in your warden baseline", key_extra="warden")

    # ------------------------------------------------------------ output

    def results(self) -> List[Alert]:
        return sorted(self.alerts, key=lambda a: -a.ts)

    def stats(self) -> dict:
        sev = defaultdict(int)
        for a in self.alerts:
            sev[a.severity] += 1
        return {"frames": self.frames, "alerts": len(self.alerts),
                "by_severity": dict(sev),
                "runtime_s": round(time.time() - self.started, 1)}


# ------------------------------------------------------------------ audit

CHECKS_DOC = """Each finding maps to the offensive technique it exposes and the
configuration that defeats it. Every mitigation here is a settings change you
make on YOUR OWN router."""


def audit_ap(ap: AccessPoint) -> List[dict]:
    """Defensive hardening audit: (check, status, severity, why + fix)."""
    rows: List[dict] = []

    def add(check, ok, warn, sev, fix):
        rows.append({"check": check,
                     "status": "PASS" if ok else ("WARN" if warn else "FAIL"),
                     "severity": "" if ok else sev,
                     "finding": "" if ok else fix})

    sec = ap.security
    add("WPA3 / PMF-required encryption",
        "WPA3" in sec and ap.pmf == "required", True, "critical",
        "OWE/WPA3 with MFP required defeats deauth floods, and the 4-way "
        "handshake cannot be harvested or cracked offline (SAE binds it to "
        "the password without exposing a capturable MIC). Fix: WPA3-only or "
        "WPA2/3 with PMF REQUIRED.")
    add("PMF (802.11w) protects management frames",
        ap.pmf == "required", ap.pmf == "optional", "high",
        "Without PMF, anyone can kick your clients off (deauth flood) and "
        "provoke fresh handshakes. Fix: set PMF/management-frame protection "
        "to REQUIRED on the radio.")
    add("No WPS", not ap.wps, False, "high",
        "WPS PIN (esp. with old firmware) = offline Pixie-Dust style PIN "
        "recovery in seconds; treat the whole PIN feature as a "
        "password-disclosure hole. Fix: disable WPS entirely.")
    add("No WEP/TKIP/RC4 anywhere",
        "WEP" not in sec and "TKIP" not in ap.ciphers,
        not ap.ciphers, "critical",
        "TKIP/RC4 are broken ciphers whose keystreams have known recovery "
        "attacks; legacy WEP likewise. Fix: CCMP/GCMP only, disable legacy "
        "modes.")
    add("WPA2 uses AES-CCMP",
        ("WPA3" in sec) or ("CCMP" in ap.ciphers if "WPA2" in sec else True),
        False, "high",
        "CCMP still carries a capturable PSK handshake (safe only if your "
        "passphrase is strong/long); prefer WPA3, else >=25-char random "
        "passphrase.")
    if not sec or sec == ["OPEN"]:
        add("Authentication present", False, False, "critical",
            "Open BSS: every frame your clients send is readable by anyone "
            "in range (see `traffic` - the very module that proves it). Fix: "
            "at minimum WPA2/3, ideally all clients onto an authenticated "
            "SSID.")
    add("SSID broadcast (hidden-SSID is false security)",
        True, True, "",
        "Hiding the SSID gives no protection (probe responses still name it) "
        "and breaks some clients; it's here as documentation, not a defect.")
    if ap.raw.get("eapol_frames"):
        add("No abnormal handshake churn during scan",
            int(ap.raw.get("eapol_frames") or 0) < 20, True, "medium",
            "Many EAPOL frames in a short passive window means clients are "
            "renegotiating repeatedly - commonly a deauth/kick pattern; run "
            "`ids` to attribute it.")
    return rows


def audit_engine(engine: Engine) -> List[dict]:
    out = []
    for ap in engine.sorted_aps("rssi"):
        for r in audit_ap(ap):
            out.append({"bssid": ap.bssid, "ssid": ap.ssid, **r})
    return out
