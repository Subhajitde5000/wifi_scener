"""Authorized, defensive packet injection: verify YOUR sensors and YOUR PMF.

This is the *only* transmitting component of an otherwise 100% receive-only
toolkit. It exists so an operator can answer two defensive questions that
passive listening alone cannot:

1. "Do my passive IDS sensors actually HEAR the channels they claim to?"
   -> ``mode=canary``    transmits distinctive, harmless probe-request markers
      and lets you confirm every remote sensor logged them (coverage test).

2. "Does enabling PMF / 802.11w on MY router actually stop deauth kicks?"
   -> ``mode=pmf-test``  sends a tiny, bounded burst of deauthentication
      frames at ONE of your own clients, then observes whether the client
      stays associated (PMF works) or gets kicked and re-joins (PMF missing).

``mode=probe`` is ordinary active scanning - byte-for-byte the same probe
requests every laptop/phone OS broadcasts while scanning for networks; it
makes the survey deterministic instead of waiting for beacons.

``mode=ids-selftest`` is fully OFFLINE: it synthesises the attack signatures
in memory (no radio at all) and confirms the IDS watchdog fires on each.
Use it in CI / before deploying a sensor.

Hard safety gates (every one enforced in code, not just documented)
-------------------------------------------------------------------
* root / admin privileges are required for ANY over-the-air transmission;
* NOTHING is transmitted unless BOTH ``--transmit`` and ``--authorized`` are
  passed - the default is a dry run that only builds and displays frames;
* ``pmf-test`` additionally requires ``--yes`` AND an explicit unicast
  ``--bssid`` and ``--client`` - broadcast/multicast kicking is refused;
* burst sizes are hard-capped below IDS flood thresholds and spaced out so
  they can never constitute a flood;
* every frame (or would-be frame) is recorded in an owner-only (0600) audit CSV.

What this module deliberately refuses to do
-------------------------------------------
deauth/disassoc FLOODS, broadcast or wildcard kicking, AP cloning or beacon
forgery, channel jamming, replay of captured third-party frames, evil-twin
operation, or any transmission outside airspace you own or are authorised
to test. Those are attack tools, not defence tools, and they do not belong
in a sensor.
"""
from __future__ import annotations

import csv
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from .oui import is_multicast, normalize
from .privacy import secure_file
from .util import is_root, log

# ----------------------------------------------------------------- limits
# Hard ceilings. These cannot be raised from the CLI by design: a defensive
# self-test needs only a handful of frames, and staying under the IDS flood
# threshold (default 5 deauths/10s -> we allow max 4 in a burst + spacing)
# means even the test traffic itself never looks like an attack to a tuned
# sensor at the default medium sensitivity.
MAX_PROBE_PER_CHANNEL = 6
MAX_CANARY_PER_CHANNEL = 4
MAX_DEAUTH_BURST = 4              # < Watchdog.effective_flood_n (5 at medium)
MIN_FRAME_INTERVAL_S = 0.30       # floor between transmitted frames
DEFAULT_FRAME_INTERVAL_S = 0.45
DEFAULT_DWELL_S = 2.5             # listen per channel after a probe burst
PMF_BASELINE_S = 5.0             # observe client activity before the burst
PMF_VERIFY_S = 8.0              # observe after the burst for re-association
DEAUTH_REASON = 7               # Class-3 frame from non-associated STA (standard)

BROADCAST = "FF:FF:FF:FF:FF:FF"
CANARY_PREFIX = "WIFISCANNER-CANARY-"


class InjectionError(Exception):
    """Raised when a safety gate refuses an injection request."""


# ------------------------------------------------------------ frame builders

def random_local_mac() -> str:
    """A random unicast, locally-administered MAC (privacy by default).

    Probe requests sent with a rotated LAA address look identical to the
    randomized probe MACs modern OSes already use, so active scanning here
    does not add a stable hardware fingerprint to the air.
    """
    import secrets
    val = secrets.randbits(48)
    val &= ~0x010000000000        # clear I/G (multicast) bit -> unicast
    val |= 0x020000000000        # set U/L bit -> locally administered
    return ":".join(f"{(val >> (8 * i)) & 0xFF:02X}" for i in range(5, -1, -1))


def new_canary_token() -> str:
    import secrets
    return CANARY_PREFIX + secrets.token_hex(3).upper()


def build_probe_request(src_mac: str, ssid: str = ""):
    """One 802.11 probe-request frame. Empty ``ssid`` = wildcard probe."""
    from scapy.all import Dot11, Dot11ProbeReq, Dot11Elt, RadioTap
    src = normalize(src_mac)
    pkt = (RadioTap()
           / Dot11(type=0, subtype=4, addr1=BROADCAST, addr2=src,
                   addr3=BROADCAST)
           / Dot11ProbeReq())
    pkt /= Dot11Elt(ID=0, info=(ssid or "").encode("utf-8", "replace"))
    # Supported rates (1/2/5.5/11/18/24/36/54 Mbps) + extended supported
    # rates - the identical IE set a normal client probes with.
    pkt /= Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8B, 0x96,
                                      0x0C, 0x12, 0x18, 0x24]))
    pkt /= Dot11Elt(ID=50, info=bytes([0x30, 0x48, 0x60, 0x6C]))
    pkt /= Dot11Elt(ID=46, info=bytes([0x05, 0x04, 0x00, 0x04]))   # channels
    return pkt


def build_deauth(bssid: str, client: str, reason: int = DEAUTH_REASON):
    """One 802.11 deauthentication frame, AP->STA direction (PMF test only)."""
    from scapy.all import Dot11, Dot11Deauth, RadioTap
    bssid, client = normalize(bssid), normalize(client)
    return (RadioTap()
            / Dot11(type=0, subtype=12, addr1=client, addr2=bssid,
                    addr3=bssid)
            / Dot11Deauth(reason=reason))


# ------------------------------------------------------------- frame anatomy

def frame_summary(pkt) -> str:
    """One-line human description of a built/observed 802.11 frame."""
    from scapy.all import Dot11
    from scapy.layers.dot11 import Dot11Deauth, Dot11Disas
    d = pkt.getlayer(Dot11)
    if d is None:
        return "non-802.11 frame"
    t, st = int(d.type), int(d.subtype)
    if t == 0 and st == 4:
        ssid = _elt_ssid(pkt)
        return f"probe-request  {d.addr2} -> broadcast  SSID={ssid or '<wildcard>'!r}"
    if t == 0 and st == 5:
        return f"probe-response {d.addr2} -> {d.addr1}"
    if t == 0 and st in (12, 11):
        reason = getattr(pkt.getlayer(Dot11Deauth) or pkt.getlayer(Dot11Disas),
                         "reason", "?")
        kind = "deauth" if st == 12 else "disassoc"
        return f"{kind}  {d.addr2} -> {d.addr1}  reason={reason}"
    if t == 0 and st == 0:
        return f"assoc-request  {d.addr2} -> {d.addr1}"
    if t == 2:
        return f"data  {d.addr2} -> {d.addr1}"
    return f"802.11 type={t} subtype={st}  {d.addr2} -> {d.addr1}"


def _elt_ssid(pkt) -> str:
    from scapy.layers.dot11 import Dot11Elt
    el = pkt.getlayer(Dot11Elt)
    while el is not None:
        try:
            if el.ID == 0:
                return bytes(el.info).decode("utf-8", "replace").strip("\x00")
        except Exception:
            return ""
        el = el.payload.getlayer(Dot11Elt)
    return ""


# ------------------------------------------------------------------- gating

def gate_transmission(mode: str, *, transmit: bool, authorized: bool,
                      confirmed: bool = False,
                      _root: Optional[bool] = None) -> None:
    """Refuse to transmit unless every consent / privilege gate is satisfied.

    Dry runs (``transmit=False``) never touch the radio and need no root -
    they only build frames in memory so the operator can preview an action.
    """
    root = is_root() if _root is None else _root
    if not transmit:
        return
    # Consent gates first, so a non-root user is still told what explicit
    # authorization a live transmission would require.
    if not authorized:
        raise InjectionError(
            "refusing to TRANSMIT: pass --authorized to confirm you own the "
            "target network (or are authorised in writing to test it), and "
            "--transmit to leave dry-run mode.")
    if mode == "pmf-test" and not confirmed:
        raise InjectionError(
            "pmf-test sends deauthentication frames that will briefly kick "
            "the named client if PMF is NOT enabled. It requires --yes in "
            "addition to --authorized/--transmit, plus an explicit unicast "
            "--bssid (YOUR AP) and --client (YOUR test device).")
    if not root:
        raise InjectionError(
            "over-the-air injection requires root privileges (run with sudo). "
            "Re-run without --transmit for a dry run that sends nothing.")


def validate_pmf_targets(bssid: str, client: str) -> Tuple[str, str]:
    """pmf-test may only aim a unicast burst at one named AP + one named STA."""
    bssid, client = normalize(bssid or ""), normalize(client or "")
    if not bssid or not client:
        raise InjectionError(
            "pmf-test requires --bssid <your-AP-MAC> and --client <your-test-"
            "device-MAC>. A broadcast/wildcard target is refused outright.")
    for label, mac in (("bssid", bssid), ("client", client)):
        if is_multicast(mac):
            raise InjectionError(
                f"--{label} {mac} is a broadcast/multicast address. Kicking "
                "all clients is an attack, not a self-test: name ONE device.")
    return bssid, client


def clamp_count(mode: str, count: int) -> int:
    cap = {"probe": MAX_PROBE_PER_CHANNEL,
           "canary": MAX_CANARY_PER_CHANNEL,
           "pmf-test": MAX_DEAUTH_BURST}[mode]
    if count > cap:
        log.warning("requested %d frames capped to the hard safety limit of %d "
                    "for mode %s", count, cap, mode)
    return max(1, min(int(count), cap))


def parse_channels(spec: str, default: Optional[List[int]] = None) -> List[int]:
    if not spec:
        return list(default or [1, 6, 11])
    out = []
    for part in spec.split(","):
        part = part.strip()
        if part.isdigit():
            ch = int(part)
            if ch not in out:
                out.append(ch)
    return out or list(default or [1, 6, 11])


# ------------------------------------------------------------------- audit

class AuditLog:
    """Append-only CSV record of every frame considered; created 0600."""

    COLUMNS = ["ts", "time", "mode", "iface", "tx", "dry_run", "frame",
               "channel", "target", "detail"]

    def __init__(self, path: str):
        self.path = path
        self.rows: List[dict] = []
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self._exists = os.path.exists(path)
        self.fh = open(path, "a", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.fh, fieldnames=self.COLUMNS,
                                     extrasaction="ignore")
        if not self._exists or os.path.getsize(path) == 0:
            self.writer.writeheader()
        self.fh.flush()
        secure_file(path)

    def record(self, *, mode: str, iface: str, tx: bool, dry_run: bool,
               frame: str, channel: str = "", target: str = "",
               detail: str = "") -> None:
        now = time.time()
        row = {"ts": round(now, 3),
               "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
               "mode": mode, "iface": iface, "tx": int(tx),
               "dry_run": int(dry_run), "frame": frame, "channel": channel,
               "target": target, "detail": detail}
        self.rows.append(row)
        self.writer.writerow(row)
        self.fh.flush()

    def close(self) -> None:
        try:
            self.fh.close()
        except Exception:
            pass
        secure_file(self.path)


# ----------------------------------------------------------- air monitoring

@dataclass
class AirEvent:
    ts: float
    kind: str           # probe | proberesp | deauth | assoc | eapol | data
    src: str
    dst: str
    bssid: str
    rssi: Optional[int] = None
    ssid: str = ""


def classify_frame(pkt) -> Optional[AirEvent]:
    """Reduce a scapy frame to the handful of fields the injection verifiers use."""
    from scapy.all import Dot11
    if not pkt.haslayer(Dot11):
        return None
    d = pkt.getlayer(Dot11)
    t, st = int(d.type), int(d.subtype)
    a1 = normalize(d.addr1 or "")
    a2 = normalize(d.addr2 or "")
    a3 = normalize(d.addr3 or "")
    rssi = None
    try:
        rssi = int(pkt.dBm_AntSignal)
    except Exception:
        pass
    if t == 0 and st == 4:
        return AirEvent(time.time(), "probe", a2, a1, a3, rssi, _elt_ssid(pkt))
    if t == 0 and st == 5:
        return AirEvent(time.time(), "proberesp", a2, a1, a3 or a2, rssi,
                        _elt_ssid(pkt))
    if t == 0 and st in (12, 11):
        return AirEvent(time.time(), "deauth", a2, a1, a3 or a2, rssi)
    if t == 0 and st in (0, 2):
        return AirEvent(time.time(), "assoc", a2, a1, a3 or a1, rssi,
                        _elt_ssid(pkt))
    if t == 2:
        if _is_eapol(pkt, d):
            return AirEvent(time.time(), "eapol", a2, a1, a3 or a1, rssi)
        return AirEvent(time.time(), "data", a2, a1, a3 or a1, rssi)
    return None


def _is_eapol(pkt, d) -> bool:
    from scapy.all import EAPOL
    if pkt.haslayer(EAPOL):
        return True
    try:
        raw = bytes(d.payload)
        return raw[6:8] == b"\x88\x8e" and raw[:3] == b"\xaa\xaa\x03"
    except Exception:
        return False


class AirListener:
    """Background sniffer that records AirEvents (and optionally a pcap)."""

    def __init__(self, iface: str, duration: float,
                 on_packet: Optional[Callable] = None, pcap_path: str = ""):
        self.iface = iface
        self.duration = duration
        self.on_packet = on_packet
        self.pcap_path = pcap_path
        self.events: List[AirEvent] = []
        self.frames = 0
        self._th: Optional[threading.Thread] = None
        self._writer = None

    def _cb(self, pkt) -> None:
        ev = classify_frame(pkt)
        if ev is not None:
            self.events.append(ev)
            self.frames += 1
        if self._writer is not None:
            try:
                self._writer.write(pkt)
            except Exception:
                pass
        if self.on_packet is not None:
            try:
                self.on_packet(pkt)
            except Exception:
                pass

    def start(self) -> None:
        self._th = threading.Thread(target=self._run, daemon=True)
        self._th.start()

    def _run(self) -> None:
        from scapy.all import sniff, PcapWriter
        if self.pcap_path:
            self._writer = PcapWriter(self.pcap_path, sync=True)
            secure_file(self.pcap_path)
        try:
            try:
                sniff(iface=self.iface, prn=self._cb, store=False,
                      timeout=self.duration, monitor=True)
            except Exception:
                sniff(iface=self.iface, prn=self._cb, store=False,
                      timeout=self.duration)
        finally:
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception:
                    pass

    def join(self) -> None:
        if self._th is not None:
            self._th.join(timeout=self.duration + 10)


# ------------------------------------------------------------------ injector

class Injector:
    """Builds, logs and (only when authorised) transmits 802.11 frames."""

    def __init__(self, iface: str, *, mode: str, dry_run: bool = True,
                 audit: Optional[AuditLog] = None, src_mac: str = "",
                 interval: float = DEFAULT_FRAME_INTERVAL_S):
        self.iface = iface
        self.mode = mode
        self.dry_run = dry_run
        self.audit = audit
        self.src_mac = normalize(src_mac) or random_local_mac()
        self.interval = max(interval, MIN_FRAME_INTERVAL_S)
        self.sent = 0
        self.built = 0
        self._last_send = 0.0

    def _emit(self, pkt, *, frame: str, channel: str = "", target: str = "",
              detail: str = "") -> bool:
        """Log one frame; transmit it unless this is a dry run."""
        self.built += 1
        if self.audit is not None:
            self.audit.record(mode=self.mode, iface=self.iface,
                              tx=not self.dry_run, dry_run=self.dry_run,
                              frame=frame, channel=channel, target=target,
                              detail=detail)
        if self.dry_run:
            log.info("[dry-run] would send ch%s: %s",
                     channel or "-", frame_summary(pkt))
            return False
        now = time.time()
        wait = self.interval - (now - self._last_send)
        if wait > 0:
            time.sleep(wait)
        from scapy.all import sendp
        sendp(pkt, iface=self.iface, verbose=False)
        self.sent += 1
        self._last_send = time.time()
        log.debug("sent ch%s: %s", channel or "-", frame_summary(pkt))
        return True

    # ------------------------------------------------------- high-level TX

    def probe_sweep(self, channels: List[int], ssids: List[str],
                    count: int) -> None:
        for ch in channels:
            if not self.dry_run:                    # dry runs never touch the radio
                _set_channel(self.iface, ch)
            for ssid in ssids:
                for _ in range(count):
                    pkt = build_probe_request(self.src_mac, ssid)
                    self._emit(pkt, frame="probe-request", channel=str(ch),
                               target=BROADCAST,
                               detail=f"ssid={ssid or '<wildcard>'}")

    def canary_sweep(self, channels: List[int], token: str,
                     count: int) -> None:
        for ch in channels:
            if not self.dry_run:
                _set_channel(self.iface, ch)
            for _ in range(count):
                pkt = build_probe_request(self.src_mac, token)
                self._emit(pkt, frame="canary-probe", channel=str(ch),
                           target=BROADCAST, detail=f"token={token}")

    def deauth_burst(self, bssid: str, client: str, count: int) -> None:
        for _ in range(count):
            pkt = build_deauth(bssid, client)
            self._emit(pkt, frame="deauth", target=f"{bssid}->{client}",
                       detail=f"reason={DEAUTH_REASON}")


def _set_channel(iface: str, channel: int) -> bool:
    from .backends.sniffer import set_channel
    return set_channel(iface, channel)


# ------------------------------------------------------------- verifications

def pmf_verdict(events: List[AirEvent], bssid: str, client: str,
                burst_ts: float) -> dict:
    """Decide whether the bounded deauth burst actually kicked the client.

    * client keeps exchanging data and never re-associates -> forged deauths
      were IGNORED: PMF/802.11w is protecting management frames (PASS).
    * an (re)association or EAPOL from the client follows the burst -> the
      client was deauthenticated and had to rejoin: PMF is NOT enforced
      between this client and BSS (FAIL - fix the setting on both ends).
    * no client frames at all -> inconclusive (idle/asleep/off-channel).
    """
    bssid, client = normalize(bssid), normalize(client)
    before = [e for e in events
              if e.ts < burst_ts and _involves(e, bssid, client)]
    after = [e for e in events
             if e.ts >= burst_ts and _involves(e, bssid, client)]
    data_before = sum(1 for e in before if e.kind == "data")
    data_after = sum(1 for e in after if e.kind == "data")
    reauth_after = [e for e in after if e.kind in ("assoc", "eapol")]
    deauths_observed = sum(1 for e in events if e.kind == "deauth"
                           and _involves(e, bssid, client))
    if data_before == 0:
        verdict = "inconclusive"
        detail = ("no traffic from the client before the burst - it may be "
                  "idle, asleep or on another channel; repeat while it is "
                  "actively using the network")
        protected = None
    elif reauth_after:
        verdict = "fail"
        protected = False
        detail = (f"client re-associated ({len(reauth_after)} assoc/EAPOL "
                  "frame(s) after the burst): the forged deauth was "
                  "ACCEPTED. PMF/802.11w is not protecting this client - "
                  "set Management Frame Protection to REQUIRED on the AP "
                  "and the client supplicant, then re-test")
    elif data_after > 0:
        verdict = "pass"
        protected = True
        detail = (f"client kept exchanging data ({data_after} frame(s)) and "
                  "never re-associated: forged deauthentication frames were "
                  "ignored - PMF is working on this BSS")
    else:
        verdict = "inconclusive"
        protected = None
        detail = ("client was active before but silent after without a "
                  "visible re-association; extend --verify-s and re-test")
    return {"verdict": verdict, "pmf_protected": protected,
            "data_before": data_before, "data_after": data_after,
            "reauth_after": len(reauth_after),
            "deauths_observed": deauths_observed, "detail": detail}


def _involves(e: AirEvent, bssid: str, client: str) -> bool:
    return client in (e.src, e.dst) or bssid in (e.bssid, e.src, e.dst)


def canary_results(events: List[AirEvent], src_mac: str, token: str) -> dict:
    """Count canary markers heard back over the air (self-hear / co-radio)."""
    src = normalize(src_mac)
    heard = [e for e in events
             if e.kind == "probe" and (normalize(e.src) == src
                                       or e.ssid == token)]
    rssis = [e.rssi for e in heard if e.rssi is not None]
    return {"token": token, "heard": len(heard),
            "rssi_dbm": (max(rssis) if rssis else None),
            "note": ("markers heard on this radio; remote sensors must each "
                     "be checked with `ids`/`capture`/`traffic` and grepped "
                     f"for token {token}")}


# --------------------------------------------------------- IDS self-test

def ids_selftest_scenarios():
    """(name, [frames], expected_alert_kinds) synthesised entirely offline."""
    from scapy.all import Dot11, RadioTap
    from scapy.layers.dot11 import (Dot11AssoReq, Dot11Beacon, Dot11Deauth,
                                    Dot11Elt)
    ap, sta = "F0:9F:C2:11:22:34", "AC:BC:32:01:02:99"

    def deauth():
        return (RadioTap() / Dot11(type=0, subtype=12, addr1=sta,
                                   addr2=ap, addr3=ap)
                / Dot11Deauth(reason=7))

    def assoc():
        return (RadioTap() / Dot11(type=0, subtype=0, addr1=ap, addr2=sta,
                                   addr3=ap) / Dot11AssoReq()
                / Dot11Elt(ID=0, info=b"OwnNet"))

    def eapol():
        key = b"\x02\x03\x00\x5d\x02\x01\x8a\x00\x10" + b"\x00" * 80
        return (RadioTap() / Dot11(type=2, subtype=8, FCfield=["to_DS"],
                                   addr1=ap, addr2=sta, addr3=ap)
                / (b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + key))

    def beacon(channel=6, rsn=True):
        p = (RadioTap() / Dot11(type=0, subtype=8,
                                addr1="ff:ff:ff:ff:ff:ff", addr2=ap,
                                addr3=ap)
             / Dot11Beacon(cap=0x1111 if rsn else 0x0001))
        p /= Dot11Elt(ID=0, info=b"OwnNet")
        p /= Dot11Elt(ID=3, info=bytes([channel]))
        if rsn:
            p /= Dot11Elt(ID=48,
                          info=bytes.fromhex("0100000fac040100000fac040100000"
                                             "fac020c00"))
        return p

    rogue_ap = "12:34:56:78:9A:BC"
    rogue = (RadioTap() / Dot11(type=0, subtype=8,
                                addr1="ff:ff:ff:ff:ff:ff", addr2=rogue_ap,
                                addr3=rogue_ap)
             / Dot11Beacon(cap=0x0001) / Dot11Elt(ID=0, info=b"OwnNet"))

    return [
        ("deauth-flood detection",
         [deauth() for _ in range(6)],
         {"deauth-flood"}),
        ("forced-reauth / handshake-harvest chain",
         [assoc(), eapol()],
         {"forced-reauth", "handshake-harvest-signature"}),
        ("beacon-mutation persistence",
         [beacon(6, rsn=True)] + [beacon(11, rsn=False) for _ in range(3)],
         {"beacon-mutation"}),
        ("unknown-bss warden",
         [rogue],
         {"unknown-bss"}),
    ], ap


def run_ids_selftest(write_pcap: str = "") -> dict:
    """Feed every synthetic attack signature to the Watchdog; report fires.

    No root, no radio, no hardware - safe in CI and on locked-down hosts.
    """
    from .defense import Watchdog
    scenarios, own_ap = ids_selftest_scenarios()
    wd = Watchdog(window_s=60, cooldown_s=0, flood_frames=5,
                  sensitivity="medium", known_bssids={own_ap})
    all_frames = []
    rows = []
    for name, frames, expected in scenarios:
        for pkt in frames:
            wd.feed(pkt)
        all_frames.extend(frames)
        fired = {a.kind for a in wd.alerts}
        missing = expected - fired
        ok = not missing
        rows.append({"scenario": name,
                     "expected": "|".join(sorted(expected)),
                     "fired": "|".join(sorted(expected & fired)),
                     "missing": "|".join(sorted(missing)),
                     "status": "PASS" if ok else "FAIL"})
    if write_pcap:
        from scapy.all import wrpcap
        d = os.path.dirname(os.path.abspath(write_pcap))
        os.makedirs(d, exist_ok=True)
        wrpcap(write_pcap, all_frames)
        secure_file(write_pcap)
    return {"rows": rows,
            "passed": sum(1 for r in rows if r["status"] == "PASS"),
            "total": len(rows),
            "frames": len(all_frames),
            "alerts": len(wd.alerts),
            "own_bssid": own_ap}
