"""wifiscanner command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__, inject as ij
from .backends import lan, sniffer, survey
from .display import (print_banner, print_congestion, print_detail,
                      print_devices, print_networks, print_rogues,
                      print_summary, print_rows, console, _RICH)
from .engine import Engine
from .export import export_all
from .locate import Tracker, ascii_map, load_sensors, load_zones
from .defense import Watchdog, audit_ap, audit_engine
from .oui import db_size, normalize
from .store import Store, parse_when
from .util import is_root, log, os_name, setup_logging

LEGAL = (
    "SCOPE: passive, defensive, own-network-first. Every survey, IDS, audit "
    "and history feature only listens to what is broadcast in public "
    "airspace and reads YOUR OWN router's association table. The single "
    "exception is `inject`, which can transmit - but only as an explicit, "
    "opt-in, AUTHORIZED self-test of your own defences (IDS sensor canaries, "
    "active probe scanning, a bounded own-AP PMF/deauth-resistance check). "
    "It defaults to a DRY RUN (nothing emitted), needs root plus --authorized "
    "(--yes for deauth frames), is hard rate-capped below attack thresholds, "
    "refuses broadcast/third-party targets, and logs every frame. It contains "
    "no flood, AP-clone, jam, key-crack or decrypt capability. Continuous "
    "history recording is restricted to your own network. Use transmission "
    "only on infrastructure you own or are authorised in writing to test."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wifiscanner",
        description="Advanced passive Wi-Fi survey, client-attribution and CSV export engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  wifiscanner scan                          quick survey of nearby networks
  wifiscanner scan -o out --format csv json html
  wifiscanner monitor -i wlan0 -d 120       count devices per AP (root, passive)
  wifiscanner own                           full client census of YOUR network
  wifiscanner record --db home.sqlite       keep presence history of your AP
  wifiscanner presence --db home.sqlite --since -24h
  wifiscanner locate --db home.sqlite --sensors sensors.csv
  wifiscanner trail --db home.sqlite --sensors sensors.csv --zones zones.csv \
      --mac AC:BC:32:01:02:03
  wifiscanner capture -i wlan0 -d 3600 --ring-segments 8 --rotate-mb 64
  wifiscanner traffic capture.pcap -o out   dissect unencrypted frames
  wifiscanner offline capture.pcap          analyse an existing capture
  wifiscanner ids -i wlan0 --pcap hour.pcap  passive IDS: deauth floods,
                                              handshake-harvest signatures,
                                              beacon mutations, rogue BSSIDs
  wifiscanner audit                           hardening report for YOUR network
  wifiscanner frames capture.pcap             802.11 frame-by-frame anatomy
                                              (how all of this works)
  wifiscanner inject --mode ids-selftest      offline test: does MY IDS detect
                                              deauth/beacon/warden signatures?
  wifiscanner inject --mode canary -i wlan0   dry run by default: preview the
      --channels 1,6,11                          probe markers, add --transmit
                                              --authorized to actually emit
  wifiscanner inject --mode pmf-test -i wlan0 -c 6 --bssid MY-AP \\
      --client MY-test-laptop --transmit --authorized --yes
  wifiscanner inject --mode deauth -i wlan0 -c 6 --frame-type both \\
      --bssid MY-AP --client MY-test-laptop --count 10 --transmit \\
      --authorized --yes        # bounded, unicast, audited kick TEST
  wifiscanner interfaces                    list wireless adapters
""")
    p.add_argument("--version", action="version", version=f"wifiscanner {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-banner", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-i", "--interface", default="", help="wireless interface")
        sp.add_argument("-o", "--output", default="", metavar="DIR",
                        help="export directory (enables CSV export)")
        sp.add_argument("--prefix", default="", help="output filename prefix")
        sp.add_argument("--format", nargs="+", default=["csv", "json"],
                        choices=["csv", "json", "html", "md"])
        sp.add_argument("--sort", default="rssi",
                        choices=["rssi", "clients", "ssid", "channel", "security"])
        sp.add_argument("--limit", type=int, default=0)
        sp.add_argument("--db", default="", metavar="SQLITE",
                        help="also persist this scan into a history database")
        sp.add_argument("--sensor", default="", metavar="NAME",
                        help="tag stored rows with this sensor id (multi-AP setups)")
        sp.add_argument("--retain-days", type=float, default=90.0,
                        help="history retention for --db (0 = keep forever, "
                             "not recommended)")
        sp.add_argument("--privacy-mode", default="standard",
                        choices=["standard", "minimal", "ephemeral"],
                        help="minimal = pseudonymised MACs, no hostnames/probes; "
                             "ephemeral = refuse all persistence")
        sp.add_argument("--anonymize", action="store_true",
                        help="pseudonymise client MACs in exports (salted, "
                             "per-export, unlinkable)")
        return sp

    s = common(sub.add_parser("scan", help="survey nearby access points"))
    s.add_argument("--backend", default="auto",
                   choices=["auto", "nmcli", "iw", "iwlist", "airport", "netsh"])
    s.add_argument("--no-rescan", action="store_true")

    m = common(sub.add_parser("monitor", help="passively count devices per AP (root)"))
    m.add_argument("-d", "--duration", type=float, default=60.0)
    m.add_argument("-c", "--channels", default="",
                   help="comma list, e.g. 1,6,11 (default: hop all)")
    m.add_argument("--bands", nargs="+", default=["2.4GHz", "5GHz"],
                   choices=["2.4GHz", "5GHz", "6GHz"])
    m.add_argument("--bssid", default="", help="lock onto one AP")
    m.add_argument("--hop-interval", type=float, default=0.35)
    m.add_argument("--airmon", action="store_true", help="use airmon-ng")
    m.add_argument("--no-monitor-setup", action="store_true",
                   help="interface is already in monitor mode")
    m.add_argument("--write-pcap", default="", metavar="FILE")

    f = common(sub.add_parser("full", help="scan + monitor + LAN inventory + export"))
    f.add_argument("-d", "--duration", type=float, default=60.0)
    f.add_argument("--bands", nargs="+", default=["2.4GHz", "5GHz"])
    f.add_argument("--airmon", action="store_true")
    f.add_argument("--no-monitor-setup", action="store_true")
    f.add_argument("--lan", action="store_true", help="also inventory current LAN")
    f.add_argument("--ports", action="store_true")

    d = common(sub.add_parser("detail", help="A-to-Z detail for a network"))
    d.add_argument("target", help="SSID or BSSID (substring ok)")
    d.add_argument("-d", "--duration", type=float, default=45.0,
                   help="monitor seconds to enumerate its clients (root)")
    d.add_argument("--no-monitor", action="store_true")
    d.add_argument("--airmon", action="store_true")
    d.add_argument("--no-monitor-setup", action="store_true")

    dv = common(sub.add_parser("devices", help="list detected client devices"))
    dv.add_argument("-d", "--duration", type=float, default=60.0)
    dv.add_argument("--lan", action="store_true", help="scan the LAN you are joined to")
    dv.add_argument("--subnet", default="", help="e.g. 192.168.1.0/24")
    dv.add_argument("--ports", action="store_true", help="port-scan LAN devices")
    dv.add_argument("--no-monitor", action="store_true")
    dv.add_argument("--airmon", action="store_true")
    dv.add_argument("--no-monitor-setup", action="store_true")

    w = common(sub.add_parser("watch", help="live refreshing dashboard"))
    w.add_argument("-n", "--interval", type=float, default=8.0)
    w.add_argument("--monitor", action="store_true", help="add monitor-mode capture")
    w.add_argument("--airmon", action="store_true")
    w.add_argument("--no-monitor-setup", action="store_true")

    off = common(sub.add_parser("offline", help="analyse an existing pcap"))
    off.add_argument("pcap")

    ow = common(sub.add_parser(
        "own", help="authoritative client census of YOUR OWN network/AP"))
    ow.add_argument("-d", "--duration", type=float, default=25.0)
    ow.add_argument("--no-lan", action="store_true",
                    help="skip the active LAN sweep (ARP/DNS/ports)")
    ow.add_argument("--ports", action="store_true", help="port-scan your LAN hosts")
    ow.add_argument("--no-monitor", action="store_true")
    ow.add_argument("--airmon", action="store_true")
    ow.add_argument("--no-monitor-setup", action="store_true")

    rec = sub.add_parser("record", help="continuously record YOUR network's "
                                        "presence history to SQLite")
    rec.add_argument("--db", default="presence.sqlite", metavar="SQLITE")
    rec.add_argument("-i", "--interface", default="")
    rec.add_argument("--bssid", default="",
                     help="AP to record (comma-separated list). Default: your own "
                          "current connection. Refuses open-ended bystander logging.")
    rec.add_argument("--sensor", default="", help="sensor id for multi-AP lateration")
    rec.add_argument("-n", "--interval", type=float, default=30.0,
                     help="seconds between snapshots")
    rec.add_argument("-d", "--duration", type=float, default=0.0,
                     help="total seconds (0 = run until Ctrl-C)")
    rec.add_argument("--lan", action="store_true",
                     help="enrich with ARP/DNS/ports (hostnames, IPs)")
    rec.add_argument("--backend", default="auto",
                     choices=["auto", "nmcli", "iw", "iwlist", "airport", "netsh"])
    rec.add_argument("--pcap", default="",
                     help="one-shot: import an existing capture into the DB and exit")
    rec.add_argument("--retain-days", type=float, default=90.0,
                     help="history retention in days (0 = keep forever, "
                          "not recommended)")
    rec.add_argument("--privacy-mode", default="standard",
                     choices=["standard", "minimal", "ephemeral"],
                     help="minimal = pseudonymised MACs, no hostnames; "
                          "ephemeral = refuse to persist")
    rec.add_argument("--anonymize", action="store_true",
                     help="store salted MAC pseudonyms instead of real MACs")

    pr = sub.add_parser("presence", help="query presence history: who was on, when")
    pr.add_argument("--db", default="presence.sqlite")
    pr.add_argument("--mac", default="")
    pr.add_argument("--ssid", default="")
    pr.add_argument("--since", default="", help="'-24h', '2026-09-07', '18:00'")
    pr.add_argument("--until", default="")
    pr.add_argument("--gap", type=float, default=300.0,
                    help="seconds of absence that ends a session")
    pr.add_argument("--known", action="store_true", help="show device roster instead")
    pr.add_argument("-o", "--output", default="", help="also export session CSV here")
    pr.add_argument("--limit", type=int, default=100)

    loc = sub.add_parser("locate", help="estimate device positions from multiple "
                                        "sensors (trilateration + zone dwell)")
    loc.add_argument("--db", default="presence.sqlite")
    loc.add_argument("--sensors", required=True,
                     help="CSV: name,x,y[,floor,rssi_offset_db,tx_power_dbm] (metres)")
    loc.add_argument("--zones", default="", help="CSV: zone,x,y polygon vertices")
    loc.add_argument("--mac", default="")
    loc.add_argument("--window", type=float, default=3.0,
                     help="seconds to fuse readings across sensors")
    loc.add_argument("--n-exp", type=float, default=2.7,
                     help="path-loss exponent (2 free-space, 2.7 indoor, 3.5 dense)")
    loc.add_argument("--since", default="")
    loc.add_argument("--until", default="")
    loc.add_argument("--recompute", action="store_true",
                     help="re-derive fixes and store them back into the DB")
    loc.add_argument("--live", action="store_true",
                     help="also do a short live capture first")
    loc.add_argument("-d", "--duration", type=float, default=20.0)
    loc.add_argument("-i", "--interface", default="")
    loc.add_argument("--airmon", action="store_true")
    loc.add_argument("--no-monitor-setup", action="store_true")

    tr = sub.add_parser("trail", help="reconstruct a device's movement path "
                                      "across YOUR sensor grid")
    tr.add_argument("--mac", required=True)
    tr.add_argument("--db", default="presence.sqlite")
    tr.add_argument("--sensors", default="")
    tr.add_argument("--zones", default="")
    tr.add_argument("--window", type=float, default=3.0)
    tr.add_argument("--since", default="")
    tr.add_argument("--until", default="")
    tr.add_argument("--map", action="store_true", help="ASCII movement map")
    tr.add_argument("-o", "--output", default="")

    cap = sub.add_parser("capture", help="raw 802.11 frame capture to pcap "
                                        "(ring buffer, rotation; passive)")
    cap.add_argument("-i", "--interface", default="")
    cap.add_argument("-d", "--duration", type=float, default=300.0)
    cap.add_argument("-c", "--channels", default="")
    cap.add_argument("--bands", nargs="+", default=["2.4GHz", "5GHz"],
                     choices=["2.4GHz", "5GHz", "6GHz"])
    cap.add_argument("--bssid", default="")
    cap.add_argument("--hop-interval", type=float, default=0.35)
    cap.add_argument("-o", "--pcap", default="capture.pcap", metavar="FILE")
    cap.add_argument("--rotate-mb", type=float, default=0.0,
                     help="start a new file after N MB")
    cap.add_argument("--ring-segments", type=int, default=0,
                     help="keep only N segment files (bounded ring buffer)")
    cap.add_argument("--analyze", action="store_true",
                     help="also parse the capture into AP/client tables at exit")
    cap.add_argument("--ack-sensitive", action="store_true",
                     help="acknowledge that raw captures contain sensitive "
                          "third-party data (silences the warning)")
    cap.add_argument("--strip-payloads", action="store_true",
                     help="privacy-preserving capture: truncate frames to 128 "
                          "bytes (headers for counting/IDS, no payloads)")
    cap.add_argument("--max-age-days", type=float, default=0.0,
                     help="delete capture segments older than N days on exit "
                          "(0 = keep)")
    cap.add_argument("--airmon", action="store_true")
    cap.add_argument("--no-monitor-setup", action="store_true")

    trf = sub.add_parser("traffic", help="dissect UNENCRYPTED frames from a "
                                        "capture or live monitor interface")
    trf.add_argument("pcap", nargs="?", default="",
                     help="capture file to dissect (omit with --live)")
    trf.add_argument("--live", action="store_true",
                     help="live dissection (root; monitor interface)")
    trf.add_argument("-i", "--interface", default="")
    trf.add_argument("-d", "--duration", type=float, default=30.0)
    trf.add_argument("--max-frames", type=int, default=200000)
    trf.add_argument("--limit", type=int, default=40)
    trf.add_argument("-o", "--output", default="", help="export events/flows CSV here")
    trf.add_argument("--prefix", default="traffic")
    trf.add_argument("--no-redact", action="store_true",
                     help="disable URL/User-Agent redaction (NOT recommended; "
                          "logs sensitive cleartext verbatim)")
    trf.add_argument("--anonymize-ips", action="store_true",
                     help="mask IPs to /24 in events/flows (for shared reports)")
    trf.add_argument("--airmon", action="store_true")
    trf.add_argument("--no-monitor-setup", action="store_true")

    ids = sub.add_parser("ids", help="passive wireless IDS: detect deauth "
                       "floods, handshake-harvest attempts, beacon mutation, "
                       "and unapproved BSSIDs. Detection only - it never "
                       "attacks back, because that is not what defence needs.")
    ids.add_argument("-i", "--interface", default="")
    ids.add_argument("-d", "--duration", type=float, default=60.0)
    ids.add_argument("--pcap", default="", help="analyse an existing capture instead")
    ids.add_argument("--window", type=float, default=10.0, help="anomaly window (s)")
    ids.add_argument("--flood", type=int, default=5, help="mgmt frames in window that count as flood")
    ids.add_argument("--sensitivity", default="medium",
                     choices=["low", "medium", "high"],
                     help="low = fewer, surer alerts (2x threshold); "
                          "high = more, noisier alerts")
    ids.add_argument("--db", default="", help="warden baseline sqlite (learn/unknown BSSIDs)")
    ids.add_argument("--learn", action="store_true", help="save current APs as known-good baseline")
    ids.add_argument("--airmon", action="store_true")
    ids.add_argument("--no-monitor-setup", action="store_true")
    ids.add_argument("-o", "--output", default="", help="export alerts CSV here")
    ids.add_argument("--follow", action="store_true", help="print alerts live as they fire")

    aud = sub.add_parser("audit", help="defensive hardening audit of your own "
                         "network: every weakness -> the attack it exposes -> "
                         "the setting that defeats it")
    aud.add_argument("--ssid", default="", help="audit only networks matching this")
    aud.add_argument("--pcap", default="", help="audit from a capture file")
    aud.add_argument("-i", "--interface", default="")
    aud.add_argument("-o", "--output", default="", help="write markdown report here")

    fr = sub.add_parser("frames", help="802.11 frame anatomy: annotated, "
                        "educational dissection of every frame in a capture")
    fr.add_argument("pcap")
    fr.add_argument("--limit", type=int, default=20)
    fr.add_argument("--filter", default="",
                    help="beacon|probe-req|assoc-req|deauth|disassoc|data|handshake")
    fr.add_argument("--handshakes", action="store_true",
                    help="just summarise EAPOL/deauth activity (counts only)")

    inj = sub.add_parser("inject", help="AUTHORIZED transmission for defensive "
                         "self-test only: IDS canaries, active probe scan, a "
                         "bounded own-AP PMF/deauth-resistance test, and an "
                         "explicit unicast deauth/disassoc TEST. Dry run by "
                         "default; needs root + --authorized (+--yes for kick "
                         "modes). Broadcast/wildcard/third-party targets refused.")
    inj.add_argument("-i", "--interface", default="", help="wireless interface")
    inj.add_argument("--mode", default="probe",
                     choices=["probe", "canary", "pmf-test", "deauth",
                              "ids-selftest"],
                     help="probe = active survey; canary = IDS/sensor coverage "
                          "marker; pmf-test = small burst to verify YOUR AP "
                          "enforces PMF; deauth = explicit bounded unicast "
                          "deauth/disassoc TEST of YOUR own client (pen-test); "
                          "ids-selftest = offline, zero-RF IDS signature check")
    inj.add_argument("-c", "--channels", default="",
                     help="comma list, e.g. 1,6,11 (kick modes: the AP channel)")
    inj.add_argument("--ssid", default="",
                     help="probe mode: directed probe for this SSID (default: "
                          "wildcard broadcast probe, like normal client scans)")
    inj.add_argument("--bssid", default="",
                     help="kick modes (pmf-test/deauth): YOUR AP's BSSID "
                          "(unicast, required)")
    inj.add_argument("--client", default="",
                     help="kick modes: YOUR own test device's MAC (unicast, "
                          "required; broadcast/multicast targets are refused)")
    inj.add_argument("--frame-type", default="deauth", dest="frame_type",
                     choices=["deauth", "disassoc", "both"],
                     help="deauth mode: which disconnect frame to send "
                          "(both alternates deauth+disassoc)")
    inj.add_argument("--direction", default="ap-to-sta",
                     choices=["ap-to-sta", "sta-to-ap"],
                     help="deauth mode: spoofed direction (ap-to-sta is the "
                          "classic client kick; sta-to-ap drops it AP-side)")
    inj.add_argument("--count", type=int, default=2,
                     help="frames per channel (probe/canary) or kick burst size "
                          "(pmf-test/deauth); hard-capped per mode for safety")
    inj.add_argument("--dwell", type=float, default=0.0,
                     help="seconds to listen on each channel after a burst "
                          "(0 = sensible default per mode)")
    inj.add_argument("--baseline-s", type=float, default=5.0,
                     help="pmf-test: observe client activity before the burst")
    inj.add_argument("--verify-s", type=float, default=8.0,
                     help="pmf-test: observe for re-association after the burst")
    inj.add_argument("--token", default="", help="canary: marker SSID (auto if "
                                                 "blank; grep this in sensor logs)")
    inj.add_argument("--src-mac", default="",
                     help="source MAC (default: random locally-administered)")
    inj.add_argument("--transmit", action="store_true",
                     help="actually emit frames over the air (WITHOUT this flag "
                          "the command is a dry run that only builds/displays)")
    inj.add_argument("--authorized", action="store_true",
                     help="assert you own the target network / hold written "
                          "authorization to test it (required with --transmit)")
    inj.add_argument("--yes", action="store_true",
                     help="required for kick modes (pmf-test, deauth): "
                          "acknowledge the named client will be disconnected "
                          "if management-frame protection is not enforced")
    inj.add_argument("--airmon", action="store_true")
    inj.add_argument("--no-monitor-setup", action="store_true")
    inj.add_argument("--audit-log", default="",
                     help="CSV audit trail of every frame (default: "
                          "<output>/injection_audit.csv); always written 0600")
    inj.add_argument("--write-pcap", default="",
                     help="also record the verification window to a pcap")
    inj.add_argument("-o", "--output", default="output", metavar="DIR",
                     help="directory for the audit log / pcap (default: ./output)")

    dbp = sub.add_parser("db", help="history-database maintenance: retention, "
                         "anonymization, deletion (privacy controls)")
    dbp.add_argument("--db", default="presence.sqlite", metavar="SQLITE")
    dbp.add_argument("--report", action="store_true",
                     help="show permissions/size/retention/tables report")
    dbp.add_argument("--prune-days", type=float, default=0.0,
                     help="delete rows older than N days, then vacuum")
    dbp.add_argument("--delete-mac", default="",
                     help="erase every row for one device MAC (or pseudonym)")
    dbp.add_argument("--anonymize-db", action="store_true",
                     help="IRREVERSIBLY pseudonymise stored MACs + drop IPs/ "
                          "hostnames (no undo)")
    dbp.add_argument("--purge", action="store_true",
                     help="delete ALL history rows (keeps warden baseline)")
    dbp.add_argument("--vacuum", action="store_true",
                     help="reclaim space after deletions")
    dbp.add_argument("--yes", action="store_true",
                     help="confirm destructive actions (required)")

    sub.add_parser("interfaces", help="list wireless interfaces and capabilities")
    return p


# ------------------------------------------------------------------ helpers

def _do_survey(args) -> Engine:
    eng = Engine()
    backend = getattr(args, "backend", "auto")
    rescan = not getattr(args, "no_rescan", False)
    log.info("scanning for access points (%s)...", backend)
    aps = survey.survey_networks(args.interface, backend, rescan)
    eng.ingest(aps)
    log.info("discovered %d access points", len(eng.aps))
    return eng


def _do_monitor(args, eng: Engine, duration: float, bssid: str = "") -> Engine:
    if not sniffer.scapy_available():
        log.error("scapy is not installed - monitor mode unavailable. "
                  "Install with:  pip install scapy")
        return eng
    iface = args.interface
    if not iface:
        ifaces = survey.list_interfaces()
        if not ifaces:
            log.error("no wireless interface found; specify one with -i")
            return eng
        iface = ifaces[0]["name"]
        log.info("using interface %s", iface)
    if not is_root() and not getattr(args, "no_monitor_setup", False):
        log.error("monitor mode requires root. Re-run with sudo, or pass "
                  "--no-monitor-setup if %s is already in monitor mode.", iface)
        return eng
    channels = None
    if getattr(args, "channels", ""):
        channels = [int(c) for c in args.channels.split(",") if c.strip()]
    # Lock to the target AP's channel when we already know it.
    if bssid and not channels:
        ap = eng.aps.get(normalize(bssid))
        if ap and ap.channel:
            channels = [ap.channel]
            log.info("locking to channel %d for %s", ap.channel, bssid)

    def _run(mon_iface: str) -> None:
        sn = sniffer.MonitorSniffer(
            mon_iface, channels=channels,
            hop_interval=getattr(args, "hop_interval", 0.35),
            bands=tuple(getattr(args, "bands", ("2.4GHz", "5GHz"))),
            lock_bssid=bssid)
        sn.run(duration, pcap_out=getattr(args, "write_pcap", ""))
        eng.ingest(sn.results())
        eng.ingest_unassociated(sn.unassociated)
        eng.sniffer_stats = sn.stats()
        log.info("capture stats: %s", eng.sniffer_stats)

    if getattr(args, "no_monitor_setup", False):
        _run(iface)
    else:
        with sniffer.MonitorMode(iface, use_airmon=getattr(args, "airmon", False)) as mon:
            _run(mon)
    return eng


def _export(args, eng: Engine) -> None:
    if not args.output:
        return
    files = export_all(eng, args.output, args.prefix, tuple(args.format),
                       anonymize=getattr(args, "anonymize", False))
    msg = "\n".join(f"  -> {f}" for f in files)
    anon = " (anonymized: salted pseudonyms, no hostnames/IPs/probes)" \
        if getattr(args, "anonymize", False) else " (owner-only permissions)"
    print(f"\nExported {len(files)} file(s){anon}:\n{msg}")


def _maybe_store(args, eng: Engine, mode: str = "scan") -> None:
    db = getattr(args, "db", "")
    if not db:
        return
    try:
        st = Store(db, retention_days=getattr(args, "retain_days", 90.0),
                   privacy_mode=getattr(args, "privacy_mode", "standard"),
                   anonymize=getattr(args, "anonymize", False))
    except PermissionError as exc:
        log.error("%s", exc)
        return
    try:
        sid = st.record_engine(eng, mode=mode, sensor=getattr(args, "sensor", ""))
        print(f"persisted scan {sid} -> {db}")
    finally:
        st.close()


def _fmt_ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"


# ----------------------------------------------------------------- commands

def cmd_scan(args) -> int:
    eng = _do_survey(args)
    print_networks(eng, args.sort, args.limit)
    print_congestion(eng)
    print_rogues(eng)
    print_summary(eng)
    _maybe_store(args, eng, "scan")
    _export(args, eng)
    return 0


def cmd_monitor(args) -> int:
    eng = _do_survey(args)
    _do_monitor(args, eng, args.duration, args.bssid)
    print_networks(eng, "clients" if not args.sort else args.sort, args.limit)
    print_devices(eng, args.limit)
    print_rogues(eng)
    print_summary(eng)
    _maybe_store(args, eng, "monitor")
    _export(args, eng)
    return 0


def cmd_full(args) -> int:
    eng = _do_survey(args)
    _do_monitor(args, eng, args.duration)
    if args.lan:
        eng.connection = lan.current_connection()
        eng.ingest_lan(lan.lan_inventory(do_ports=args.ports),
                       bssid_hint=eng.connection.get("bssid", ""))
    print_networks(eng, args.sort, args.limit)
    print_devices(eng, args.limit)
    print_congestion(eng)
    print_rogues(eng)
    print_summary(eng)
    if not args.output:
        args.output = "output"
    if "html" not in args.format:
        args.format = list(args.format) + ["html"]
    _maybe_store(args, eng, "full")
    _export(args, eng)
    return 0


def cmd_detail(args) -> int:
    eng = _do_survey(args)
    matches = eng.find(args.target)
    if not matches:
        log.error("no network matching %r (found %d networks)", args.target, len(eng.aps))
        return 1
    if len(matches) > 1:
        log.info("%d BSSIDs match %r", len(matches), args.target)
    if not args.no_monitor and is_root() and sniffer.scapy_available():
        _do_monitor(args, eng, args.duration, matches[0].bssid)
        matches = eng.find(args.target)
    elif not args.no_monitor:
        log.warning("client enumeration skipped (needs root + scapy); "
                    "showing beacon-derived detail only")
    for ap in matches:
        print_detail(ap)
    _export(args, eng)
    return 0


def cmd_devices(args) -> int:
    eng = _do_survey(args)
    if not args.no_monitor and is_root() and sniffer.scapy_available():
        _do_monitor(args, eng, args.duration)
    if args.lan:
        eng.connection = lan.current_connection()
        stations = lan.lan_inventory(args.subnet, do_ports=args.ports)
        eng.ingest_lan(stations, bssid_hint=eng.connection.get("bssid", ""))
    print_devices(eng, args.limit)
    print_summary(eng)
    _maybe_store(args, eng, "devices")
    _export(args, eng)
    return 0


def cmd_watch(args) -> int:
    eng = Engine()
    try:
        while True:
            fresh = _do_survey(args)
            eng.ingest(list(fresh.aps.values()))
            if args.monitor and is_root() and sniffer.scapy_available():
                _do_monitor(args, eng, max(3.0, args.interval - 1))
            os.system("cls" if os_name() == "windows" else "clear")
            if not args.no_banner:
                print_banner()
            print_networks(eng, args.sort, args.limit)
            print_devices(eng, args.limit)
            print_summary(eng)
            print(f"\nrefreshing every {args.interval}s - Ctrl-C to stop and export")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")
    _export(args, eng)
    return 0


def cmd_offline(args) -> int:
    if not sniffer.scapy_available():
        log.error("scapy required for pcap analysis:  pip install scapy")
        return 2
    if not os.path.exists(args.pcap):
        log.error("no such file: %s", args.pcap)
        return 2
    eng = Engine()
    sn = sniffer.MonitorSniffer(iface="offline")
    sn.read_pcap(args.pcap)
    eng.ingest(sn.results())
    eng.ingest_unassociated(sn.unassociated)
    eng.sniffer_stats = sn.stats()
    print_networks(eng, args.sort, args.limit)
    print_devices(eng, args.limit)
    print_congestion(eng)
    print_rogues(eng)
    print_summary(eng)
    _maybe_store(args, eng, "offline")
    _export(args, eng)
    return 0


# ------------------------------------------------------- own-network suite

def cmd_own(args) -> int:
    """Client census of the network you own/are connected to."""
    conn = lan.current_connection()
    my_bssid = conn.get("bssid", "") or ""
    eng = Engine()
    print_rows("Your connection", [
        ("SSID", "ssid"), ("BSSID", "bssid"), ("Channel", "channel"),
        ("Rate", "rate"), ("Signal", "signal"), ("Security", "security"),
        ("Gateway", "gateway"), ("Subnet", "subnet")],
        [dict(conn)])

    ap_clients = lan.own_ap_clients(args.interface)
    if ap_clients:
        log.info("own AP association table supplied %d clients", len(ap_clients))

    eng.ingest(survey.survey_networks(args.interface, "auto", False))
    if not my_bssid:
        for b, a in eng.aps.items():
            if a.client_count:
                my_bssid = b
                break

    if not args.no_monitor and my_bssid and is_root() and sniffer.scapy_available():
        _do_monitor(args, eng, args.duration, my_bssid)
    elif not args.no_monitor:
        log.info("over-the-air census skipped (needs root+scapy) - using "
                 "association table + LAN sweep")

    if not args.no_lan:
        eng.ingest_lan(lan.lan_inventory(do_ports=args.ports),
                       bssid_hint=my_bssid)
    if ap_clients:
        # The AP's own kernel table is ground truth: router-CONFIRMED.
        eng.ingest_lan(ap_clients, bssid_hint=my_bssid, authoritative=True)
        print(f"router association table confirmed "
              f"{len(ap_clients)} client(s) — these counts are fact, "
              f"everything else RF-observed is an estimate")

    ap = eng.aps.get(normalize(my_bssid)) if my_bssid else None
    if ap:
        print_detail(ap)
    else:
        log.info("no AP record for your connection - showing devices instead")
        print_devices(eng)
    print_summary(eng)
    _maybe_store(args, eng, "own")
    _export(args, eng)
    return 0


def cmd_record(args) -> int:
    """Continuous presence recorder, scoped to your own network(s) only."""
    try:
        st0 = Store(args.db, retention_days=args.retain_days,
                    privacy_mode=args.privacy_mode,
                    anonymize=args.anonymize)
        st0.close()
    except PermissionError as exc:
        log.error("%s", exc)
        return 2
    if args.pcap:
        if not sniffer.scapy_available():
            log.error("scapy required for pcap import")
            return 2
        eng = Engine()
        sn = sniffer.MonitorSniffer(iface="offline")
        sn.read_pcap(args.pcap)
        eng.ingest(sn.results())
        st = Store(args.db, retention_days=args.retain_days,
                   privacy_mode=args.privacy_mode,
                   anonymize=args.anonymize)
        try:
            sid = st.record_engine(eng, mode="pcap-import", sensor=args.sensor)
            print(f"imported {args.pcap} into {args.db} as scan {sid}")
        finally:
            st.close()
        return 0

    wanted = {normalize(b) for b in args.bssid.split(",") if b.strip()}
    if not wanted:
        conn = lan.current_connection()
        if conn.get("bssid"):
            wanted = {normalize(conn["bssid"])}
            print(f"recording your current connection: SSID={conn.get('ssid', '?')} "
                  f"BSSID={conn['bssid']}")
    if not wanted:
        log.error("record needs an explicit own-network target: pass --bssid "
                  "AA:BB:... or be connected to your Wi-Fi. Indefinitely "
                  "logging every nearby device is not a feature of this tool; "
                  "use `scan`/`monitor` for ephemeral surveys.")
        return 2

    st = Store(args.db, retention_days=args.retain_days,
               privacy_mode=args.privacy_mode,
               anonymize=args.anonymize)
    if args.retain_days:
        print(f"retention: rows older than {args.retain_days:g} days are "
              f"pruned automatically")
    else:
        print("retention DISABLED (rows kept forever) — not recommended; "
              "see `db --prune-days`")
    if st.anonymize:
        print("privacy: storing salted MAC pseudonyms, no hostnames/IPs")
    t_end = time.time() + args.duration if args.duration else 0.0
    n = 0
    try:
        while True:
            t0 = time.time()
            eng = Engine()
            try:
                eng.ingest(survey.survey_networks(args.interface, args.backend,
                                                   rescan=(n % 10 == 0)))
            except Exception as exc:
                log.warning("survey pass failed: %s", exc)
            eng.aps = {b: a for b, a in eng.aps.items() if b in wanted}
            if args.lan:
                eng.ingest_lan(lan.lan_inventory())
            apc = lan.own_ap_clients(args.interface)
            if apc:
                eng.ingest_lan(apc, bssid_hint=next(iter(eng.aps), ""))
            sid = st.record_engine(eng, mode="record", sensor=args.sensor)
            n += 1
            clients = sum(a.client_count for a in eng.aps.values())
            print(f"[{_fmt_ts(time.time())}] {sid}: {len(eng.aps)} BSS, "
                  f"{clients} clients -> {args.db}")
            if t_end and time.time() + args.interval > t_end:
                break
            time.sleep(max(1.0, args.interval - (time.time() - t0)))
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        s = st.stats()
        print(f"history: {s['devices']['rows']} device rows, "
              f"{s['observations']['rows']} observations in {args.db}")
        st.close()
    return 0


def cmd_presence(args) -> int:
    if not os.path.exists(args.db):
        log.error("no history database at %s - start with:  wifiscanner record",
                  args.db)
        return 2
    st = Store(args.db)
    try:
        if args.known:
            rows = st.known_devices()[:args.limit]
            for r in rows:
                r["first"] = _fmt_ts(r["first"])
                r["last"] = _fmt_ts(r["last"])
            print_rows(f"Device roster ({len(rows)} seen so far)",
                       [("MAC", "mac"), ("Seen", "n"), ("First", "first"),
                        ("Last", "last"), ("APs", "bssids"),
                        ("SSIDs", "ssids")], rows)
            return 0
        rows = st.sessions(mac=args.mac, ssid=args.ssid,
                           since=parse_when(args.since),
                           until=parse_when(args.until, end=True), gap=args.gap)
        for r in rows:
            r["first_h"] = _fmt_ts(r["first_seen"])
            r["last_h"] = _fmt_ts(r["last_seen"])
            r["dur_h"] = (f"{int(r['duration_s'] // 60)}m"
                          f"{int(r['duration_s'] % 60):02d}s")
        rows = rows[:args.limit]
        print_rows(f"Presence sessions ({len(rows)} latest, gap>{args.gap:.0f}s "
                   f"splits sessions)",
                   [("MAC", "mac"), ("SSID", "ssid"), ("BSSID", "bssid"),
                    ("Since", "first_h"), ("Until", "last_h"),
                    ("Duration", "dur_h"), ("Seen", "sightings"),
                    ("AvgRSSI", "avg_rssi")], rows)
        live = [r for r in rows if r["last_seen"] > time.time() - max(args.gap * 2, 60)]
        print(f"\n{len(live)} devices present NOW (seen within "
              f"{max(args.gap * 2, 60):.0f}s)")
        if args.output:
            import csv as _csv
            from .privacy import secure_file
            os.makedirs(args.output, exist_ok=True)
            path = os.path.join(args.output, "presence_sessions.csv")
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = _csv.DictWriter(fh, fieldnames=[
                    "mac", "bssid", "ssid", "first_seen", "last_seen",
                    "duration_s", "sightings", "avg_rssi", "min_rssi", "max_rssi"],
                    extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
            secure_file(path)
            print(f"exported -> {path}")
        return 0
    finally:
        st.close()


def _tracker(args):
    sensors = load_sensors(args.sensors) if args.sensors else []
    zones = load_zones(args.zones) if getattr(args, "zones", "") else []
    if not sensors:
        log.error("locate/trail need a sensor grid: --sensors sensors.csv "
                  "(rows: name,x,y[,floor,rssi_offset,tx_power] in metres)")
        return None, None, None
    return (Tracker(sensors, zones, window_s=getattr(args, "window", 3.0),
                    path_loss_exponent=getattr(args, "n_exp", 2.7)),
            sensors, zones)


def cmd_locate(args) -> int:
    tracker, sensors, zones = _tracker(args)
    if not tracker:
        return 2
    if args.live:
        eng = _do_survey(args)
        _do_monitor(args, eng, args.duration)
        st0 = Store(args.db)
        st0.record_engine(eng, mode="locate-live",
                          sensor=getattr(args, "sensor", "") or sensors[0].name)
        st0.close()
    st = Store(args.db)
    try:
        obs = st.get_observations(args.mac, parse_when(args.since),
                                   parse_when(args.until, end=True))
        if not obs:
            log.error("no sensor observations in %s yet - run `record` on each "
                      "sensor, tagging it with --sensor NAME matching sensors.csv",
                      args.db)
            return 2
        fixes = tracker.fixes(obs)
        if args.recompute and fixes:
            st.record_fixes([(f.ts, f.mac, f.x, f.y, f.uncertainty_m,
                              f.method, f.sensors) for f in fixes])
        rows = [dict(ts=_fmt_ts(f.ts), mac=f.mac, x=f.x, y=f.y,
                     unc=f.uncertainty_m, zone=f.zone, method=f.method,
                     conf=f.confidence, zone_conf=f.zone_confidence,
                     sensors=f.sensors, answer=f.display)
                for f in fixes[-80:]]
        print_rows(f"Position fixes ({len(fixes)} computed, showing latest {len(rows)}) — "
                   f"ZONE is the primary answer; coordinates are shown only "
                   f"when confidence is medium/high",
                   [("Time", "ts"), ("MAC", "mac"), ("x", "x"), ("y", "y"),
                    ("Err±m", "unc"), ("Zone", "zone"), ("ZoneConf", "zone_conf"),
                    ("Method", "method"), ("Conf", "conf"),
                    ("Sources", "sensors")], rows)
        for f in fixes[-5:]:
            print(f"  -> {f.mac} @ {_fmt_ts(f.ts)[11:]}: {f.display}")
        if len(sensors) >= 2 and fixes:
            print()
            print(ascii_map(fixes[-400:], sensors, zones))
        return 0
    finally:
        st.close()


def cmd_trail(args) -> int:
    st = Store(args.db)
    try:
        since, until = parse_when(args.since), parse_when(args.until, end=True)
        tracker = sensors = zones = None
        if args.sensors:
            tracker, sensors, zones = _tracker(args)
            if not tracker:
                return 2
            obs = st.get_observations(args.mac, since, until)
            fixes = tracker.fixes(obs)
            if fixes:
                st.record_fixes([(f.ts, f.mac, f.x, f.y, f.uncertainty_m,
                                  f.method, f.sensors) for f in fixes])
        else:
            hist = st.device_history(args.mac, 10000)[::-1]
            fixes = [type("F", (), dict(ts=r["ts"], mac=args.mac, x=None, y=None,
                                       uncertainty_m=None, method="presence-only",
                                       sensors=r.get("sensor", ""), zone="",
                                       rssi=r.get("rssi"), ssid=r.get("ssid")))()
                     for r in hist]
        if not fixes:
            log.error("no movement data for %s in %s", args.mac, args.db)
            return 2
        rows = []
        for f in fixes:
            d = dict(ts=_fmt_ts(f.ts), x=f.x, y=f.y, unc=f.uncertainty_m,
                     zone=getattr(f, "zone", ""), method=f.method,
                     conf=getattr(f, "confidence", ""),
                     answer=getattr(f, "display", ""))
            rows.append(d)
        print_rows(f"Movement trail for {args.mac} ({len(fixes)} fixes) — "
                   f"zone-level answers; low-confidence coordinates withheld",
                   [("Time", "ts"), ("x", "x"), ("y", "y"), ("Err±m", "unc"),
                    ("Zone", "zone"), ("Method", "method"), ("Conf", "conf")],
                   rows[-100:])
        if tracker:
            dwell = tracker.zone_dwell(fixes)
            if dwell:
                print_rows("Zone dwell", [("Zone", "zone"), ("Seconds", "secs")],
                           [dict(zone=z, secs=s) for z, s in
                            sorted(dwell.items(), key=lambda kv: -kv[1])])
        if args.map and sensors and any(f.x is not None for f in fixes):
            print()
            print(ascii_map(fixes, sensors, zones))
        if args.output:
            os.makedirs(args.output, exist_ok=True)
            path = os.path.join(args.output,
                                f"trail-{args.mac.replace(':', '')}.csv")
            import csv as _csv
            from .privacy import secure_file
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = _csv.DictWriter(fh, fieldnames=[
                    "ts", "time", "mac", "x", "y", "unc_m", "error_radius_m",
                    "zone", "zone_confidence", "method", "confidence",
                    "sensor_count", "display"])
                w.writeheader()
                for f in fixes:
                    w.writerow({"ts": round(f.ts, 1), "time": _fmt_ts(f.ts),
                                "mac": f.mac, "x": f.x, "y": f.y,
                                "unc_m": f.uncertainty_m,
                                "error_radius_m": getattr(
                                    f, "error_radius_m", f.uncertainty_m),
                                "zone": getattr(f, "zone", ""),
                                "zone_confidence": getattr(
                                    f, "zone_confidence", ""),
                                "method": f.method,
                                "confidence": getattr(f, "confidence", ""),
                                "sensor_count": getattr(f, "sensor_count", ""),
                                "display": getattr(f, "display", "")})
            secure_file(path)
            print(f"exported -> {path}")
        return 0
    finally:
        st.close()


def cmd_capture(args) -> int:
    """Raw frame capture with rotation / ring buffer. Passive only."""
    if not args.ack_sensitive:
        log.warning("raw captures contain sensitive third-party data "
                    "(payloads, identifiers) — collect only where authorized; "
                    "add --strip-payloads for a privacy-preserving header-only "
                    "capture, or --ack-sensitive to silence this warning")
    if not sniffer.scapy_available():
        log.error("scapy required:  pip install scapy")
        return 2
    iface = args.interface
    if not iface:
        ifaces = survey.list_interfaces()
        if not ifaces:
            log.error("no wireless interface found; specify -i")
            return 2
        iface = ifaces[0]["name"]
    if not args.no_monitor_setup and not is_root():
        log.error("monitor capture requires root (sudo)")
        return 13
    channels = [int(c) for c in args.channels.split(",") if c.strip()] \
        if args.channels else None
    sn = sniffer.MonitorSniffer(iface, channels=channels,
                                hop_interval=args.hop_interval,
                                bands=tuple(args.bands), lock_bssid=args.bssid)
    snaplen = 128 if args.strip_payloads else 0
    if args.strip_payloads:
        print("privacy-preserving capture: 128-byte snaplen keeps 802.11 "
              "headers (counting/IDS) and discards payloads")
    print(f"capture files are written owner-only (0600) to {args.pcap or '.'}; "
          f"they remain sensitive — store encrypted, delete when done")

    def _go(mon):
        sn.iface = mon
        sn.run(args.duration, pcap_out=args.pcap,
               ring_segments=args.ring_segments, rotate_mb=args.rotate_mb,
               snaplen=snaplen, secure_storage=True)

    try:
        if args.no_monitor_setup:
            _go(iface)
        else:
            with sniffer.MonitorMode(iface, use_airmon=args.airmon) as mon:
                _go(mon)
    except KeyboardInterrupt:
        sn.stop()
        print("\nstopped.")
    stt = sn.stats()
    print_rows("Capture stats", [(k, k) for k in stt], [stt])
    if args.max_age_days:
        import glob as _glob
        base, _ext = os.path.splitext(args.pcap)
        cutoff = time.time() - args.max_age_days * 86400
        for f in _glob.glob(base + "*.pcap*"):
            try:
                if os.path.getmtime(f) < cutoff:
                    os.remove(f)
                    print(f"  retention: deleted expired segment {f}")
            except OSError as exc:
                log.warning("retention delete failed for %s: %s", f, exc)
    if args.analyze:
        eng = Engine()
        eng.ingest(sn.results())
        eng.ingest_unassociated(sn.unassociated)
        print_networks(eng, "clients")
        print_devices(eng)
    return 0


def cmd_traffic(args) -> int:
    """Inspect UNENCRYPTED traffic. This tool never decrypts protected frames."""
    if not sniffer.scapy_available():
        log.error("scapy required:  pip install scapy")
        return 2
    from . import traffic as tf
    redact = not args.no_redact
    if args.no_redact:
        log.warning("--no-redact: URL query strings, full User-Agents and "
                    "hostnames will be logged VERBATIM. Only use on your own "
                    "network with consent.")
    else:
        print("redaction ON (default): URL queries stripped, User-Agents "
              "reduced to product tokens, credential values never logged")
    if args.live:
        if not is_root():
            log.error("live dissection needs root + a monitor interface")
            return 13

        def show(ev):
            print(f"{_fmt_ts(ev.ts)[11:]} [{ev.proto}] {ev.src} -> {ev.dst}  "
                  f"{ev.summary}" + (f"  !!{ev.alert}" if ev.alert else ""))
        if args.no_monitor_setup:
            d = tf.analyze_live(args.interface, args.duration, on_event=show,
                                redact=redact,
                                anonymize_ips=args.anonymize_ips)
        else:
            with sniffer.MonitorMode(args.interface,
                                     use_airmon=args.airmon) as mon:
                d = tf.analyze_live(mon, args.duration, on_event=show,
                                    redact=redact,
                                    anonymize_ips=args.anonymize_ips)
    else:
        if not args.pcap or not os.path.exists(args.pcap):
            log.error("usage: wifiscanner traffic <file.pcap>  (or --live -i wlan0mon)")
            return 2
        print("dissecting cleartext frames only; protected frames are skipped "
              "and counted...")
        d = tf.analyze_pcap(args.pcap, args.max_frames, redact=redact,
                            anonymize_ips=args.anonymize_ips)
    tf.print_dissector(d, args.limit)
    if d.protected_skipped:
        print(f"note: {d.protected_skipped} protected frames skipped - by "
              f"design this tool never attempts decryption.")
    if args.output:
        for f in tf.export(args.output, args.prefix, d):
            print(f"  -> {f}")
    return 0


# ------------------------------------------------- defense & education

def cmd_ids(args) -> int:
    wd = Watchdog(window_s=args.window, flood_frames=args.flood,
                  sensitivity=args.sensitivity)
    print(f"IDS sensitivity: {args.sensitivity} "
          f"(effective flood threshold {wd.effective_flood_n} frames; "
          f"adaptive margin raises it automatically in noisy air)")
    known: set = set()
    st = None
    if args.db:
        st = Store(args.db)
        known = {r["bssid"] for r in st.warden_list()}
    wd.known = known or wd.known
    fired = [0]

    if args.pcap:
        if not sniffer.scapy_available():
            log.error("scapy required for pcap analysis")
            return 2
        from scapy.all import PcapReader
        for pkt in PcapReader(args.pcap):
            wd.feed(pkt)
        log.info("analysed %s", args.pcap)
    else:
        if not sniffer.scapy_available():
            log.error("scapy required for live IDS")
            return 2
        iface = args.interface
        if not iface:
            ifaces = survey.list_interfaces()
            if not ifaces:
                log.error("no wireless interface; use --pcap FILE instead")
                return 2
            iface = ifaces[0]["name"]
        sn = sniffer.MonitorSniffer(iface, hop_interval=0.35)

        def cb(pkt):
            try:
                wd.feed(pkt)
            except Exception:
                pass
            if args.follow and len(wd.alerts) > fired[0]:
                for a in wd.alerts[fired[0]:]:
                    print(f"[{a.severity.upper():8}] {a.kind}: {a.detail}")
                fired[0] = len(wd.alerts)
        if args.no_monitor_setup:
            sn.run(args.duration, on_packet=cb)
        else:
            if not is_root():
                log.error("live IDS needs root (monitor mode), or --pcap FILE")
                return 13
            with sniffer.MonitorMode(iface, use_airmon=args.airmon) as mon:
                sn.iface = mon
                sn.run(args.duration, on_packet=cb)

    alerts = wd.results()
    if args.learn and st is not None:
        eng = Engine()
        if args.pcap and sniffer.scapy_available():
            sn2 = sniffer.MonitorSniffer(iface="offline")
            sn2.read_pcap(args.pcap)
            eng.ingest(sn2.results())
        else:
            eng.ingest(survey.survey_networks(args.interface, "auto", False))
        n = st.learn_warden(eng)
        print(f"warden baseline updated: {n} BSSIDs marked known-good in {args.db}")
    if alerts:
        from .display import print_rows
        print_rows(f"IDS alerts ({len(alerts)}) — every alert carries "
                   f"confidence + status; 'unconfirmed' means a single "
                   f"indicator, corroborate before acting",
                   [("Time", "time"), ("Severity", "severity"), ("Kind", "kind"),
                    ("BSSID", "bssid"), ("SSID", "ssid"), ("Conf", "confidence"),
                    ("Status", "status"), ("Evidence", "evidence"),
                    ("Detail", "detail")],
                   [a.to_row() for a in alerts])
    else:
        print("no anomalies detected in "
              f"{wd.stats()['frames']} frames ({wd.stats()['runtime_s'] or ''}s).")
    s = wd.stats()
    print(f"watchdog: {s['frames']} frames, {s['alerts']} alerts "
          f"{ {k: v for k, v in s['by_severity'].items()} }")
    if args.output and alerts:
        import csv as _csv
        from .privacy import secure_file
        os.makedirs(args.output, exist_ok=True)
        path = os.path.join(args.output, "ids_alerts.csv")
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = _csv.DictWriter(fh, fieldnames=list(alerts[0].to_row()))
            w.writeheader()
            w.writerows(a.to_row() for a in alerts)
        secure_file(path)
        print(f"exported -> {path}")
    if st:
        st.close()
    return 0


def cmd_audit(args) -> int:
    eng = Engine()
    if args.pcap:
        if not sniffer.scapy_available():
            log.error("scapy required for pcap audit")
            return 2
        sn = sniffer.MonitorSniffer(iface="offline")
        sn.read_pcap(args.pcap)
        eng.ingest(sn.results())
    else:
        eng.ingest(survey.survey_networks(args.interface, "auto", True))
    if args.ssid:
        eng.aps = {b: a for b, a in eng.aps.items()
                   if args.ssid.lower() in (a.ssid or "").lower()
                   or args.ssid.upper() == b}
    if not eng.aps:
        log.error("no networks to audit (connected? or pass --pcap / --ssid)")
        return 2
    rows = audit_engine(eng)
    from .display import print_rows
    fails = [r for r in rows if r["status"] != "PASS"]
    print_rows(f"Hardening audit - {len(eng.aps)} BSS, "
               f"{len(fails)} findings",
               [("BSSID", "bssid"), ("SSID", "ssid"), ("Check", "check"),
                ("Status", "status"), ("Severity", "severity"),
                ("Fix", "finding")], rows)
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        path = os.path.join(args.output, "audit_report.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Wi-Fi hardening audit\n\n")
            for a in eng.sorted_aps("rssi"):
                fh.write(f"\n## {a.ssid or '<hidden>'} ({a.bssid}, {a.vendor})\n\n")
                fh.write(f"- Current: {a.encryption}, PMF {a.pmf or '?'}, "
                         f"channel {a.channel}, WPS {'ENABLED' if a.wps else 'off'}\n")
                for r in [x for x in rows if x["bssid"] == a.bssid]:
                    mark = {"PASS": "[x]", "WARN": "[!]", "FAIL": "[ ]"}[r["status"]]
                    fh.write(f" - {mark} **{r['check']}** "
                             f"{'— ' + r['finding'] if r['finding'] else ''}\n")
        print(f"report -> {path}")
    return 0


def cmd_frames(args) -> int:
    if not sniffer.scapy_available():
        log.error("scapy required:  pip install scapy")
        return 2
    if not os.path.exists(args.pcap):
        log.error("no such file: %s", args.pcap)
        return 2
    from .frames import annotate_pcap, find_handshakes
    if args.handshakes:
        stats = find_handshakes(args.pcap)
        print_rows("EAPOL / deauth activity (counts only - no frames are "
                   "extracted, by design)",
                   [("metric", "k"), ("value", "v")],
                   [{"k": k, "v": v} for k, v in stats.items()
                    if k != "eapol_by_bss"])
        for b, c in (stats.get("eapol_by_bss") or {}).items():
            print(f"  eapol @ {b}: {c}")
        return 0
    blocks = annotate_pcap(args.pcap, limit=args.limit, filt=args.filter)
    if not blocks:
        print("no frames matched (check --filter).")
    for b in blocks:
        print(b)
    print(f"\n({len(blocks)} frames annotated"
          + (f", filter={args.filter!r}" if args.filter else "") + ")")
    return 0


# ------------------------------------------------- authorized injection

def cmd_inject(args) -> int:
    """Transmit frames ONLY as an authorized, logged, bounded self-test.

    Defaults to a dry run that builds/describes frames and writes the audit
    trail without touching the radio, so the operator can preview an action.
    Live emission requires root + --transmit + --authorized (and --yes for
    the bounded pmf-test); broadcast/third-party targets are refused.
    """
    # ------------------------------------------------ offline, zero-RF mode
    if args.mode == "ids-selftest":
        pcap = args.write_pcap or (os.path.join(args.output,
                                                "ids_selftest.pcap")
                                   if args.output else "")
        print("IDS self-test: synthesising attack signatures OFFLINE (no "
              "radio, no root) and confirming the watchdog fires on each.\n")
        rep = ij.run_ids_selftest(write_pcap=pcap)
        print_rows("IDS signature self-test",
                   [("Scenario", "scenario"), ("Expected", "expected"),
                    ("Fired", "fired"), ("Missing", "missing"),
                    ("Status", "status")], rep["rows"])
        all_pass = rep["passed"] == rep["total"]
        print(f"\nwatchdog saw {rep['frames']} synthetic frames -> "
              f"{rep['alerts']} alerts; {rep['passed']}/{rep['total']} "
              f"signatures detected.")
        if pcap and os.path.exists(pcap):
            print(f"synthetic-signature pcap (for `ids --pcap`): {pcap}")
        if not all_pass:
            log.error("IDS did NOT fire on every signature - investigate "
                      "sensor coverage before trusting live detection.")
            return 1
        print("all signatures detected: this sensor's detection path works.")
        return 0

    # ---------------------------------------------------- live modes
    if not sniffer.scapy_available():
        log.error("scapy required for injection:  pip install scapy")
        return 2

    mode = args.mode
    bssid = client = ""
    try:
        if mode in ij.KICK_MODES:
            bssid, client = ij.validate_kick_targets(args.bssid, args.client,
                                                     mode)
        # Consent + privilege gates (raise InjectionError with a clear reason).
        ij.gate_transmission(mode, transmit=args.transmit,
                             authorized=args.authorized,
                             confirmed=args.yes)
    except ij.InjectionError as exc:
        log.error("%s", exc)
        return 2

    iface = args.interface
    if not iface:
        ifaces = survey.list_interfaces()
        if not ifaces:
            log.error("no wireless interface found; specify one with -i")
            return 2
        iface = ifaces[0]["name"]
        log.info("using interface %s", iface)

    transmit = args.transmit and args.authorized
    count = ij.clamp_count(mode, args.count)
    channels = ij.parse_channels(args.channels)
    if mode in ij.KICK_MODES and not args.channels:
        log.warning("no --channels given: targeting channel %s. Pass the AP's "
                    "channel (-c CH) or the frames may not reach it.",
                    channels[0])
    os.makedirs(args.output, exist_ok=True)
    audit_path = args.audit_log or os.path.join(args.output,
                                                "injection_audit.csv")
    # A verification pcap only makes sense when frames actually go out.
    pcap_path = args.write_pcap
    if transmit and not pcap_path:
        pcap_path = os.path.join(args.output, f"inject-{mode}.pcap")
    audit = ij.AuditLog(audit_path)
    src_mac = args.src_mac or ij.random_local_mac()

    try:
        if not transmit:
            print("DRY RUN: no frames will be transmitted. Add --transmit "
                  "--authorized" + (" --yes" if mode in ij.KICK_MODES else "") +
                  " to actually emit. Preview:\n")
            inj = ij.Injector(iface, mode=mode, dry_run=True, audit=audit,
                              src_mac=src_mac)
            _build_preview(inj, mode, channels, args)
            print(f"\naudit trail: {audit_path}")
            print(f"frames built: {inj.built}; frames transmitted: 0")
            return 0

        return _inject_live(args, ij, mode, iface, channels, count, bssid,
                            client, src_mac, audit, audit_path, pcap_path)
    finally:
        audit.close()


def _build_preview(inj, mode, channels, args) -> None:
    """Populate the audit log in dry-run mode and show the would-be frames."""
    if mode == "probe":
        ssids = [s.strip() for s in args.ssid.split(",") if s.strip()] or [""]
        inj.probe_sweep(channels, ssids, ij.clamp_count("probe", args.count))
    elif mode == "canary":
        token = args.token or ij.new_canary_token()
        print(f"canary token: {token}\n")
        inj.canary_sweep(channels, token, ij.clamp_count("canary", args.count))
    elif mode in ij.KICK_MODES:
        bssid, client = ij.validate_kick_targets(args.bssid, args.client, mode)
        n = ij.clamp_count(mode, args.count)
        ftype = args.frame_type if mode == "deauth" else "deauth"
        direction = args.direction if mode == "deauth" else "ap-to-sta"
        print(f"target: {bssid} -> {client}   {n} {ftype} frame(s), "
              f"direction={direction}\n")
        inj.kick_burst(bssid, client, n, frame_type=ftype, direction=direction)


def _inject_live(args, ij, mode, iface, channels, count, bssid, client,
                 src_mac, audit, audit_path, pcap_path) -> int:
    """Actually transmit. Assumes consent gates have already passed + root."""
    from .display import print_rows
    inj = ij.Injector(iface, mode=mode, dry_run=False, audit=audit,
                      src_mac=src_mac)

    def _run(tx_iface: str) -> dict:
        inj.iface = tx_iface
        if mode in ij.KICK_MODES:
            ij._set_channel(tx_iface, channels[0])
            dur = args.baseline_s + args.verify_s + 2.0
            listener = ij.AirListener(tx_iface, dur, pcap_path=pcap_path)
            listener.start()
            print(f"baseline: listening {args.baseline_s:.0f}s for {client} "
                  "on your AP...")
            time.sleep(args.baseline_s)
            burst_ts = time.time()
            ftype = args.frame_type if mode == "deauth" else "deauth"
            direction = args.direction if mode == "deauth" else "ap-to-sta"
            inj.kick_burst(bssid, client, count, frame_type=ftype,
                           direction=direction)
            print(f"sent {count} bounded {ftype} frame(s); observing "
                  f"{args.verify_s:.0f}s for disconnect / re-association...")
            time.sleep(args.verify_s)
            listener.join()
            rep = ij.kick_verdict(listener.events, bssid, client, burst_ts)
            rep["mode"] = mode
            rep["frame_type"] = ftype
            rep["direction"] = direction
            rep["burst_sent"] = count
            rep["frames_seen"] = listener.frames
            rep["pcap"] = pcap_path or "-"
            return rep
        # probe / canary: a long-running listener; burst + dwell per channel
        dwell = args.dwell or ij.DEFAULT_DWELL_S
        n_ssid = len([s for s in args.ssid.split(",") if s.strip()] or [""])
        total_dur = len(channels) * (
            dwell + count * n_ssid * inj.interval + 2.0) + 2
        listener = ij.AirListener(tx_iface, total_dur, pcap_path=pcap_path)
        listener.start()
        if mode == "probe":
            ssids = [s.strip() for s in args.ssid.split(",") if s.strip()] or [""]
            for ch in channels:
                ij._set_channel(tx_iface, ch)
                for ssid in ssids:
                    for _ in range(count):
                        inj._emit(ij.build_probe_request(src_mac, ssid),
                                  frame="probe-request", channel=str(ch),
                                  target=ij.BROADCAST,
                                  detail=f"ssid={ssid or '<wildcard>'}")
                time.sleep(dwell)
            listener.join()
            responses = [e for e in listener.events if e.kind == "proberesp"]
            bssids = sorted({(normalize(e.bssid), e.ssid) for e in responses})
            return {"mode": "probe", "channels": ",".join(map(str, channels)),
                    "probe_responses": len(responses),
                    "distinct_bss": len(bssids),
                    "networks": "|".join(f"{s}@{b}" for b, s in bssids[:30]),
                    "sent": inj.sent, "pcap": pcap_path or "-"}
        token = args.token or ij.new_canary_token()
        print(f"canary token: {token}")
        print("every remote IDS/capture sensor must now report this token; "
              "grep it in their logs/pcaps.")
        for ch in channels:
            ij._set_channel(tx_iface, ch)
            for _ in range(count):
                inj._emit(ij.build_probe_request(src_mac, token),
                          frame="canary-probe", channel=str(ch),
                          target=ij.BROADCAST, detail=f"token={token}")
            time.sleep(dwell)
        listener.join()
        rep = ij.canary_results(listener.events, src_mac, token)
        rep.update({"mode": "canary", "sent": inj.sent, "pcap": pcap_path or "-"})
        return rep

    if args.no_monitor_setup:
        rep = _run(iface)
    else:
        with sniffer.MonitorMode(iface, use_airmon=args.airmon) as mon:
            rep = _run(mon)

    # ---------------------------------------------------------------- report
    if mode in ij.KICK_MODES:
        title = ("PMF / deauth-resistance self-test" if mode == "pmf-test"
                 else "Deauthentication / disassociation test (authorised)")
        print_rows(title,
                   [("Fact", "k"), ("Result", "v")],
                   [{"k": k, "v": v} for k, v in rep.items()])
        verdict = rep.get("verdict")
        if verdict == "pass":
            print("\nPASS: the forged deauth/disassoc frames were ignored - "
                  "management-frame protection (PMF/802.11w) is protecting "
                  "this client.")
        elif verdict == "fail":
            log.error("\nKICKED: the client disconnected and had to "
                      "re-associate. Management-frame protection (802.11w PMF) "
                      "is NOT enforced - set it to REQUIRED on your AP and "
                      "supplicant, then re-test. For a PMF verification this "
                      "is FAIL; for a pen-test it confirms the client/AP are "
                      "vulnerable to a kick attack.")
            return 1
        else:
            log.warning("\nINCONCLUSIVE: %s", rep.get("detail"))
            return 3
    else:
        print_rows(f"Injection result ({rep.get('mode')})",
                   [(k, k) for k in rep], [rep])
    print(f"\ntransmitted {inj.sent} frame(s); audit trail: {audit_path}")
    if pcap_path and os.path.exists(pcap_path):
        print(f"verification capture: {pcap_path}")
    return 0


def cmd_db(args) -> int:
    """History-database maintenance: retention, anonymization, deletion."""
    if not os.path.exists(args.db) and not args.report:
        log.error("no database at %s", args.db)
        return 2
    st = Store(args.db) if os.path.exists(args.db) else None
    try:
        if args.report or not (args.prune_days or args.delete_mac or
                               args.anonymize_db or args.purge or args.vacuum):
            if st is None:
                log.error("no database at %s - nothing to report", args.db)
                return 2
            rep = st.storage_report()
            print_rows("Database storage report",
                       [("Fact", "k"), ("Value", "v")],
                       [{"k": "path", "v": rep.get("path")},
                        {"k": "size", "v": f"{rep.get('bytes', 0)} bytes"},
                        {"k": "mode", "v": rep.get("mode")},
                        {"k": "world-readable",
                         "v": rep.get("world_readable")},
                        {"k": "retention", "v": rep.get("retention")},
                        {"k": "privacy mode", "v": rep.get("privacy_mode")},
                        {"k": "anonymized writes",
                         "v": rep.get("anonymized_writes")},
                        {"k": "device rows",
                         "v": rep["tables"]["devices"]["rows"]},
                        {"k": "observation rows",
                         "v": rep["tables"]["observations"]["rows"]},
                        {"k": "fix rows",
                         "v": rep["tables"]["fixes"]["rows"]}])
            if rep.get("world_readable"):
                print("WARNING: database is readable by other users — "
                      "it maps devices to places and times. Restrict it: "
                      f"`chmod 600 {args.db}` (this tool creates 0600 by "
                      f"default; it was loosened afterwards)")
            return 0
        if args.prune_days:
            n = st.prune(args.prune_days)
            print(f"pruned {n} row(s) older than {args.prune_days:g} days")
        if args.delete_mac:
            n = st.delete_device(args.delete_mac)
            print(f"erased {n} row(s) for {args.delete_mac}")
        if args.anonymize_db or args.purge:
            if not args.yes:
                log.warning("proceeding without --yes: --anonymize-db is "
                            "IRREVERSIBLE and --purge deletes all history")
            if args.anonymize_db:
                n = st.anonymize_history()
                print(f"anonymized {n} row(s) — MACs are now salted "
                      f"pseudonyms, IPs/hostnames cleared (no undo)")
            if args.purge:
                n = st.purge_all()
                print(f"purged {n} history row(s)")
        if args.vacuum or args.prune_days or args.delete_mac or \
                args.anonymize_db or args.purge:
            st.vacuum()
            print("vacuumed.")
        return 0
    finally:
        if st is not None:
            st.close()


def cmd_interfaces(args) -> int:
    ifaces = survey.list_interfaces()
    print(f"platform      : {os_name()}")
    print(f"root/admin    : {is_root()}")
    print(f"backends      : {', '.join(survey.available_backends()) or 'none'}")
    print(f"scapy         : {'yes' if sniffer.scapy_available() else 'no (pip install scapy)'}")
    print(f"OUI database  : {db_size()} vendor prefixes")
    print(f"\nwireless interfaces ({len(ifaces)}):")
    for i in ifaces:
        extra = " ".join(f"{k}={v}" for k, v in i.items() if k != "name")
        print(f"  - {i['name']:<12} {extra}")
    if not ifaces:
        print("  (none detected)")
    return 0


# --------------------------------------------------------------------- main

def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose, args.quiet)
    if not args.no_banner and not args.quiet:
        print_banner()
        if _RICH:
            console.print(f"[dim]{LEGAL}[/]\n")
        else:
            print(LEGAL + "\n")
    fn = {"scan": cmd_scan, "monitor": cmd_monitor, "full": cmd_full,
          "detail": cmd_detail, "devices": cmd_devices, "watch": cmd_watch,
          "offline": cmd_offline, "interfaces": cmd_interfaces,
          "own": cmd_own, "record": cmd_record, "presence": cmd_presence,
          "locate": cmd_locate, "trail": cmd_trail, "capture": cmd_capture,
          "traffic": cmd_traffic, "ids": cmd_ids, "audit": cmd_audit,
          "frames": cmd_frames, "inject": cmd_inject, "db": cmd_db}[args.cmd]
    try:
        return fn(args)
    except KeyboardInterrupt:
        print("\ninterrupted.")
        return 130
    except PermissionError as exc:
        log.error("%s", exc)
        return 13
    except Exception as exc:
        log.error("fatal: %s", exc)
        if args.verbose:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
