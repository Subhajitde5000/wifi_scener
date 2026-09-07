"""wifiscanner command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__
from .backends import lan, sniffer, survey
from .display import (print_banner, print_congestion, print_detail,
                      print_devices, print_networks, print_rogues,
                      print_summary, print_rows, console, _RICH)
from .engine import Engine
from .export import export_all
from .locate import Tracker, ascii_map, load_sensors, load_zones
from .oui import db_size, normalize
from .store import Store, parse_when
from .util import is_root, log, os_name, setup_logging

LEGAL = (
    "SCOPE: passive, defensive, own-network-first. This tool listens to what "
    "is broadcast in public airspace and reads YOUR OWN router's association "
    "table; it never transmits, injects, deauthenticates, clones APs, cracks "
    "keys or decrypts traffic - those features are deliberately NOT part of "
    "this tool (see README). Continuous history recording is restricted to "
    "your own network. Use on your own infrastructure or with written consent."
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
    trf.add_argument("--airmon", action="store_true")
    trf.add_argument("--no-monitor-setup", action="store_true")

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
    files = export_all(eng, args.output, args.prefix, tuple(args.format))
    msg = "\n".join(f"  -> {f}" for f in files)
    print(f"\nExported {len(files)} file(s):\n{msg}")


def _maybe_store(args, eng: Engine, mode: str = "scan") -> None:
    db = getattr(args, "db", "")
    if not db:
        return
    st = Store(db)
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
        eng.ingest_lan(ap_clients, bssid_hint=my_bssid)

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
    if args.pcap:
        if not sniffer.scapy_available():
            log.error("scapy required for pcap import")
            return 2
        eng = Engine()
        sn = sniffer.MonitorSniffer(iface="offline")
        sn.read_pcap(args.pcap)
        eng.ingest(sn.results())
        st = Store(args.db)
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

    st = Store(args.db)
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
            os.makedirs(args.output, exist_ok=True)
            path = os.path.join(args.output, "presence_sessions.csv")
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = _csv.DictWriter(fh, fieldnames=[
                    "mac", "bssid", "ssid", "first_seen", "last_seen",
                    "duration_s", "sightings", "avg_rssi", "min_rssi", "max_rssi"],
                    extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
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
                     sensors=f.sensors) for f in fixes[-80:]]
        print_rows(f"Position fixes ({len(fixes)} computed, showing latest {len(rows)})",
                   [("Time", "ts"), ("MAC", "mac"), ("x", "x"), ("y", "y"),
                    ("Unc m", "unc"), ("Zone", "zone"), ("Method", "method"),
                    ("Sources", "sensors")], rows)
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
                     zone=f.zone, method=f.method)
            rows.append(d)
        print_rows(f"Movement trail for {args.mac} ({len(fixes)} fixes)",
                   [("Time", "ts"), ("x", "x"), ("y", "y"), ("Unc m", "unc"),
                    ("Zone", "zone"), ("Method", "method")], rows[-100:])
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
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = _csv.DictWriter(fh, fieldnames=[
                    "ts", "time", "mac", "x", "y", "unc_m", "zone", "method"])
                w.writeheader()
                for f in fixes:
                    w.writerow({"ts": round(f.ts, 1), "time": _fmt_ts(f.ts),
                                "mac": f.mac, "x": f.x, "y": f.y,
                                "unc_m": f.uncertainty_m, "zone": f.zone,
                                "method": f.method})
            print(f"exported -> {path}")
        return 0
    finally:
        st.close()


def cmd_capture(args) -> int:
    """Raw frame capture with rotation / ring buffer. Passive only."""
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

    def _go(mon):
        sn.iface = mon
        sn.run(args.duration, pcap_out=args.pcap,
               ring_segments=args.ring_segments, rotate_mb=args.rotate_mb)

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
    if args.live:
        if not is_root():
            log.error("live dissection needs root + a monitor interface")
            return 13

        def show(ev):
            print(f"{_fmt_ts(ev.ts)[11:]} [{ev.proto}] {ev.src} -> {ev.dst}  "
                  f"{ev.summary}" + (f"  !!{ev.alert}" if ev.alert else ""))
        if args.no_monitor_setup:
            d = tf.analyze_live(args.interface, args.duration, on_event=show)
        else:
            with sniffer.MonitorMode(args.interface,
                                     use_airmon=args.airmon) as mon:
                d = tf.analyze_live(mon, args.duration, on_event=show)
    else:
        if not args.pcap or not os.path.exists(args.pcap):
            log.error("usage: wifiscanner traffic <file.pcap>  (or --live -i wlan0mon)")
            return 2
        print("dissecting cleartext frames only; protected frames are skipped "
              "and counted...")
        d = tf.analyze_pcap(args.pcap, args.max_frames)
    tf.print_dissector(d, args.limit)
    if d.protected_skipped:
        print(f"note: {d.protected_skipped} protected frames skipped - by "
              f"design this tool never attempts decryption.")
    if args.output:
        for f in tf.export(args.output, args.prefix, d):
            print(f"  -> {f}")
    return 0


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
          "traffic": cmd_traffic}[args.cmd]
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
