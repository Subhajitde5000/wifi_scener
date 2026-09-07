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
                      print_summary, console, _RICH)
from .engine import Engine
from .export import export_all
from .oui import db_size, normalize
from .util import is_root, log, os_name, setup_logging

LEGAL = (
    "LEGAL / ETHICS: This tool is 100% passive - it only listens to frames that "
    "are already broadcast in public airspace and never transmits, injects, "
    "deauthenticates or attempts to join or crack any network. Monitoring "
    "networks you do not own or administer may still be regulated where you "
    "live. Use it only on your own networks or with explicit written permission."
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
  wifiscanner monitor -i wlan0 --bssid AA:BB:CC:DD:EE:FF -d 300
  wifiscanner detail "MyHomeWiFi"           A-to-Z detail for one network
  wifiscanner devices --lan --ports         inventory the network you are on
  wifiscanner full -i wlan0 -d 90 -o out    everything, then export
  wifiscanner watch -i wlan0                live refreshing dashboard
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


# ----------------------------------------------------------------- commands

def cmd_scan(args) -> int:
    eng = _do_survey(args)
    print_networks(eng, args.sort, args.limit)
    print_congestion(eng)
    print_rogues(eng)
    print_summary(eng)
    _export(args, eng)
    return 0


def cmd_monitor(args) -> int:
    eng = _do_survey(args)
    _do_monitor(args, eng, args.duration, args.bssid)
    print_networks(eng, "clients" if not args.sort else args.sort, args.limit)
    print_devices(eng, args.limit)
    print_rogues(eng)
    print_summary(eng)
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
    _export(args, eng)
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
          "offline": cmd_offline, "interfaces": cmd_interfaces}[args.cmd]
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
