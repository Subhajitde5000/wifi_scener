"""Terminal rendering: rich tables when available, clean ASCII otherwise."""
from __future__ import annotations

from typing import List

from .engine import Engine
from .models import AccessPoint, rssi_bars, rssi_quality

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    _RICH = True
    console = Console()
except Exception:                                        # pragma: no cover
    _RICH = False
    console = None


def _c(rssi):
    if rssi is None:
        return "dim"
    return "green" if rssi >= -60 else ("yellow" if rssi >= -75 else "red")


def _gc(grade: str) -> str:
    return {"A+": "bold green", "A": "green", "B": "cyan",
            "C": "yellow", "D": "red", "F": "bold red"}.get(grade, "white")


def print_banner() -> None:
    art = r"""
 __      __.__  _____.__    _________
/  \    /  \  |/ ____\  |  /   _____/ ___________  ____   ___________
\   \/\/   /  \   __\|  |  \_____  \_/ ___\__  \ /    \_/ __ \_  __ \
 \        /|  ||  |  |  |  /        \  \___/ __ \   |  \  ___/|  | \/
  \__/\  / |__||__|  |__| /_______  /\___  >____  /___|  /\___  >__|
       \/                         \/     \/     \/     \/     \/
      passive Wi-Fi survey  &  client-attribution engine"""
    if _RICH:
        console.print(f"[bold cyan]{art}[/]")
    else:
        print(art)


def print_networks(engine: Engine, sort: str = "rssi", limit: int = 0) -> None:
    aps = engine.sorted_aps(sort)
    if limit:
        aps = aps[:limit]
    if not _RICH:
        print(f"\n{'SSID':<26}{'BSSID':<19}{'CH':>4}{'RSSI':>6}{'Q':>5}  "
              f"{'SEC':<14}{'GR':<3}{'DEV':>4}  VENDOR")
        print("-" * 110)
        for a in aps:
            print(f"{(a.ssid or '<hidden>')[:25]:<26}{a.bssid:<19}"
                  f"{a.channel or '-':>4}{a.rssi if a.rssi is not None else '-':>6}"
                  f"{rssi_quality(a.rssi) or 0:>4}%  {a.encryption[:13]:<14}"
                  f"{a.security_grade:<3}{a.client_count:>4}  {a.vendor[:22]}")
        print(f"\n{len(aps)} networks")
        return

    t = Table(title=f"Access Points ({len(aps)})", box=box.ROUNDED,
              header_style="bold cyan", expand=True)
    for col, kw in (("SSID", {"style": "bold", "max_width": 24}),
                    ("BSSID", {}), ("Vendor", {"max_width": 16}),
                    ("Band", {}), ("Ch", {"justify": "right"}),
                    ("Signal", {}), ("Dist", {"justify": "right"}),
                    ("Security", {"max_width": 18}), ("Gr", {"justify": "center"}),
                    ("Dev", {"justify": "right"}), ("Risks", {"max_width": 26})):
        t.add_column(col, **kw)
    for a in aps:
        sig = (f"[{_c(a.rssi)}]{rssi_bars(a.rssi)} "
               f"{a.rssi if a.rssi is not None else '--'}dBm[/]")
        dev = f"[bold]{a.client_count}[/]" if a.client_count else "[dim]0[/]"
        d = f"{a.distance_m:.0f}m" if a.distance_m else "-"
        t.add_row(a.ssid or "[dim italic]<hidden>[/]", a.bssid,
                  a.vendor or "[dim]?[/]", a.band, str(a.channel or "-"), sig, d,
                  a.encryption, f"[{_gc(a.security_grade)}]{a.security_grade}[/]",
                  dev, "[yellow]" + ", ".join(r.split(":")[0] for r in a.risks[:3]) + "[/]")
    console.print(t)


def print_devices(engine: Engine, limit: int = 0) -> None:
    stations = []
    for ap in engine.sorted_aps("rssi"):
        for s in ap.stations.values():
            stations.append((ap, s, "associated"))
    for s in engine.unassociated.values():
        stations.append((None, s, "probing"))
    if not stations:
        msg = ("No client devices detected. Client attribution requires "
               "monitor mode: run with --monitor as root.")
        console.print(f"[yellow]{msg}[/]") if _RICH else print(msg)
        return
    if limit:
        stations = stations[:limit]
    if not _RICH:
        print(f"\n{'MAC':<19}{'VENDOR':<20}{'NETWORK':<22}{'RSSI':>6}"
              f"{'PKTS':>7}  STATE")
        for ap, s, st in stations:
            print(f"{s.mac:<19}{(s.vendor or '?')[:19]:<20}"
                  f"{(ap.ssid if ap else '-')[:21]:<22}"
                  f"{s.rssi if s.rssi is not None else '-':>6}{s.packets:>7}  {st}")
        return
    t = Table(title=f"Client Devices ({len(stations)})", box=box.ROUNDED,
              header_style="bold magenta", expand=True)
    for col in ("MAC", "Vendor", "Rnd", "Network", "IP / Host", "Signal",
                "Pkts", "Data", "Dwell", "State", "Probed SSIDs"):
        t.add_column(col, max_width=26 if col == "Probed SSIDs" else None)
    for ap, s, st in stations:
        ipinfo = s.ip_address + (f" {s.hostname}" if s.hostname else "")
        t.add_row(s.mac, (s.vendor or "?")[:18],
                  "[yellow]Y[/]" if s.is_randomized else "",
                  (ap.ssid or ap.bssid) if ap else "[dim]-[/]",
                  ipinfo or "[dim]-[/]",
                  f"[{_c(s.rssi)}]{s.rssi if s.rssi is not None else '--'}dBm[/]",
                  str(s.packets), str(s.data_packets), f"{s.dwell_s:.0f}s",
                  "[green]assoc[/]" if st == "associated" else "[dim]probe[/]",
                  ", ".join(sorted(s.probed_ssids))[:26])
    console.print(t)


def print_detail(ap: AccessPoint) -> None:
    """A-to-Z dump of one access point."""
    lines = [
        ("SSID", ap.ssid or "<hidden>"), ("BSSID", ap.bssid),
        ("Vendor / OUI", ap.vendor or "unknown"), ("Band", ap.band),
        ("Channel", f"{ap.channel} ({ap.frequency} MHz, {ap.width_mhz or 20} MHz wide)"),
        ("Signal", f"{ap.rssi} dBm  ({rssi_quality(ap.rssi)}% quality, "
                   f"{rssi_bars(ap.rssi)})"),
        ("Signal range", f"min {ap.rssi_min} / max {ap.rssi_max} dBm"),
        ("Noise / SNR", f"{ap.noise if ap.noise is not None else '?'} dBm / "
                        f"{ap.snr if ap.snr is not None else '?'} dB"),
        ("Est. distance", f"~{ap.distance_m} m" if ap.distance_m else "?"),
        ("Encryption", ap.encryption),
        ("Ciphers", ", ".join(ap.ciphers) or "-"),
        ("Auth suites", ", ".join(ap.auth_suites) or "-"),
        ("PMF (802.11w)", ap.pmf or "unknown"),
        ("WPS", "ENABLED" if ap.wps else "disabled"),
        ("Security score", f"{ap.security_score}/100  grade {ap.security_grade}"),
        ("PHY modes", ", ".join(f"802.11{m}" for m in ap.phy_modes) or "-"),
        ("Max rate", f"{ap.max_rate_mbps} Mbit/s" if ap.max_rate_mbps else "-"),
        ("Beacon interval", f"{ap.beacon_interval} TU" if ap.beacon_interval else "-"),
        ("DTIM period", ap.dtim if ap.dtim is not None else "-"),
        ("Country", ap.country or "-"), ("Mesh", "yes" if ap.is_mesh else "no"),
        ("Hidden SSID", "yes" if ap.hidden else "no"),
        ("Beacons seen", ap.beacons), ("Data frames", ap.data_packets),
        ("BSS load STA count", ap.raw.get("bss_load_sta_count", "-")),
        ("Channel utilisation", f"{ap.raw.get('channel_utilization_pct', '-')}%"),
        ("EAPOL handshakes", ap.raw.get("eapol_frames", 0)),
        ("Deauth frames", ap.raw.get("deauths", 0)),
        ("Connected devices", f"{ap.client_count} ({ap.active_client_count} active)"),
        ("Data source", ap.source),
    ]
    body = "\n".join(f"[cyan]{k:<22}[/] {v}" for k, v in lines) if _RICH \
        else "\n".join(f"{k:<22} {v}" for k, v in lines)
    risks = "\n".join(f"  ! {r}" for r in ap.risks) or "  none detected"
    if _RICH:
        console.print(Panel(body + f"\n\n[bold red]Risks[/]\n{risks}",
                            title=f"[bold]{ap.ssid or '<hidden>'}[/] — A-to-Z detail",
                            border_style="cyan", box=box.ROUNDED))
    else:
        print("=" * 70)
        print(body)
        print("\nRisks:\n" + risks)
        print("=" * 70)
    if ap.stations:
        if _RICH:
            t = Table(title="Connected devices", box=box.SIMPLE,
                      header_style="bold magenta")
            for c in ("MAC", "Vendor", "Randomized", "IP", "Hostname", "RSSI",
                      "Packets", "Data", "Bytes", "First seen", "Last seen"):
                t.add_column(c)
            for s in sorted(ap.stations.values(), key=lambda x: -(x.rssi or -999)):
                r = s.to_row()
                t.add_row(s.mac, s.vendor or "?", "yes" if s.is_randomized else "no",
                          s.ip_address or "-", s.hostname or "-",
                          f"{s.rssi if s.rssi is not None else '--'} dBm",
                          str(s.packets), str(s.data_packets), str(s.bytes_seen),
                          r["first_seen"], r["last_seen"])
            console.print(t)
        else:
            for s in ap.stations.values():
                print(f"  {s.mac}  {s.vendor:<20} {s.ip_address:<16} "
                      f"{s.rssi} dBm  {s.packets} pkts")


def print_summary(engine: Engine) -> None:
    s = engine.summary()
    rows = [
        ("Access points", s["access_points"]),
        ("Unique SSIDs", s["unique_ssids"]),
        ("Hidden SSIDs", s["hidden_ssids"]),
        ("Client devices", f"{s['connected_devices']} ({s['active_devices']} active)"),
        ("Unassociated/probing", s["unassociated_devices"]),
        ("Randomized MACs", s["randomized_macs"]),
        ("Open networks", s["open_networks"]),
        ("WEP networks", s["wep_networks"]),
        ("WPA3 networks", s["wpa3_networks"]),
        ("WPS enabled", s["wps_enabled"]),
        ("Rogue/evil-twin alerts", s["rogue_alerts"]),
        ("Signal range", f"{s['strongest_rssi_dbm']} .. {s['weakest_rssi_dbm']} dBm"),
        ("Bands", ", ".join(f"{k}:{v}" for k, v in s["bands"].items())),
        ("Recommended channels", ", ".join(
            f"{b}:{'/'.join(map(str, c))}" for b, c in s["recommended_channels"].items())),
    ]
    body = "\n".join(f"[cyan]{k:<24}[/] [bold]{v}[/]" for k, v in rows) if _RICH \
        else "\n".join(f"{k:<24} {v}" for k, v in rows)
    if _RICH:
        console.print(Panel(body, title="Survey Summary", border_style="green",
                            box=box.ROUNDED))
    else:
        print("\n--- Survey Summary ---")
        print(body)


def print_congestion(engine: Engine) -> None:
    cong = engine.channel_congestion()
    if not cong:
        return
    for band, rows in cong.items():
        if not _RICH:
            print(f"\n{band}:")
            for r in rows:
                bar = "#" * min(40, r["total_interferers"] * 3)
                print(f"  ch {r['channel']:>3} | {bar:<40} {r['ap_count']} APs")
            continue
        t = Table(title=f"{band} channel utilisation", box=box.SIMPLE,
                  header_style="bold yellow")
        for c in ("Ch", "APs", "Overlap", "Clients", "Strongest", "Load"):
            t.add_column(c, justify="right" if c != "Load" else "left")
        for r in rows:
            load = r["total_interferers"]
            colour = "green" if load <= 2 else ("yellow" if load <= 5 else "red")
            t.add_row(str(r["channel"]), str(r["ap_count"]),
                      str(r["overlapping_aps"]), str(r["clients"]),
                      f"{r['strongest_rssi_dbm']} dBm",
                      f"[{colour}]{'█' * min(30, load * 2)}[/]")
        console.print(t)


def print_rogues(engine: Engine) -> None:
    alerts = engine.rogue_candidates()
    if not alerts:
        return
    if not _RICH:
        print("\n!! Rogue / evil-twin alerts:")
        for a in alerts:
            print(f"  [{a['severity']}] {a['ssid']}: {a['reasons']}")
        return
    t = Table(title="Rogue / Evil-Twin Alerts", box=box.ROUNDED,
              header_style="bold red")
    for c in ("SSID", "BSSIDs", "Severity", "Reasons"):
        t.add_column(c)
    for a in alerts:
        t.add_row(a["ssid"], str(a["bssid_count"]),
                  f"[red]{a['severity']}[/]", a["reasons"])
    console.print(t)
