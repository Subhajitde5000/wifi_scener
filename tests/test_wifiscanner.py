"""Test suite. Run:  python -m pytest tests/ -v   (or: python tests/test_wifiscanner.py)"""
import csv
import glob
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wifiscanner.models import (AccessPoint, Station, band_of, channel_to_freq,
                                estimate_distance_m, freq_to_channel,
                                rssi_quality)
from wifiscanner.engine import Engine, merge_ap
from wifiscanner.export import export_all, AP_COLUMNS, STA_COLUMNS
from wifiscanner.oui import is_randomized, is_multicast, lookup, normalize
from wifiscanner.backends.survey import _parse_iw, _parse_security, scan_netsh

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixture.pcap")


# ------------------------------------------------------------------- RF math

def test_channel_freq_roundtrip():
    for ch in (1, 6, 11, 13, 36, 44, 100, 149, 165):
        f = channel_to_freq(ch)
        assert freq_to_channel(f) == ch, f"ch {ch} -> {f}"
    assert channel_to_freq(14) == 2484 and freq_to_channel(2484) == 14


def test_band_classification():
    assert band_of(2437) == "2.4GHz"
    assert band_of(5220) == "5GHz"
    assert band_of(6135) == "6GHz"
    assert band_of(None) == "unknown"


def test_rssi_quality():
    assert rssi_quality(-30) == 100
    assert rssi_quality(-100) == 0
    assert rssi_quality(-75) == 50
    assert rssi_quality(None) is None


def test_distance_monotonic_and_sane():
    d_near = estimate_distance_m(-40, 2437)
    d_far = estimate_distance_m(-85, 2437)
    assert d_near < d_far
    assert 0.5 < d_near < 20, d_near        # -40 dBm is a few metres
    assert d_far < 1000
    # higher frequency attenuates faster -> larger implied distance is wrong;
    # for the same RSSI a 5 GHz signal must have travelled *less* far.
    assert estimate_distance_m(-60, 5220) < estimate_distance_m(-60, 2437)
    assert estimate_distance_m(None, 2437) is None


# ---------------------------------------------------------------- MAC / OUI

def test_randomized_mac_detection():
    assert is_randomized("0A:1B:2C:3D:4E:5F")     # locally administered
    assert is_randomized("9E:12:34:56:78:9A")
    assert not is_randomized("AC:BC:32:01:02:03")  # real Apple OUI
    assert not is_randomized("F0:9F:C2:11:22:33")


def test_multicast_and_normalize():
    assert is_multicast("01:00:5E:00:00:01")
    assert is_multicast("FF:FF:FF:FF:FF:FF")
    assert not is_multicast("AC:BC:32:01:02:03")
    assert normalize("ac-bc-32-01-02-03") == "AC:BC:32:01:02:03"


def test_vendor_lookup():
    assert "Apple" in lookup("AC:BC:32:01:02:03")
    assert "Raspberry" in lookup("B8:27:EB:11:22:33")
    assert lookup("0A:1B:2C:3D:4E:5F") == "(randomized MAC)"


# ------------------------------------------------------------- security model

def _ap(**kw):
    base = dict(bssid="AA:BB:CC:DD:EE:FF", ssid="X")
    base.update(kw)
    return AccessPoint(**base)


def test_security_scoring_order():
    wpa3 = _ap(security=["WPA3"], ciphers=["CCMP"], pmf="required")
    wpa2 = _ap(security=["WPA2"], ciphers=["CCMP"], pmf="disabled")
    wep = _ap(security=["WEP"])
    open_ = _ap(security=["OPEN"])
    assert wpa3.security_score > wpa2.security_score > wep.security_score
    assert open_.security_score < wpa2.security_score
    assert wpa3.security_grade == "A+"
    assert open_.security_grade == "F"


def test_wps_and_tkip_penalties():
    clean = _ap(security=["WPA2"], ciphers=["CCMP"], pmf="required")
    wps = _ap(security=["WPA2"], ciphers=["CCMP"], pmf="required", wps=True)
    tkip = _ap(security=["WPA2"], ciphers=["TKIP"], pmf="required")
    assert wps.security_score < clean.security_score
    assert tkip.security_score < clean.security_score
    assert "wps-enabled:pixie-dust" in wps.risks
    assert "tkip-cipher-deprecated" in tkip.risks


def test_open_network_risk():
    assert "open-network:traffic-in-cleartext" in _ap(security=[]).risks
    assert _ap(security=[]).encryption == "OPEN"


# ------------------------------------------------------------ client tracking

def test_station_accounting():
    ap = _ap()
    s = Station(mac="AC:BC:32:01:02:03")
    ap.add_station(s)
    s.observe(-55, data=True, length=200)
    s.observe(-60, data=False, length=50)
    assert ap.client_count == 1
    assert ap.active_client_count == 1
    assert s.packets == 2 and s.data_packets == 1 and s.bytes_seen == 250
    assert s.rssi_min == -60 and s.rssi_max == -55
    assert s.bssid == ap.bssid


def test_add_station_is_idempotent():
    ap = _ap()
    for _ in range(5):
        ap.add_station(Station(mac="AC:BC:32:01:02:03", packets=1))
    assert ap.client_count == 1
    assert ap.stations["AC:BC:32:01:02:03"].packets == 5


# -------------------------------------------------------------------- engine

def test_merge_prefers_richer_data():
    a = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", rssi=-70, source="nmcli")
    b = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", ssid="Real", rssi=-55,
                    channel=6, security=["WPA3"], wps=True, source="iw")
    m = merge_ap(a, b)
    assert m.ssid == "Real" and m.rssi == -55 and m.channel == 6
    assert m.security == ["WPA3"] and m.wps
    assert "nmcli" in m.source and "iw" in m.source


def test_engine_dedupes_by_bssid():
    e = Engine()
    e.ingest([AccessPoint(bssid="aa:bb:cc:dd:ee:ff", rssi=-70)])
    e.ingest([AccessPoint(bssid="AA:BB:CC:DD:EE:FF", ssid="Late", rssi=-60)])
    assert len(e.aps) == 1
    assert e.aps["AA:BB:CC:DD:EE:FF"].ssid == "Late"


def test_channel_congestion_and_recommendation():
    e = Engine()
    for i in range(5):
        e.ingest([AccessPoint(bssid=f"AA:BB:CC:00:00:0{i}", ssid=f"N{i}",
                              channel=1, frequency=2412, rssi=-50)])
    e.ingest([AccessPoint(bssid="AA:BB:CC:00:00:99", ssid="Quiet",
                          channel=11, frequency=2462, rssi=-70)])
    cong = e.channel_congestion()["2.4GHz"]
    ch1 = [r for r in cong if r["channel"] == 1][0]
    assert ch1["ap_count"] == 5
    # ch 1 is saturated; the recommender must not pick it
    best = e.best_channels()["2.4GHz"]
    assert best[0] in (6, 11) and best[-1] == 1


def test_rogue_detection():
    e = Engine()
    e.ingest([AccessPoint(bssid="F0:9F:C2:00:00:01", ssid="Cafe",
                          vendor="Ubiquiti", security=["WPA2"]),
              AccessPoint(bssid="00:11:22:33:44:55", ssid="Cafe",
                          vendor="Evil Inc", security=["OPEN"])])
    alerts = e.rogue_candidates()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert "open clone" in alerts[0]["reasons"]


def test_summary_counts():
    e = Engine()
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", ssid="N", security=["OPEN"],
                     channel=6, frequency=2437, rssi=-50)
    ap.add_station(Station(mac="AC:BC:32:01:02:03", data_packets=5))
    ap.add_station(Station(mac="0A:1B:2C:3D:4E:5F", is_randomized=True))
    e.ingest([ap])
    s = e.summary()
    assert s["access_points"] == 1 and s["connected_devices"] == 2
    assert s["active_devices"] == 1 and s["open_networks"] == 1
    assert s["randomized_macs"] == 1


# ------------------------------------------------------------------- parsers

IW_SAMPLE = """BSS f0:9f:c2:11:22:33(on wlan0)
\tlast seen: 100 ms ago
\tfreq: 5220
\tbeacon interval: 100 TUs
\tsignal: -48.00 dBm
\tSSID: HomeFiber-5G
\tDS Parameter set: channel 44
\tCountry: US\tEnvironment: Indoor/Outdoor
\tTIM: DTIM Count 0 DTIM Period 2
\tRSN:\t * Version: 1
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: SAE
\t\t * Capabilities: 1-PTKSA-RC MFP-required (0x00c0)
\tHT capabilities:
\tVHT capabilities:
\tSupported rates: 6.0* 9.0 12.0* 54.0
BSS 50:c7:bf:aa:00:11(on wlan0)
\tfreq: 2462
\tsignal: -71.00 dBm
\tSSID: CafeGuest
\tDS Parameter set: channel 11
"""


def test_parse_iw_output():
    aps = _parse_iw(IW_SAMPLE)
    assert len(aps) == 2
    a = aps[0]
    assert a.bssid == "F0:9F:C2:11:22:33" and a.ssid == "HomeFiber-5G"
    assert a.channel == 44 and a.frequency == 5220 and a.band == "5GHz"
    assert a.rssi == -48 and a.dtim == 2 and a.country == "US"
    assert a.security == ["WPA3"] and a.pmf == "required"
    assert "CCMP" in a.ciphers and "n" in a.phy_modes and "ac" in a.phy_modes
    assert a.max_rate_mbps == 54.0
    assert aps[1].security == ["OPEN"]


def test_parse_security_strings():
    proto, ciphers, auth, pmf = _parse_security("WPA2", "", "pair_ccmp psk")
    assert proto == ["WPA2"] and "CCMP" in ciphers and "PSK" in auth
    proto, _, _, _ = _parse_security("")
    assert proto == ["OPEN"]
    proto, _, _, pmf = _parse_security("WPA3", "", "sae")
    assert "WPA3" in proto and pmf == "required"


# -------------------------------------------------------------- pcap -> CSV

def _run_offline():
    if not os.path.exists(FIXTURE):
        subprocess.run([sys.executable, os.path.join(HERE, "make_fixture.py")],
                       check=True, capture_output=True)
    from wifiscanner.backends.sniffer import MonitorSniffer, scapy_available
    assert scapy_available(), "scapy required"
    e = Engine()
    sn = MonitorSniffer(iface="offline")
    sn.read_pcap(FIXTURE)
    e.ingest(sn.results())
    e.ingest_unassociated(sn.unassociated)
    e.sniffer_stats = sn.stats()
    return e


def test_pcap_client_attribution():
    """The core claim: count devices per AP without joining the network."""
    e = _run_offline()
    by_ssid = {a.ssid: a for a in e.aps.values() if a.ssid}
    assert len(e.aps) == 5, list(e.aps)
    assert by_ssid["HomeFiber-5G"].client_count == 3
    assert by_ssid["HomeFiber"].client_count == 4
    assert by_ssid["Neighbour_2.4"].client_count == 1
    assert len(e.unassociated) == 3               # probe-request-only devices
    assert e.summary()["connected_devices"] == 10


def test_pcap_ie_parsing():
    e = _run_offline()
    by_ssid = {a.ssid: a for a in e.aps.values() if a.ssid}
    wpa3 = by_ssid["HomeFiber-5G"]
    assert wpa3.security == ["WPA3"], wpa3.security
    assert wpa3.pmf == "required" and wpa3.security_grade == "A+"
    assert "SAE" in wpa3.auth_suites and "CCMP" in wpa3.ciphers
    assert wpa3.channel == 44 and wpa3.band == "5GHz"
    assert wpa3.country == "US" and wpa3.dtim == 2
    assert wpa3.raw["bss_load_sta_count"] == 3
    home = by_ssid["HomeFiber"]
    assert home.wps and "PSK" in home.auth_suites and home.security == ["WPA2"]
    assert "wps-enabled:pixie-dust" in home.risks


def test_pcap_probe_requests_and_deauth():
    e = _run_offline()
    probes = set()
    for s in e.unassociated.values():
        probes |= s.probed_ssids
    assert {"HomeOffice", "Starbucks", "AirportFree"} <= probes
    assert e.sniffer_stats["deauth_frames"] == 9


def test_pcap_randomized_mac_flagged():
    e = _run_offline()
    macs = {s.mac: s for a in e.aps.values() for s in a.stations.values()}
    assert macs["0A:1B:2C:3D:4E:5F"].is_randomized
    assert not macs["AC:BC:32:01:02:03"].is_randomized


def test_csv_export_schema_and_content():
    e = _run_offline()
    with tempfile.TemporaryDirectory() as td:
        files = export_all(e, td, "t", ("csv", "json", "html", "md"))
        assert len(files) == 8
        net = os.path.join(td, "t_networks.csv")
        with open(net, encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        assert list(rows[0]) == AP_COLUMNS          # exact, stable schema
        assert len(rows) == 5
        assert all(r["scan_id"] for r in rows)
        assert sum(int(r["connected_devices"]) for r in rows) == 10

        with open(os.path.join(td, "t_devices.csv"), encoding="utf-8-sig") as fh:
            drows = list(csv.DictReader(fh))
        assert list(drows[0]) == STA_COLUMNS
        assert len(drows) == 13                     # 10 associated + 3 probing
        assert sum(1 for r in drows if r["state"] == "associated") == 10
        assert all(r["associated_bssid"] for r in drows
                   if r["state"] == "associated")

        for name in ("t_channels.csv", "t_rogue_alerts.csv", "t_summary.csv",
                     "t.json", "t.html", "t.md"):
            p = os.path.join(td, name)
            assert os.path.getsize(p) > 100, name


def test_csv_is_excel_safe():
    """Values containing commas/quotes must survive a round trip."""
    e = Engine()
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", ssid='Evil, "Twin" Net',
                     channel=6, frequency=2437, rssi=-50, security=["WPA2"])
    e.ingest([ap])
    with tempfile.TemporaryDirectory() as td:
        export_all(e, td, "q", ("csv",))
        with open(os.path.join(td, "q_networks.csv"), encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
    assert rows[0]["ssid"] == 'Evil, "Twin" Net'


# ------------------------------------------------------------------ CLI smoke

def test_cli_interfaces_and_help():
    root = os.path.dirname(HERE)
    for args in (["--help"], ["interfaces"], ["scan", "--help"],
                 ["monitor", "--help"], ["--version"]):
        p = subprocess.run([sys.executable, "main.py"] + args, cwd=root,
                           capture_output=True, text=True, timeout=90)
        assert p.returncode == 0, f"{args}: {p.stderr}"


def test_cli_offline_end_to_end():
    root = os.path.dirname(HERE)
    if not os.path.exists(FIXTURE):
        subprocess.run([sys.executable, "tests/make_fixture.py"], cwd=root,
                       check=True, capture_output=True)
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.run(
            [sys.executable, "main.py", "--no-banner", "-q", "offline",
             FIXTURE, "-o", td, "--format", "csv", "json"],
            cwd=root, capture_output=True, text=True, timeout=180)
        assert p.returncode == 0, p.stderr
        assert glob.glob(os.path.join(td, "*_networks.csv"))
        assert glob.glob(os.path.join(td, "*_devices.csv"))
        assert glob.glob(os.path.join(td, "*.json"))


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in fns:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(fns) - failed}/{len(fns)} tests passed")
    sys.exit(1 if failed else 0)
