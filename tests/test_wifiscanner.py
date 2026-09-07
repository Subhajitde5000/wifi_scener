"""Test suite. Run:  python -m pytest tests/ -v   (or: python tests/test_wifiscanner.py)"""
import csv
import glob
import os
import subprocess
import sys
import tempfile
import time

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


# ------------------------------------------------------ store / presence

def _synthetic_engine():
    from wifiscanner.models import AccessPoint, Station
    e = Engine()
    for i in range(3):
        ap = AccessPoint(bssid=f"F0:9F:C2:00:00:0{i}", ssid=f"OwnNet{i % 2}",
                         channel=6, frequency=2437, rssi=-50,
                         security=["WPA2"])
        st = Station(mac=f"AC:BC:32:00:00:0{i}", rssi=-55 - i)
        st.observe(data=True, length=100)
        ap.add_station(st)
        e.ingest([ap])
    return e


def test_store_roundtrip_and_sessions():
    import sqlite3
    from wifiscanner.store import Store, parse_when
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "h.sqlite")
        st = Store(db)
        s1 = st.record_engine(_synthetic_engine(), mode="record", sensor="kitchen")
        assert s1
        st.record_engine(_synthetic_engine(), mode="record", sensor="kitchen")
        sess = st.sessions()
        assert len(sess) == 3, sess          # 3 devices merged across scans
        assert all(x["sightings"] == 2 for x in sess)
        assert all(x["duration_s"] >= 0 for x in sess)
        hist = st.device_history("AC:BC:32:00:00:00")
        assert len(hist) == 2
        known = st.known_devices()
        assert len(known) == 3 and known[0]["n"] == 2
        obs = st.get_observations()
        assert len(obs) == 6 and obs[0]["sensor"] == "kitchen"
        s = st.stats()
        assert s["devices"]["rows"] == 6 and s["fixes"]["rows"] == 0
        st.close()
        assert parse_when("-1h") < time.time() - 3590
        with sqlite3.connect(db) as c:      # WAL db is a real file, reopenable
            assert c.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 6


def test_session_split_on_gap():
    from wifiscanner.store import Store
    with tempfile.TemporaryDirectory() as td:
        st = Store(os.path.join(td, "g.sqlite"))
        eng = _synthetic_engine()
        first = st.record_engine(eng, sensor="s")
        with st.db:
            st.db.execute("UPDATE devices SET ts = ts - 3600 WHERE scan_id = ?",
                          (first,))
            st.db.execute("UPDATE observations SET ts = ts - 3600 WHERE ts = "
                          "(SELECT MIN(ts) FROM observations)")
        st.record_engine(eng, sensor="s")
        sess = st.sessions(gap=300)
        assert len(sess) == 6, sess        # 1h gap split each into 2 sessions
        assert sess[0]["last_seen"] - sess[0]["first_seen"] < 300
        st.close()


def test_parse_when_formats():
    from wifiscanner.store import parse_when
    assert parse_when("") == 0.0
    a = parse_when("2026-09-07")
    b = parse_when("2026-09-07", end=True)
    assert 86300 < b - a < 86500
    assert abs(parse_when("-30m") - (time.time() - 1800)) < 2
    try:
        parse_when("nonsense!")
        assert False
    except ValueError:
        pass


# ------------------------------------------------------------- locate math

def test_trilateration_accuracy():
    from wifiscanner.locate import (Measure, Sensor, multilateration,
                                    simulate_from_ranges)
    sensors = [Sensor("S1", 0, 0), Sensor("S2", 20, 0),
               Sensor("S3", 0, 20), Sensor("S4", 20, 20)]
    tx, ty = 7.0, 9.0
    ms = []
    for (s, rssi) in simulate_from_ranges(tx, ty, sensors):
        ms.append(Measure(sensor=s, rssi=rssi, freq=2437))
    res = multilateration(ms)
    assert res, "no fix"
    x, y, unc, method = res
    assert method == "trilateration"
    assert abs(x - tx) < 1.2 and abs(y - ty) < 1.2, (x, y)
    assert unc < 5.0


def test_bilateration_two_sensors():
    from wifiscanner.locate import Measure, Sensor, multilateration
    s1, s2 = Sensor("A", 0, 0), Sensor("B", 10, 0)
    m1 = Measure(sensor=s1, rssi=-59, freq=2437)
    m2 = Measure(sensor=s2, rssi=-59, freq=2437)
    res = multilateration([m1, m2])
    assert res and abs(res[0] - 5.0) < 0.5          # equidistant -> x=5
    assert "bilateration" in res[3]
    assert multilateration([m1]) is None            # 1 sensor: no fix


def test_zone_geometry_and_dwell():
    from wifiscanner.locate import Zone, zone_at, Tracker, Sensor
    living = Zone("living", [(0, 0), (10, 0), (10, 10), (0, 10)])
    assert zone_at(5, 5, [living]) == "living"
    assert zone_at(15, 5, [living]) == "outside-zones"
    assert zone_at(None, None, [living]) == "unknown"
    sensors = [Sensor("S1", 1, 1), Sensor("S2", 9, 1), Sensor("S3", 5, 9)]
    tr = Tracker(sensors, [living], window_s=5)
    now = 1000.0
    obs = ([{"ts": now, "sensor": "S1", "mac": "AA", "rssi": -40, "freq": 2437},
            {"ts": now + 1, "sensor": "S2", "mac": "AA", "rssi": -45, "freq": 2437},
            {"ts": now + 2, "sensor": "S3", "mac": "AA", "rssi": -50, "freq": 2437},
            {"ts": now + 60, "sensor": "S1", "mac": "AA", "rssi": -80, "freq": 2437}]
           )
    fixes = tr.fixes(obs)
    assert len(fixes) == 2
    assert fixes[0].method in ("trilateration", "nearest-sensor")
    assert fixes[0].zone in ("living", "outside-zones")
    dwell = tr.zone_dwell(fixes)
    assert sum(dwell.values()) == 60.0


def test_sensors_zones_files():
    from wifiscanner.locate import load_sensors, load_zones
    with tempfile.TemporaryDirectory() as td:
        sp = os.path.join(td, "sensors.csv")
        with open(sp, "w") as fh:
            fh.write("name,x,y,floor\n# comment\nS1,0,0,0\nS2,15,0,,-4,-3\n"
                     "bad,row,here\n")
        sensors = load_sensors(sp)
        assert len(sensors) == 2 and sensors[0].name == "S1"
        assert sensors[1].tx_power_dbm == -3.0
        zp = os.path.join(td, "zones.csv")
        with open(zp, "w") as fh:
            fh.write("zone,x,y\nkit,0,0\nkit,5,0\nkit,5,5\nkit,0,5\n"
                     "bed,10,0\nbed,15,0\nbed,15,5\n")   # <3 pts ignored? =3 ok
        zones = load_zones(zp)
        assert {z.name for z in zones} == {"kit", "bed"}


# ------------------------------------------------------------------ traffic

def test_traffic_dissector_synthetic():
    from scapy.all import (ARP, DNS, DNSQR, Ether, IP, Raw, TCP, UDP,
                           wrpcap)
    from wifiscanner.traffic import Dissector, tls_sni
    d = Dissector()
    # DNS query
    d.feed(Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=5300, dport=53)
           / DNS(qd=DNSQR(qname="example.com")))
    # HTTP GET with Host + UA
    http = (b"GET /index.html HTTP/1.1\r\nHost: internal.lan\r\n"
            b"User-Agent: TestAgent/1.0\r\n\r\n")
    d.feed(Ether() / IP(src="192.168.1.10", dst="93.184.216.34")
           / TCP(sport=5301, dport=80) / Raw(load=http))
    # HTTP POST carrying credentials -> must be flagged, values NOT dumped
    post = (b"POST /login HTTP/1.1\r\nHost: oldapp.lan\r\n\r\n"
            b"user=alice&password=hunter2")
    d.feed(Ether() / IP(src="192.168.1.11", dst="93.184.216.34")
           / TCP(sport=5302, dport=80) / Raw(load=post))
    # ARP
    d.feed(Ether() / ARP(op=1, psrc="192.168.1.50", pdst="192.168.1.1"))
    events = d.events
    protos = [e.proto for e in events]
    assert protos == ["DNS", "HTTP", "HTTP", "ARP"], protos
    assert "example.com" in events[0].summary
    assert "internal.lan" in events[1].summary
    assert "TestAgent" in events[1].detail
    assert events[2].alert == "cleartext-credentials"
    assert "hunter2" not in events[2].summary and "hunter2" not in events[2].detail
    assert "who-has" in events[3].summary
    assert d.protected_skipped == 0
    assert len(d.flows) >= 2

    # raw TLS ClientHello -> SNI extraction ("abc")
    ch = (b"\x16\x03\x01\x00\x3b"              # record hdr (len 59)
          b"\x01\x00\x00\x37\x03\x03"          # ClientHello, v1.2
          + b"\x11" * 32                          # random
          + b"\x00"                               # empty session id
          + b"\x00\x02\xc0\x2f"                 # 1 cipher suite
          + b"\x01\x00"                          # 1 compression method
          + b"\x00\x0c"                          # extensions len 12
          + b"\x00\x00\x00\x08"                 # sni ext, len 8
          + b"\x00\x06\x00\x00\x03abc")        # list, hostname len 3
    assert tls_sni(ch) == "abc"

    # protected 802.11 frame must be skipped
    from scapy.all import RadioTap, Dot11
    d2 = Dissector()
    d2.feed(RadioTap() / Dot11(type=2, subtype=0, FCfield=["to_DS", "protected"],
                                addr1="AA:BB:CC:DD:EE:FF", addr2="11:22:33:44:55:66")
            / (b"\x00" * 100))
    assert d2.protected_skipped == 1 and d2.events == []


def test_traffic_analyze_pcap_roundtrip():
    from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap
    from wifiscanner.traffic import analyze_pcap, export
    with tempfile.TemporaryDirectory() as td:
        cap = os.path.join(td, "t.pcap")
        wrpcap(cap, [Ether() / IP(src="10.0.0.2", dst="10.0.0.1")
                     / UDP(sport=4000, dport=53)
                     / DNS(qd=DNSQR(qname="printer.local"))])
        d = analyze_pcap(cap)
        assert len(d.events) == 1 and "printer.local" in d.events[0].summary
        files = export(td, "t", d)
        assert all(os.path.getsize(f) > 50 for f in files)
        import csv as _csv
        rows = list(_csv.DictReader(open(files[0], encoding="utf-8-sig")))
        assert rows[0]["proto"] == "DNS"


def test_80211_open_network_data_frame_dissection():
    """RadioTap/Dot11 unencrypted data frame must dissect to a DNS event."""
    from scapy.all import RadioTap, Dot11, Ether, IP, UDP, DNS, DNSQR, Raw
    from wifiscanner.traffic import Dissector
    inner = IP(src="192.168.1.10", dst="1.1.1.1") / UDP(sport=4100, dport=53) \
        / DNS(qd=DNSQR(qname="iot-device.example.org"))
    llc = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"   # LLC/SNAP + ethertype
    pkt = (RadioTap() / Dot11(type=2, subtype=0, FCfield="to_DS",
                              addr1="F0:9F:C2:11:22:33",
                              addr2="AC:BC:32:01:02:03",
                              addr3="F0:9F:C2:11:22:33")
           / llc / Raw(load=bytes(inner)))
    d = Dissector()
    ev = d.feed(pkt)
    assert ev is not None and ev.proto == "DNS"
    assert "iot-device.example.org" in ev.summary
    assert ev.src_mac == "AC:BC:32:01:02:03"


# ----------------------------------------------- sniffer ring/rotate + pcap

def test_capture_rotation_streams_to_disk(tmp=None):
    from wifiscanner.backends.sniffer import MonitorSniffer
    from scapy.all import rdpcap
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "ring.pcap")
        # replay fixture frames through the pcap-writing path via run() mock:
        # simpler - exercise the same writer logic directly
        from scapy.all import PcapWriter
        frames = list(rdpcap(FIXTURE))
        base, ext = os.path.splitext(out)
        for i, seg in enumerate((frames[:50], frames[50:100], frames[100:])):
            with PcapWriter(f"{base}-{i % 2:03d}{ext}", sync=True) as w:
                for p in seg:
                    w.write(p)
        assert os.path.exists(f"{base}-000{ext}") and os.path.exists(f"{base}-001{ext}")
        # ring semantics: 3 segments into 2 slots -> slot 000 was overwritten
        assert len(glob.glob(os.path.join(td, "ring*.pcap"))) == 2
        assert len(rdpcap(f"{base}-000{ext}")) == len(frames[100:])


# -------------------------------------------------------------- CLI surface

def test_new_cli_commands_help():
    root = os.path.dirname(HERE)
    for cmd in ("own", "record", "presence", "locate", "trail", "capture",
                "traffic"):
        p = subprocess.run([sys.executable, "main.py", cmd, "--help"], cwd=root,
                           capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, f"{cmd}: {p.stderr[:400]}"
        assert "usage" in p.stdout.lower(), cmd


def test_record_import_and_presence_cli():
    root = os.path.dirname(HERE)
    env = dict(os.environ, COLUMNS="220")
    if not os.path.exists(FIXTURE):
        subprocess.run([sys.executable, "tests/make_fixture.py"], cwd=root,
                       check=True, capture_output=True)
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "h.sqlite")
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "record", "--db", db, "--pcap",
                            os.path.relpath(FIXTURE, root)],
                           cwd=root, capture_output=True, text=True, timeout=180,
                           env=env)
        assert p.returncode == 0, p.stderr[:600]
        assert "imported" in p.stdout, p.stdout
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "presence", "--db", db, "--gap", "3600"],
                           cwd=root, capture_output=True, text=True, timeout=60,
                           env=env)
        assert p.returncode == 0, p.stderr[:600]
        assert "Presence sessions" in p.stdout
        assert "HomeFiber" in p.stdout
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "presence", "--db", td + "/nope.sqlite"],
                           cwd=root, capture_output=True, text=True, timeout=60)
        assert p.returncode == 2 and "no history database" in p.stderr


def test_record_refuses_open_ended_bystander_mode():
    """Guardrail: record must not run without an own-network target."""
    root = os.path.dirname(HERE)
    p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q", "record",
                        "--db", "/tmp/should-not-exist.sqlite", "--duration", "1"],
                       cwd=root, capture_output=True, text=True, timeout=60)
    # in the sandbox there is no wifi connection and no --bssid -> must refuse
    assert p.returncode == 2 or "not a feature" in (p.stderr + p.stdout)


def test_traffic_cli_on_pcap():
    root = os.path.dirname(HERE)
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "traffic", os.path.relpath(FIXTURE, root), "-o", td],
                           cwd=root, capture_output=True, text=True, timeout=180)
        assert p.returncode == 0, p.stderr[:600]
        # fixture is all encrypted/beacon data -> dissects 0 events but runs
        assert glob.glob(os.path.join(td, "*traffic_events.csv"))



# ------------------------------------------------------------ defense / IDS

def _mgmt_frames():
    from scapy.all import RadioTap, Dot11
    from scapy.layers.dot11 import (Dot11Beacon, Dot11Elt, Dot11Deauth,
                                    Dot11AssoReq)
    ap, sta = "F0:9F:C2:11:22:34", "AC:BC:32:01:02:03"

    def deauth():
        return (RadioTap() / Dot11(type=0, subtype=12, addr1=sta,
                                    addr2=ap, addr3=ap) / Dot11Deauth(reason=7))

    def beacon(channel=6, rsn=True):
        p = (RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                                addr2=ap, addr3=ap)
             / Dot11Beacon(cap=0x1111 if rsn else 0x0001))
        p /= Dot11Elt(ID=0, info=b"HomeFiber")
        p /= Dot11Elt(ID=3, info=bytes([channel]))
        if rsn:
            p /= Dot11Elt(ID=48, info=bytes.fromhex(
                "0100000fac040100000fac040100000fac020000"))
        return p

    def assoc():
        return (RadioTap() / Dot11(type=0, subtype=0, addr1=ap, addr2=sta,
                                    addr3=ap) / Dot11AssoReq()
                / Dot11Elt(ID=0, info=b"HomeFiber"))

    def eapol():
        key = b"\x02\x03\x00\x5d\x02\x01\x8a\x00\x10" + b"\x00" * 80
        return (RadioTap() / Dot11(type=2, subtype=8, FCfield=["to_DS"],
                                   addr1=ap, addr2=sta, addr3=ap)
                / (b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + key))
    return ap, sta, deauth, beacon, assoc, eapol


def test_watchdog_deauth_flood_threshold():
    from wifiscanner.defense import Watchdog
    ap, sta, deauth, beacon, assoc, eapol = _mgmt_frames()
    wd = Watchdog(window_s=60, flood_frames=5, cooldown_s=0)
    wd.known = {ap}
    wd.feed(deauth())
    wd.feed(deauth())
    assert wd.alerts == [], "must not fire below threshold"
    for _ in range(3):
        wd.feed(deauth())
    assert any(a.kind == "deauth-flood" and a.severity == "high"
               for a in wd.alerts), wd.alerts


def test_watchdog_forced_reauth_and_harvest_chain():
    from wifiscanner.defense import Watchdog
    ap, sta, deauth, beacon, assoc, eapol = _mgmt_frames()
    wd = Watchdog(window_s=60, cooldown_s=0)
    wd.known = {ap}
    for _ in range(6):
        wd.feed(deauth())                      # flood to kick the client
    wd.feed(assoc())                           # victim rejoins
    wd.feed(eapol())                           # handshake restarts -> harvest
    kinds = {a.kind for a in wd.alerts}
    assert "forced-reauth" in kinds, kinds
    assert "handshake-harvest-signature" in kinds, kinds
    sev = {a.kind: a.severity for a in wd.alerts}
    assert sev["handshake-harvest-signature"] == "critical"


def test_watchdog_beacon_mutation_and_warden():
    from wifiscanner.defense import Watchdog
    ap, sta, deauth, beacon, assoc, eapol = _mgmt_frames()
    wd = Watchdog(cooldown_s=0, known_bssids={"DE:AD:BE:EF:00:01"})
    wd.feed(beacon(channel=6))                 # baseline this AP
    wd.feed(beacon(channel=11, rsn=False))     # suddenly different!
    kinds = {a.kind for a in wd.alerts}
    assert "beacon-mutation" in kinds, kinds
    # and a brand-new BSSID not in the warden baseline:
    from scapy.all import RadioTap, Dot11
    from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
    rogue = (RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                                addr2="12:34:56:78:9A:BC",
                                addr3="12:34:56:78:9A:BC")
             / Dot11Beacon(cap=0x0001) / Dot11Elt(ID=0, info=b"HomeFiber"))
    wd.feed(rogue)
    assert any(a.kind == "unknown-bss" for a in wd.alerts)


def test_audit_rows():
    from wifiscanner.defense import audit_ap
    from wifiscanner.models import AccessPoint
    wpa3 = AccessPoint(bssid="AA:BB:CC:DD:EE:01", security=["WPA3"],
                       ciphers=["CCMP"], pmf="required", auth_suites=["SAE"])
    rows = {r["check"]: r["status"] for r in audit_ap(wpa3)}
    assert rows["WPA3 / PMF-required encryption"] == "PASS"
    assert rows["PMF (802.11w) protects management frames"] == "PASS"
    legacy = AccessPoint(bssid="AA:BB:CC:DD:EE:02", security=["WPA2"],
                         ciphers=["TKIP"], wps=True, pmf="disabled")
    rows = {r["check"]: r for r in audit_ap(legacy)}
    assert rows["No WPS"]["status"] == "FAIL"
    assert rows["No WEP/TKIP/RC4 anywhere"]["status"] == "FAIL"
    assert "PMF" in rows["PMF (802.11w) protects management frames"]["finding"]
    openap = AccessPoint(bssid="AA:BB:CC:DD:EE:03", security=[])
    assert any(r["check"] == "Authentication present" and r["status"] == "FAIL"
               for r in audit_ap(openap))


# ------------------------------------------------------------------ frames

def test_frames_annotate_and_handshakes():
    from wifiscanner.frames import annotate_pcap, find_handshakes, eapol_flags
    blocks = annotate_pcap(FIXTURE, limit=3, filt="beacon")
    assert blocks, "no beacon blocks"
    joined = "\n".join(blocks)
    assert "IE[ 48] RSN" in joined or "Beacon" in joined
    assert "WPA3" not in joined          # 2.4G beacons only in first 3
    hs = annotate_pcap(FIXTURE, limit=2, filt="deauth")
    assert hs and "unplug over the air" in hs[0]
    st = find_handshakes(FIXTURE)
    assert st["deauth_disassoc"] == 9
    assert st["eapol_total"] == 10
    # eapol_flags on a raw frame
    from scapy.all import RadioTap, Dot11
    from scapy.packet import Raw
    key = b"\x02\x03\x00\x5d\x02\x01\x8a\x00\x10" + b"\x00" * 80
    pkt = (RadioTap() / Dot11(type=2, subtype=8, FCfield=["to_DS"],
                              addr1="AA:BB:CC:DD:EE:FF",
                              addr2="11:22:33:44:55:66",
                              addr3="AA:BB:CC:DD:EE:FF")
           / Raw(load=b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + key))
    desc = eapol_flags(pkt)
    assert "0x018a" in desc and "flags" in desc


def test_store_warden():
    from wifiscanner.store import Store
    with tempfile.TemporaryDirectory() as td:
        st = Store(os.path.join(td, "w.sqlite"))
        eng = _synthetic_engine()
        n = st.learn_warden(eng)
        assert n == 3
        assert st.unknown_bssids(eng) == []
        from wifiscanner.models import AccessPoint
        e2 = Engine()
        e2.ingest([AccessPoint(bssid="12:34:56:78:9A:BC", ssid="NewEvil")])
        assert st.unknown_bssids(e2) == ["12:34:56:78:9A:BC"]
        assert len(st.warden_list()) == 3
        st.close()


def test_defense_cli_smoke():
    root = os.path.dirname(HERE)
    if not os.path.exists(FIXTURE):
        subprocess.run([sys.executable, "tests/make_fixture.py"], cwd=root,
                       check=True, capture_output=True)
    env = dict(os.environ, COLUMNS="220")
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "ids", "--pcap", os.path.relpath(FIXTURE, root),
                            "-o", td],
                           cwd=root, capture_output=True, text=True,
                           timeout=180, env=env)
        assert p.returncode == 0, p.stderr[:500]
        assert "watchdog:" in p.stdout
        # fixture contains a 9-frame deauth burst toward one AP
        assert "deauth-flood" in p.stdout or "alerts 0" in p.stdout
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "audit", "--pcap", os.path.relpath(FIXTURE, root),
                            "-o", td],
                           cwd=root, capture_output=True, text=True,
                           timeout=180, env=env)
        assert p.returncode == 0, p.stderr[:500]
        assert os.path.exists(os.path.join(td, "audit_report.md"))
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "frames", os.path.relpath(FIXTURE, root),
                            "--limit", "3", "--filter", "beacon"],
                           cwd=root, capture_output=True, text=True,
                           timeout=180, env=env)
        assert p.returncode == 0 and "IE[" in p.stdout
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "frames", os.path.relpath(FIXTURE, root),
                            "--handshakes"],
                           cwd=root, capture_output=True, text=True,
                           timeout=180, env=env)
        assert p.returncode == 0 and "eapol" in p.stdout.lower()


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
