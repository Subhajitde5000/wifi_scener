# wifi_scener

**Passive Wi-Fi survey · client attribution · presence history · sensor-grid
positioning · capture & cleartext-traffic auditing — all exported to
production-grade CSV/JSON/HTML.**

Built for the terminal, built for network owners who want to know what is
happening on *their* Wi-Fi.

```
 __      __.__  _____.__    _________
/  \    /  \  |/ ____\  |  /   _____/ ___________  ____   ___________
\   \/\/   /  \   __\|  |  \_____  \_/ ___\__  \ /    \_/ __ \_  __ \
 \        /|  ||  |  |  |  /        \  \___/ __ \   |  \  ___/|  | \/
  \__/\  / |__||__|  |__| /_______  /\___  >____  /___|  /\___  >__|
       \/                         \/     \/     \/     \/     \/
```

---

## ⚖️ What this tool is — and the features it deliberately does NOT have

**It is:** passive (receive-only), defensive, own-network-first. It listens to
802.11 frames already broadcast in public airspace, reads *your own* router's
association table, and analyses captures you legally hold.

**It will never contain** (and requests for these were declined — building
them is illegal in most jurisdictions and outside what this project is for):

| Declined | Why |
|---|---|
| Decrypting WPA/WPA2/WPA3 traffic | Key recovery/decryption is a crime-tool capability. Protected frames are **skipped and counted, never touched.** |
| Forcing devices to disconnect (deauth/disoc jamming) | An attack that knocks people offline; also breaks your own network. |
| Creating fake/rogue access points | Evil-twin infrastructure — used to steal other people's credentials. |
| Capturing 4-way handshakes for cracking | Explicit attack purpose; the one thing "handshake capture" is ever used for. |
| Injecting arbitrary 802.11 frames | The enabler for every attack above. This tool never transmits. |
| Defeating MAC randomisation (de-anonymisation) | A privacy protection people chose; building a circumvention engine is surveillance tooling. |
| Open-ended bystander tracking (mass MAC-history of every nearby device, correlating them across space/time) | The `record` command refuses to run unless it is pointed at *your own* network; probe-request sightings are never persisted. |

Feature 10–14 and 7 from the wish-list fall in that table. Everything below is
what ships instead — which still covers the entire *legitimate* half of the
list, thoroughly.

---

## Feature matrix

| # | Feature you asked for | Status | Where |
|---|---|---|---|
| 1 | Detect all clients from your own AP/router | ✅ done — three independent sources fused | `own` |
| 2 | Track client presence over time | ✅ done — SQLite history, gap-aware sessions | `record`, `presence` |
| 3 | Estimate device location using multiple sensors/APs | ✅ done — trilateration/bilateration + per-sensor calibration & guards | `locate` |
| 4 | Track a device's movement around an area | ✅ done — timed trails, zone polygons, dwell-time, ASCII map (your sensors, your devices) | `trail` |
| 5 | Store MAC history of every nearby device | ⚠️ **scoped**: persistent history only for your own network (see declined list). Per-scan CSVs still capture everything observable for legitimate surveys. | `--db`, exports |
| 6 | Capture Wi-Fi probe requests | ✅ done — ephemeral per-scan (device count + remembered SSIDs) | `monitor`, `scan` |
| 7 | De-anonymize randomized MACs | ❌ declined | — |
| 8 | Capture/store raw Wi-Fi packets | ✅ done — streaming pcap, size rotation, bounded ring buffer | `capture` |
| 9 | Inspect unencrypted network traffic | ✅ done — DNS/HTTP/TLS-SNI/ARP/DHCP dissector, cleartext-credential detection, flow table | `traffic` |
| 10 | Decrypt protected traffic | ❌ declined | — |
| 11 | Force devices to disconnect | ❌ declined | — |
| 12 | Rogue/fake AP | ❌ declined (the tool instead **detects** rogue APs) | `scan` alerts |
| 13 | Handshake capture for attacks | ❌ declined (EAPOLs are counted as join-events, nothing extractable is stored) | — |
| 14 | Inject arbitrary Wi-Fi packets | ❌ declined — hardware is never put in transmit path | — |

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # scapy + rich (scan works without them)
python3 main.py interfaces             # what can this machine actually do?
```

**No root, 30 seconds — see everything nearby:**
```bash
python3 main.py scan -o output --format csv json html md
```

**Your own network, fully:**
```bash
python3 main.py own --ports            # clients, IPs, hostnames, open ports,
                                       # A-to-Z AP detail, security grade
python3 main.py own --db home.sqlite   # ...and persist it
```

**Presence over time (the network-owner way):**
```bash
# on the router, or any box that can see YOUR BSSID:
python3 main.py record --db home.sqlite --interval 30
#   (auto-targets your current connection; explicit: --bssid AA:BB:CC:DD:EE:FF)

python3 main.py presence --db home.sqlite --since -24h   # who was on, when
python3 main.py presence --db home.sqlite --known        # device roster
```

**Multi-sensor positioning & movement trails:**
```bash
# sensors.csv:  name,x,y[,floor,rssi_offset_db,tx_power_dbm]   (metres, any
# zones.csv:    zone,x,y  (polygon vertices, listed around the perimeter)
# each sensor box runs:  record --db sensorX.sqlite --sensor kitchen
# merge the DBs (same schema), then:
python3 main.py locate --db merged.sqlite --sensors sensors.csv \
                      --zones zones.csv --recompute
python3 main.py trail  --db merged.sqlite --sensors sensors.csv \
                      --zones zones.csv --mac AC:BC:32:01:02:03 --map -o out/
```

**Raw capture + cleartext audit:**
```bash
sudo python3 main.py capture -i wlan0 -d 3600 -o day.pcap \
     --rotate-mb 64 --ring-segments 8          # bounded 24/7 capture ring
python3 main.py traffic day.pcap -o out/        # DNS/HTTP/SNI/ARP/DHCP events,
                                                # flows, cleartext-credential
                                                # alerts; protected frames skipped
sudo python3 main.py monitor -i wlan0 -d 120    # devices per AP, over the air
python3 main.py offline day.pcap -o out/        # full analysis, no radio needed
```

---

## The features in detail

### 1. `own` — authoritative client census of your network
Fuses up to four sources and reconciles them per device:
1. **Your AP's kernel/hostapd association table** (`iw dev … station dump`) —
   the ground truth, byte counts and per-client signal included.
2. **OS survey** (`iw`/`nmcli`/`airport`/`netsh`) for the AP record itself.
3. **Passive monitor-mode capture** locked to your AP's channel (root) —
   catches devices your router lists oddly, and measures clients' own RSSI.
4. **Active LAN sweep** — ARP ping, reverse DNS hostnames, optional TCP
   port sweep of your own hosts; nmap used automatically when installed.

Output: connection summary, per-client A-to-Z detail, security grade, CSV/JSON.

### 2. `record` + `presence` — history that survives reboots
Append-only SQLite (WAL, safe to read while recording). Each pass stores the
network snapshot, per-device association rows and per-sensor observations.
`presence` answers *“who was on my Wi-Fi between 18:00 and 22:00?”* with
gap-aware session splitting (a silence > `--gap` seconds ends a session),
durations, sighting counts and average signal, plus a **device roster**
(`--known`: first-seen/last-seen per MAC) and CSV export. Replay old captures
into history with `record --pcap capture.pcap`.

### 3. `locate` — real multilateration, honestly bounded
Ranges come from an invertible log-distance path-loss model with per-sensor
calibration (offset + TX power). ≥3 sensors: closed-form **weighted
least-squares trilateration**; 2 sensors: bilateration with the ambiguity
marked; 1 sensor: nearest-sensor zone hint. Uncertainty is derived from fit
residuals, and a **sanity guard** demotes physically-impossible fixes to
nearest-sensor instead of printing fantasy coordinates. Fusing works from any
sensor fleet: multiple Pis (or APs + Pis) each `record --sensor NAME` to a DB
with the same schema.

### 4. `trail` — movement, not magic
Fixes for one MAC become a time-ordered path: CSV export, **zone dwell times**
(named polygons from `zones.csv`), and an ASCII map where the trail is rendered
in a time-gradient (`o…@`) against your sensors (`S`) and zone outlines.
Good enough for “the laptop sat in the living room until 21:14, then kitchen”.
Indoor RSSI physics caps reality at ~room-level accuracy — the tool reports
uncertainty per fix rather than pretending otherwise.

### 8. `capture` — forensic-grade raw capture
Passive monitor-mode frame capture **streamed to pcap** (never buffered in
RAM): `--rotate-mb 64` segments for manageability, `--ring-segments N` for a
self-overwriting bounded ring (24/7 recording, fixed disk budget), channel
selection/hopping, BSSID lock, optional `--analyze` to parse the capture into
AP/client tables at exit. `Ctrl-C` finalises cleanly.

### 9. `traffic` — cleartext inspection with production parsing
Works on any pcap (RadioTap/802.11 with LLC/SNAP reassembly, or Ethernet) and
live on a monitor interface. Extracts: **DNS queries** (+ captive-portal
probe detection), **HTTP request lines, Host, User-Agent**, **TLS SNI** (a
from-scratch ClientHello parser — plaintext metadata only), **ARP**, **DHCP
hostnames**, aggregate **flows** with byte totals. Highlights **cleartext
credentials** in POST bodies / Basic-auth — the *values are flagged, never
logged*. Frames with the 802.11 Protected bit are skipped and counted:
**this module contains no decryption, by design.**

### Also in the core engine (unchanged, still the backbone)
Full 802.11 IE parsing, security grading (WPA3/PMF/WPS/TKIP/OWE…), OUI vendor
resolution, randomised-MAC detection, evil-twin/rogue detection, channel
congestion + best-channel recommendations, five CSV schemas + JSON/HTML/MD
exports, rich terminal UI with a no-dependency fallback, Windows/macOS/Linux
survey backends, and `offline <pcap>` analysis with zero privileges.

---

## Command reference

| Command | Root? | Purpose |
|---|---|---|
| `scan` | no | Survey nearby APs (export with `-o`, persist with `--db`) |
| `monitor -i wlan0` | yes | Passive device attribution for every nearby AP |
| `own` | optional | Full census of **your** network (association table + RF + LAN) |
| `record` | optional | Continuous presence history of **your** network (refuses open-ended bystander mode) |
| `presence` | no | Session/roster queries + CSV export |
| `locate` | no | Sensor-grid trilateration from recorded observations |
| `trail` | no | Per-device movement path, zone dwell, ASCII map |
| `capture` | yes | Streaming pcap ring/rotation, raw 802.11 |
| `traffic <pcap>` | no | Cleartext dissection (live mode needs root) |
| `detail <ssid>` | optional | A-to-Z dump of one network + clients |
| `devices` | optional | Client list (with `--lan` for IPs/hostnames/ports) |
| `full` | yes | scan + monitor + LAN + every export |
| `watch` | no | Live dashboard |
| `offline <pcap>` | no | Analyse existing captures |
| `interfaces` | no | Capability report (root? backends? scapy? OUI size?) |

## Output artefacts

| File | Contents |
|---|---|
| `*_networks.csv` | 43 columns per AP: identity, RF, security, grade, clients, risks |
| `*_devices.csv` | 23 columns per device: MAC/vendor/randomised/association/signal/traffic/probes/IP/hostname/ports |
| `*_channels.csv` | Congestion per channel incl. 2.4 GHz overlap modelling |
| `*_rogue_alerts.csv` | Evil-twin indicators |
| `*_summary.csv` | Scan-level metrics |
| `presence_sessions.csv` | Queried history sessions |
| `trail-<MAC>.csv` | Timed position fixes |
| `traffic_events.csv` / `traffic_flows.csv` | Dissected cleartext + flow aggregates |
| `*.json` / `*.html` / `*.md` | Whole nested result / styled dashboard / notes |

## Testing

```bash
python3 tests/make_fixture.py        # synthetic 802.11 pcap — no radio needed
python3 tests/test_wifiscanner.py    # 42 tests
```

The suite covers RF maths, IE/RSN parsing, `iw`/`netsh` parsers, client
attribution against the fixture capture, security grading, rogue detection,
CSV schema stability, **multilateration accuracy against a synthetic sensor
grid (±1.2 m on ideal geometry)**, zone geometry, store sessions/gap-splitting
and time parsing, the TLS-SNI parser, credential-alert redaction, ring-buffer
capture files, protected-frame skipping, and CLI end-to-end runs.

## Platform & hardware

* **Linux** — full feature set. Monitor mode needs a compatible adapter
  (Atheros/Ralink/MediaTek are reliable) and root. `iw dev … station dump`
  gives the AP association table on Pi/routers with no monitor mode at all.
* **macOS** — survey + pcap analysis; monitor mode requires
  `airport Util setPersist 1`-style setups and modern chips are limited.
* **Windows** — `netsh wlan` survey; no monitor mode (driver stack limitation)
  — capture on a Linux/Pi sensor and analyse the pcap anywhere.

## Legal & ethics

100% receive-only. Never transmits, injects, deauthenticates, clones APs,
joins, cracks or decrypts anything. Continuous tracking works only on networks
you own. Local law may still regulate passive monitoring of airspace you don't
own; get permission. You are responsible for how you use this.
