# wifi_scener

**Passive Wi-Fi survey · client attribution · presence history · sensor-grid
positioning · raw capture · cleartext-traffic audit · wireless IDS ·
hardening reports · 802.11 frame anatomy — one terminal tool, everything in
CSV/JSON/HTML.**

Version 2.2.0 · Python ≥ 3.8 · Linux/macOS/Windows · zero mandatory
dependencies · 100% receive-only.

```
 __      __.__  _____.__    _________
/  \    /  \  |/ ____\  |  /   _____/ ___________  ____   ___________
\   \/\/   /  \   __\|  |  \_____  \_/ ___\__  \ /    \_/ __ \_  __ \
 \        /|  ||  |  |  |  /        \  \___/ __ \   |  \  ___/|  | \/
  \__/\  / |__||__|  |__| /_______  /\___  >____  /___|  /\___  >__|
       \/                         \/     \/     \/     \/     \/
```

---

## Table of contents

1. [What it is / isn't](#1-what-it-is--isnt)
2. [Feature matrix](#2-feature-matrix)
3. [How device counting without joining works](#3-how-device-counting-without-joining-works)
4. [Install](#4-install)
5. [Hardware for monitor mode](#5-hardware-for-monitor-mode)
6. [Quick start](#6-quick-start)
7. [Architecture](#7-architecture)
8. [Command reference (every flag)](#8-command-reference)
9. [Output artefacts (every file, every column)](#9-output-artefacts)
10. [SQLite history schema & queries](#10-sqlite-history-schema--queries)
11. [Methodology (every metric, exactly how it is computed)](#11-methodology)
12. [Sensor-grid positioning guide](#12-sensor-grid-positioning-guide)
13. [The IDS: signatures it detects](#13-the-ids-signatures-it-detects)
14. [Operational recipes](#14-operational-recipes)
15. [Python API](#15-python-api)
16. [Testing](#16-testing)
17. [Platform support & limitations](#17-platform-support--limitations)
18. [Troubleshooting FAQ](#18-troubleshooting-faq)
19. [Legal & ethics](#19-legal--ethics)
20. [Changelog](#20-changelog)

---

## 1. What it is / isn't

**It is** a professional, passive RF-intelligence and network-ownership
toolkit for *your* airspace: it listens to frames already broadcast, reads
your own router's association table, and analyses captures you legally hold.
Every capability is receive-only: it never transmits, injects, deauthenticates,
joins, clones, cracks or decrypts anything.

**It isn't** — and never will be, whatever the use-case framing — an attack
kit. These capabilities are **deliberately absent by design**:

| Not in this tool | What ships instead |
|---|---|
| Decrypt WPA/WPA2/WPA3 traffic | Protected frames are skipped and *counted*; `traffic` proves what leaks *without* encryption so you can fix it |
| Force devices to disconnect (deauth) | `ids` detects deauth floods live — the signature of exactly that attack |
| Rogue/evil-twin AP creation | `ids` + `scan` detect rogue BSSIDs and cloned SSIDs |
| Handshake capture for cracking | `ids` fires a **critical** alert when someone harvests handshakes against you; `frames --handshakes` explains the protocol |
| Packet injection | No transmit path exists in the codebase; `frames` teaches the frame formats injection would abuse |
| De-anonymising randomized MACs | Randomised addresses are *flagged* for reporting honesty, never correlated back to people |
| Indefinite bystander tracking | `record` refuses to run unless pointed at your own network; probe sightings stay ephemeral |

Learning the attacks is still on the menu — through `frames` (byte-level
anatomy of every frame type), `audit` (what each weakness exposes you to and
how to close it) and `ids` (what each attack *looks like* on the wire).

---

## 2. Feature matrix

| # | Capability | Command(s) | Root? | Needs monitor mode? |
|---|---|---|---|---|
| 1 | Survey all nearby networks, A-to-Z per AP | `scan`, `detail`, `offline` | no | no |
| 2 | Count devices connected to any AP, without joining | `monitor`, `devices`, `full` | yes | yes |
| 3 | Full client census of your own network (assoc table + RF + LAN) | `own` | optional | optional |
| 4 | Presence over time (who was on, when; roster; sessions) | `record`, `presence` | no | no |
| 5 | Device location from multiple sensors/APs (trilateration) | `locate` | no | no (from history) |
| 6 | Movement trails + zone dwell time + ASCII map | `trail` | no | no |
| 7 | Per-scan device detail: signal, traffic, probes, vendor, privacy MACs | all | mixed | mixed |
| 8 | Raw 802.11 frame capture: streaming pcap, rotation, ring buffer | `capture` | yes | yes |
| 9 | Cleartext traffic dissection (DNS/HTTP/SNI/ARP/DHCP/flows) | `traffic` | no (pcap) / yes (live) | yes (live only) |
| 10 | Passive wireless IDS (floods, harvest chains, beacon mutation, rogues) | `ids` | yes (live) / no (pcap) | yes (live only) |
| 11 | Hardening audit: weakness → attack → fix, MD checklist | `audit` | no | no |
| 12 | Frame-by-frame 802.11 education | `frames` | no | no |
| 13 | Channel congestion + recommended channels | `scan`, `watch` | no | no |
| 14 | Rogue/evil-twin detection | `scan` (`*_rogue_alerts.csv`) | no | no |
| 15 | LAN inventory (IPs, hostnames, ports, nmap integration) | `own`, `devices --lan` | no | no |
| 16 | Live dashboard | `watch` | no | optional |
| 17 | Structured export: 5 CSVs + JSON + HTML + Markdown | `-o --format` everywhere | no | no |

---

## 3. How device counting without joining works

802.11 data frames carry up to four MAC addresses plus To-DS/From-DS flags.
Even fully encrypted, the **headers are plaintext**, and they state exactly
which client talks to which access point:

| Frame (type/subtype) | Field seen | What it proves |
|---|---|---|
| Data/QoS, To-DS=1 | `addr2` = client, `addr3` = AP | this client is **associated** with that AP |
| Data/QoS, From-DS=1 | `addr1` = client, `addr2` = AP | same binding, downlink direction |
| Association / Reassociation Request (0/0, 0/2) | `addr2→addr3` | definitive join event |
| EAPOL (key type, over LLC/SNAP 0x888E) | AP of `addr3` | a device just (re)authenticated |
| Beacon / Probe Response (0/8, 0/5) | full IE set | AP fingerprint (security, channel, load…) |
| Probe Request (0/4) | `addr2` + SSID element | a nearby (unassociated) device and the networks it remembers |
| Deauth / Disassoc (0/12, 0/11) | `addr1/addr3` | churn, or an attack in progress (`ids` watches this) |

Signal strength is taken from the radiotap header per frame, so clients get
RSSI, min/max, and distance estimates too. Locally-administered address
detection (bit 1 of byte 0) marks privacy MACs.

---

## 4. Install

```bash
git clone <repo> && cd wifi_scener
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # scapy (capture/monitor) + rich (UI)
python3 main.py interfaces               # capability self-check
```

| Piece | Needed for | Install |
|---|---|---|
| **scapy** | monitor capture, `capture`, `traffic`, `frames`, offline analysis, pcap import | `pip install scapy` |
| **rich** | colour tables/panels (graceful ASCII fallback without it) | `pip install rich` |
| `iw` | Linux survey + `iw dev … station dump` own-AP table + monitor setup | `apt install iw` |
| `nmcli` | Windows-free Linux survey fallback | (NetworkManager, usually present) |
| `nmap` | auto-detected; LAN inventory becomes faster/richer | `apt install nmap` (optional) |
| `airmon-ng` | alternative monitor-mode bring-up (`--airmon`) | `apt install aircrack-ng` (optional; only the monitor-mode part is ever used) |

Everything degrades gracefully: without scapy the survey/LAN/history/audit
commands work; the ones that need it tell you exactly what to install.

Install as a package (optional, gives a `wifiscanner` command):

```bash
pip install -e .            # setup.py defines entry_points wifiscanner=wifiscanner.cli:main
wifiscanner interfaces
```

---

## 5. Hardware for monitor mode

Monitor mode is needed for: `monitor`, `capture`, `ids` live, `traffic --live`,
and the over-the-air client counting inside `own`/`full`/`devices`.

* **Linux** is the reference platform. Works out of the box with most
  Atheros (`ath9k`, `ath10k`), MediaTek (`mt76`), Ralink (`rt2x00`) chips.
  Check yours: `iw list | grep -A6 "Supported interface modes" | grep monitor`.
* **Avoid**: most Broadcom (wl) and Intel cards do unreliable/unsupported
  monitor injection-free capture on Linux/macOS. A $15 TL-WN722N **v1** (ath9k_htc)
  or any mt7601u/mt76x2u USB adapter is the classic choice.
* **macOS**: monitor mode is effectively unavailable on modern Macs
  (Apple removed it); use a USB Linux box as sensor, `scan`/`offline` locally.
* **Windows**: no monitor mode via the normal driver stack — survey works
  (`netsh wlan`); capture on a Pi/Linux sensor, analyse the pcap on Windows.
* Built-in cards on laptops are usually fine on Linux (check `iw list`).

You can always verify what *your* box can do:

```bash
python3 main.py interfaces
# platform / root? / survey backends available / scapy present / OUI size / adapter list
```

---

## 6. Quick start

```bash
# 1 — See everything nearby (10 s, no root):
python3 main.py scan

# 2 — Same, exported for Excel / pandas / your notes:
python3 main.py scan -o output --format csv json html md

# 3 — YOUR network, fully (assoc table + LAN names/ports):
python3 main.py own --ports

# 4 — Keep a presence history of your network (Ctrl-C stops):
python3 main.py record --db home.sqlite --lan

# 5 — Ask it questions:
python3 main.py presence --db home.sqlite --since -24h
python3 main.py presence --db home.sqlite --known

# 6 — 24/7 raw capture you can hand to anyone later:
sudo python3 main.py capture -i wlan0 -d 86400 -o day.pcap \
     --rotate-mb 64 --ring-segments 16

# 7 — What did anyone's cleartext actually leak on YOUR network:
python3 main.py traffic day.pcap -o out/

# 8 — Is anything trying deauth/harvest/clone tricks right now:
sudo python3 main.py ids -i wlan0 -d 3600 --db home.sqlite --follow

# 9 — How do I harden this:
python3 main.py audit -o reports/

# 10 — Understand every frame you captured:
python3 main.py frames day.pcap --limit 40
```

Full tour with a sample capture, no hardware:

```bash
python3 tests/make_fixture.py
python3 main.py offline tests/fixture.pcap -o demo/ --format csv json html md
python3 main.py traffic tests/fixture.pcap
python3 main.py ids --pcap tests/fixture.pcap
python3 main.py frames tests/fixture.pcap --filter beacon
```

---

## 7. Architecture

```
                        ┌────────────────────────────────────────────┐
   OS tools             │              Engine (merge)                │
 ┌─ iw / nmcli ────────►│  one record per BSSID, richer-wins merge   │
 ├─ airport / netsh ───►│  AP → {clients: STA objects w/ RSSI stats} │
 ├─ monitor sniffer ───►│  + unassociated devices (probing)          │
 │   (scapy, passive)   │  analytics: security grading, congestion,  │
 ├─ LAN sweep (ARP/     │  rogue detection, summary, presence,       │
 │   DNS/ports/nmap) ──►│  fixes — see modules below                 │
 └─ warden baseline ────┴───────┬───────────────┬─────────────┬──────┘
                                │               │             │
                        export.py          store.py       defense.py
                        5×CSV, JSON,       SQLite: scans,  Watchdog IDS +
                        HTML, Markdown     devices, obs.,   hardening audit
                                           sessions, fixes,
                                           warden           frames.py
                        cli.py (17 cmds) ──► display.py     frame anatomy
                        argparse, wiring     rich/ASCII      (educational)
```

| Module | Responsibility |
|---|---|
| `wifiscanner/models.py` | `AccessPoint`/`Station` dataclasses, RF math (channel↔freq, path-loss ranging, quality), security score/grade/risk rules, per-binding evidence + census breakdown |
| `wifiscanner/oui.py` | OUI vendor DB, MAC normalisation, randomized + multicast detection |
| `wifiscanner/backends/survey.py` | `iw`/`nmcli`/`iwlist`/`airport`/`system_profiler`/`netsh` parsers → AP objects |
| `wifiscanner/backends/sniffer.py` | monitor-mode bring-up (`iw`/`airmon-ng`), passive 802.11 collector: full IE/RSN parsing, To-DS/From-DS attribution, channel hopping, streaming pcap writer (rotate + ring) |
| `wifiscanner/backends/lan.py` | own-AP `station dump` table, ARP/ping sweep, PTR hostnames, TCP port sweep, nmap integration, current-connection facts |
| `wifiscanner/engine.py` | multi-source merge (richer wins), congestion, best channels, rogue detection, summary |
| `wifiscanner/store.py` | SQLite persistence: scans/networks/devices/observations/fixes/warden, session splitting, time parsing |
| `wifiscanner/locate.py` | range model, WLS trilateration/bilateration, nearest-sensor fallback, sanity guard, zones, dwell, ASCII map |
| `wifiscanner/traffic.py` | cleartext dissector (DNS/HTTP/TLS-SNI/ARP/DHCP), flows, credential alerts (redacted) |
| `wifiscanner/defense.py` | IDS Watchdog (7 detectors), hardening `audit_ap` |
| `wifiscanner/frames.py` | frame-by-frame annotated 802.11 anatomy |
| `wifiscanner/export.py` | CSV×5 / JSON / styled HTML / Markdown writers |
| `wifiscanner/display.py` | rich tables/panels with full plain-text fallback |
| `wifiscanner/cli.py` | argparse surface, 17 commands, guardrails |

---

## 8. Command reference

Global flags: `-v/--verbose` (debug logs), `-q/--quiet`, `--no-banner`,
`--version`. Shared scan-family flags (on `scan monitor full detail devices own
watch offline`): `-i/--interface`, `-o/--output DIR`, `--prefix`,
`--format {csv,json,html,md}…`, `--sort {rssi,clients,ssid,channel,security}`,
`--limit N`, `--db SQLITE` (persist snapshot), `--sensor NAME` (tag rows),
`--retain-days N` (history retention, default 90), `--privacy-mode
{standard,minimal,ephemeral}`, `--anonymize` (salted MAC pseudonyms in exports).
(`locate` reuses a subset — `-i -d --airmon --no-monitor-setup --db` — plus its own
grid flags; `record/presence/trail/capture/traffic/ids/audit/frames` are
standalone and list their flags below.)
Times for `--since/--until`: `'YYYY-MM-DD'`, `'YYYY-MM-DD HH:MM[:SS]'`,
`'HH:MM'` (today), relative `'-2h15m'`, `'now'`.

### `scan` — survey nearby APs
`iw` → `nmcli` → `iwlist` → `airport` → `netsh` auto-selection.
Flags: `--backend {auto,nmcli,iw,iwlist,airport,netsh}`, `--no-rescan`.
Prints: AP table, channel-congestion bars, rogue alerts, summary panel.
`-o` exports, `--db` persists.

### `monitor` — passive device attribution (the core trick)
Puts the card in monitor mode (auto, restore-on-exit — including after
Ctrl-C), hops all 2.4/5 GHz channels (or locks), and attributes every data
frame to AP↔client pairs.
Flags: `-d/--duration` (s, default 60), `-c/--channels 1,6,11`,
`--bands 2.4GHz 5GHz 6GHz`, `--bssid AA:..` (lock one AP: auto-locks its
channel when known from the survey pass), `--hop-interval 0.35`,
`--airmon`, `--no-monitor-setup` (iface already in monitor),
`--write-pcap FILE`.
Requires root + scapy + a monitor-capable NIC; without them it says so
clearly and still shows what the survey pass found.

### `own` — authoritative census of YOUR network
Fuses: (1) `iw dev <iface> station dump` of your own AP if this box hosts it,
(2) survey, (3) monitor capture locked to your BSSID (if root), (4) LAN sweep
— ping sweep, ARP table, PTR hostnames, `(gateway)`, optional `--ports`.
Prints your connection summary then full A-to-Z detail + per-client table.
Flags: `-d` (25 s monitor), `--ports`, `--no-lan`, `--no-monitor`,
`--airmon`, `--no-monitor-setup`.

### `full` — everything at once
`scan` + `monitor` + (with `--lan`) LAN inventory + exports; forces
`-o output` and adds the HTML report. Flags as above + `-d`, `--bands`,
`--lan`, `--ports`.

### `detail <SSID-or-BSSID>` — one network, A-to-Z
Substring match over SSID/BSSID; with root+scapy it runs a short locked
monitor pass (`-d`, default 45 s) first so the client list is populated.
`--no-monitor` skips that.

### `devices` — client-only view
Monitor census (unless `--no-monitor`) and/or `--lan [--subnet 192.168.1.0/24]
[--ports]` for your own network.

### `watch` — live dashboard
Refreshing (default `-n 8` s) table; `--monitor` folds in a short monitor
pass per cycle (root, scapy). Ctrl-C → final export if `-o` given.

### `offline <pcap>` — analyse existing captures
Runs the full monitor parsing pipeline on a pcap/pcapng (RadioTap, Ethernet
or 802.11 linktype). No root, no radio. Accepts all export/DB flags — the
workhorse for field-capture → desk-analysis workflows.

### `capture` — raw frame capture, production storage semantics
Streaming pcap writer (never buffers in RAM): `--rotate-mb 64` starts
`capture-001.pcap`, `-002`, … when a segment exceeds the size;
`--ring-segments 8` makes it a bounded ring (oldest segment overwritten —
fixed disk budget for 24/7). `--analyze` parses into AP/client tables at
exit. Ctrl-C finalises. Flags: `-i -d -c --bands --bssid --hop-interval -o
FILE --rotate-mb --ring-segments --airmon --no-monitor-setup`,
plus the sensitivity guardrails: `--ack-sensitive` (**required** — explicit
opt-in acknowledging captures hold third-party data),
`--strip-payloads` (128-byte snaplen: headers for counting/IDS, no payloads),
`--max-age-days N` (delete expired segments on exit). Files are written
owner-only (0600).

### `traffic [pcap] | --live -i IF` — cleartext dissection
Parses only frames visible *without* decryption. Extracts: DNS queries/responses
(+ captive-portal probe flagging), HTTP request line + `Host:` + `User-Agent`,
**TLS SNI** (from a hand-rolled ClientHello parser — metadata only), ARP
`who-has`, DHCP hostnames; aggregates flows (packets/bytes/SYN notes).
Detects **cleartext credentials** (`POST` bodies with password/pwd/token
fields, `Authorization: Basic`) — flagged, **values never logged**. Any frame
with the Protected/WEP bit is skipped and counted.
**Redaction is ON by default**: URL query strings/fragments stripped,
User-Agents reduced to product tokens, hostnames truncated, credential
patterns scrubbed. `--no-redact` disables it (explicit opt-out, warns loudly),
`--anonymize-ips` masks IPs to /24 for shared reports. Output: rich tables +
`traffic_events.csv` + `traffic_flows.csv` with `-o DIR` (`--prefix`).
`--max-frames` (default 200 000), `--limit` rows shown, live mode `-d`.

### `record` — continuous presence history (own network, guarded)
`--db presence.sqlite` (default), loop cadence `-n/--interval 30` s,
`-d/--duration 0` = until Ctrl-C, `--backend`, `--lan` (enrich with IPs/
names), `--sensor NAME` (tag for later lateration),
`--bssid AA:..[,BB:..]` explicit own-AP list.
**Target rule:** without `--bssid`, it auto-targets *your current Wi-Fi
connection*; with neither, it **refuses** (exit 2) rather than persisting
bystander data. `--pcap FILE` = one-shot: import a capture's AP/client model
into the DB and exit. Reaps `iw station dump` automatically when this box
hosts the AP. Prints one status line per pass.
Privacy: `--retain-days N` (default 90, auto-enforced on every open),
`--privacy-mode {standard,minimal,ephemeral}`, `--anonymize` (salted MAC
pseudonyms, no hostnames/IPs). See `db` for pruning, per-device erasure and
whole-DB anonymization.

### `presence` — query the history
`--db`, filters `--mac`, `--ssid`, `--since/-–until`, `--gap 300` (seconds of
absence that ends a session), `--limit 100`, `-o DIR` → `presence_sessions.csv`.
`--known` shows the roster (first/last seen, #APs). Default view = sessions
table + "present NOW" count.

### `locate` — multi-sensor positioning from history
`--sensors sensors.csv` (**required**), `--zones zones.csv`, `--db`,
`--mac` (optional filter), `--window 3.0` (s, fuses per-sensor readings),
`--n-exp 2.7` (path-loss exponent), `--since/--until`, `--recompute`
(store fixes back), `--live -d 20 -i wlan0` (capture first). Output:
per-fix table (`x, y, Unc m, Zone, Method, Sources`) + ASCII map when ≥2
sensors.

### `trail` — movement of one device
`--mac` (**required**), `--db`, optional `--sensors/--zones/--window/
--since/--until`, `--map` (ASCII: `S`ensors, zone outlines, time-gradient
trail `o.:-=+*#%@`), `-o DIR` → `trail-<MAC>.csv` (ts, time, x, y, unc,
zone, method). Without `--sensors` degrades to a presence-only trail
(per-scan rows) rather than failing.

### `ids` — passive wireless IDS
Live: `-i wlan0 -d 60` (root; monitor). Offline: `--pcap FILE`.
Tuning: `--window 10.0` s anomaly window, `--flood 5` frames in window
before “flood”, `--sensitivity {low,medium,high}` (scales the threshold 2×/1×/0.6×).
Every alert carries `confidence` 0-100 + `status` (unconfirmed/corroborated/confirmed)
+ `evidence` and a “to confirm” hint; beacon mutations must persist across beacons
to upgrade, and an adaptive margin raises the bar automatically when the whole
band is noisy. Warden: `--db warden.sqlite --learn` baselines currently
visible APs; every beacon from a BSSID not in the baseline then raises
`unknown-bss`. `--follow` prints alerts as they fire; `-o DIR` exports
`ids_alerts.csv`. Detection only — see §13.

### `audit` — hardening report
Live scan (or `--pcap FILE`, `--ssid filter`); one row per check per BSS:
`PASS/WARN/FAIL + severity + finding/fix`. `-o DIR` writes
`audit_report.md` — a markdown checklist (`[x] [!] [ ]`). See §11.5 for the
exact check list.

### `frames` — 802.11 frame anatomy
`frames capture.pcap [--limit 20] [--filter
beacon|probe-req|assoc-req|deauth|disassoc|data|handshake]`.
Annotates: radiotap metadata, FC flags, address-field semantics,
data-frame To-DS/From-DS binding explanation, protected-bit note, IE-by-IE
beacon decode (SSID, rates incl. legacy-11b note, DS channel, TIM, country,
BSS load, HT/VHT caps, **full RSN decode**: group/pairwise suites, AKM
selectors by IEEE registry name, PMF capable/required bits, vendor/WPS),
LLC/SNAP ethertype, EAPOL **role + flags decoded from bytes** (key
material never rendered). `--handshakes` prints the census: total EAPOL,
per-BSS EAPOL, deauth/disassoc totals — counts only.

### `db` — history-database maintenance (privacy controls)
`--report` (permissions/size/retention/table counts + world-readable warning),
`--prune-days N` (delete old rows + vacuum), `--delete-mac AA:..` (erase one
device everywhere, MAC or pseudonym), `--anonymize-db --yes` (**irreversible**:
salted MAC pseudonyms, IPs/hostnames wiped), `--purge --yes` (delete all history,
keep warden baseline), `--vacuum`. Destructive actions require `--yes`.

### `interfaces` — capability report
platform, root?, backends found, scapy present?, OUI table size, and each
wireless interface with mode / MAC / channel.

---

## 9. Output artefacts

All files UTF-8 **with BOM** (opens correctly in Excel), RFC-4180 quoting,
header row always present, filenames `wifi-<scanid>_*` (or your `--prefix`).
Every row carries `scan_id` so repeated scans concatenate in pandas.

All exports are written owner-only (0600); pass `--anonymize` for salted,
per-export, unlinkable MAC pseudonyms with hostnames/IPs/probes dropped.

### `<prefix>_networks.csv` — 49 columns, one row per BSS

| Column | Meaning |
|---|---|
| `scan_id` | run id (UTC-stamped) |
| `bssid` `ssid` `hidden` | identity; `hidden=1` = beacon/probe had no SSID |
| `vendor` | OUI vendor of the BSSID |
| `band` `channel` `frequency_mhz` `channel_width_mhz` | RF position (20/40/80/160 from HT/VHT/HE IEs) |
| `rssi_dbm` `rssi_min_dbm` `rssi_max_dbm` `noise_dbm` `snr_db` | signal levels over the whole run |
| `signal_quality_pct` `signal_bars` `estimated_distance_m` | derived quality + path-loss distance (§11.3) |
| `encryption` `ciphers` `auth_suites` `pmf` | security stack from RSN/WPA IEs (`pmf`: required/optional/disabled) |
| `wps` | WPS IE advertised |
| `security_score` `security_grade` `risks` | 0–100 / A+…F / `;`-joined risk codes (§11.2) |
| `phy_modes` `max_rate_mbps` | 802.11 a/b/g/n/ac/ax/be + top basic rate |
| `beacon_interval_tu` `dtim_period` `country` `mesh` | beacon internals |
| `beacons_seen` `data_packets` | frames attributed during capture (monitor mode only) |
| `connected_devices` `active_devices` `client_macs` | device count (§3), clients with ≥1 data frame, `|`-joined MACs |
| `bss_load_sta_count` `channel_utilization_pct` | BSS Load IE (element 11) — the AP's *own* claim |
| `eapol_frames` `deauth_frames` | handshake joins and deauth activity seen (feeds `ids` too) |
| `first_seen` `last_seen` `source` | wall-clock bounds; sources merged, e.g. `iw+monitor+lan` |

### `<prefix>_devices.csv` — 23 columns, one row per client

`scan_id`, `mac`, `vendor`, `is_randomized` (locally-administered → privacy
MAC), `associated_bssid`, `associated_ssid`, `ip_address`, `hostname`,
`open_ports` (own-LAN enrichment only), `rssi_dbm` (+min/max),
`signal_quality_pct`, `estimated_distance_m`, `channel`, `packets`,
`data_packets`, `bytes_seen`, `dwell_s` (first→last observation span),
`probed_ssids` (`,`-joined; unassociated devices only), `state`
(`associated` / `unassociated/probing` in the CSV; the DB additionally
keeps `lan` rows), `first_seen`, `last_seen`.

### Also

| File | Contents |
|---|---|
| `*_channels.csv` | per band: channel, ap_count, overlapping_aps (2.4 GHz ±4 modelling), total_interferers, clients, strongest_rssi, SSIDs |
| `*_rogue_alerts.csv` | SSID, bssid_count, bssids, severity, reasons (§11.4) |
| `*_summary.csv` | scan-level metrics (`metric,value`) |
| `presence_sessions.csv` | `presence -o`: mac, bssid, ssid, first/last_seen, duration_s, sightings, avg/min/max_rssi |
| `trail-<MAC>.csv` | ts, time, x, y, unc_m, error_radius_m, zone, zone_confidence, method, confidence, sensor_count, display |
| `traffic_events.csv` | time, ts, src/dst_mac, src, dst, proto, summary, detail, alert (redacted by default) |
| `traffic_flows.csv` | src, dst, proto, packets, bytes, bytes_h, first, last, notes |
| `ids_alerts.csv` | time, severity, kind, bssid, ssid, src, dst, confidence, confidence_label, status, evidence, detail |
| `audit_report.md` | checkbox list per BSS: `[x]/[!]/[ ]` |
| `<prefix>.json` | everything nested: `{scan_id, generated_at, summary, connection, networks[], devices[], channel_congestion{band:[]}, rogue_alerts[]}` |
| `<prefix>.html` | standalone dark-theme dashboard: summary cards, rogue banner, AP table (signal bars, grade pills), device table, channel bars, recommended channels |
| `<prefix>.md` | quick notes: summary bullets, rogue alerts, AP table |

---

## 10. SQLite history schema & queries

`Store` (WAL mode — read while recording). Tables:

```sql
scans(scan_id PK, ts, duration, mode, sensor, networks, devices, meta)
  mode: scan|monitor|full|devices|offline|own|record|locate-live|pcap-import
networks(scan_id, ts, sensor, bssid, ssid, channel, band, rssi, security, grade, clients)
devices(scan_id, ts, sensor, mac, bssid, ssid, state, rssi, packets, data,
        bytes, ip, hostname, randomized, probed)
observations(ts, sensor, mac, bssid, rssi, freq)   -- raw feeds for locate
fixes(ts, mac, x, y, unc, method, sensors)         -- computed positions
warden(bssid PK, ssid, meta, first_seen, last_seen, seen)
```

Indexed: `devices(mac,ts)`, `devices(ssid,ts)`, `observations(mac,ts)`,
`fixes(mac,ts)`.

The CLI covers the usual questions; anything else is plain SQL, e.g.:

```bash
sqlite3 home.sqlite "SELECT ssid, COUNT(DISTINCT mac) FROM devices
  WHERE ts > strftime('%s','now','-7 days') GROUP BY ssid;"
sqlite3 home.sqlite "SELECT mac, MAX(ts) FROM devices GROUP BY mac;"
```

Retention: `Store.prune(days)` is exposed in the API (`--keep-days` CLI flag
is intentionally absent — prune deliberately, knowing history is the point).

**Session semantics** (`presence`): rows for (mac, bssid) within `--gap`
seconds collapse into one session; a longer silence or an AP change starts a
new one. `state IN ('associated','lan')` rows only — probe requests are never
persisted.

---

## 11. Methodology

### 11.1 Source merge (engine)
Keyed by BSSID, richer-wins: first non-empty SSID wins (hidden→named
promotes), channel/freq/country/DTIM etc. fill if missing, RSSI keeps max
(+running min/max), security union minus `OPEN` when anything real exists,
PHY/ciphers/AKMs union, flags OR'd, counters summed, time bounds merged,
clients merged by MAC, sources recorded as `iw+monitor+lan`.

### 11.2 Security score & grade (models.py — exact arithmetic)
Base: OPEN/none 5 · WEP 15 · WPA-only 35 · WPA2 70 · WPA2+WPA3 transition 80
· WPA3-only 100. Modifiers: WPS −25 (Pixie-Dust/PIN exposure) · TKIP −15 ·
PMF required +5 · PMF disabled/unknown −5. Clamp 0–100.
Grade: ≥90 `A+` · ≥80 `A` · ≥70 `B` · ≥55 `C` · ≥35 `D` · else `F`.
Risk codes: `open-network:traffic-in-cleartext`, `wep:trivially-crackable`,
`wpa1-legacy`, `tkip-cipher-deprecated`, `wps-enabled:pixie-dust`,
`no-pmf:deauth-possible`, `hidden-ssid:security-by-obscurity`,
`very-close-transmitter` (RSSI > −35).

### 11.3 RSSI → quality → distance
`quality%` = Microsoft linear map (−100→0, −50→100). Bars: 4-block glyph.
Distance (and `locate` ranging) invert the log-distance model:

```
FSPL₁ₘ(f) = 20·log10(f_MHz) − 27.55
d = 10 ^ ((Tx − FSPL₁ₘ − (RSSI + sensor_offset)) / (10·n))
Tx default 20 dBm · n default 2.7 (2.0 free space, 3.5 dense indoor)
```
Clamped 0.1–2000 m for the survey column; `locate` ranges clamp 0.2–500 m.
**Order-of-magnitude only** — walls/antenna gain move
it; that's why `locate` reports per-fix uncertainty instead of hiding it.

### 11.4 Rogue / evil-twin scoring (multi-indicator)
Per SSID with ≥2 BSSIDs, each independent indicator scores evidence —
`open-clone` 45, `security-mismatch` 25, `vendor-mismatch` 20,
`warden-unknown` 20, `pmf-mismatch` 15, `signal-anomaly` 10, `channel-anomaly` 10 —
fused with noisy-OR into `score` 0-100. Verdict `likely-rogue` requires **≥2
indicators AND score ≥ 40** (severity `high` for open clones, else `medium`);
single-indicator groups are listed as `unconfirmed` (severity `low`) and never
counted as rogue — extenders, mesh nodes and multi-vendor enterprise WLANs all
produce single-indicator lookalikes. Warden adds: any beacon whose BSSID isn't in
`warden` table → `unknown-bss`; any beacon whose (channel, security-IE set) changed
mid-run → `beacon-mutation` (low confidence until the new fingerprint persists).

### 11.5 Audit checks (each = weakness → attack → fix)
`WPA3 / PMF-required encryption` · `PMF (802.11w) protects management frames`
(no PMF ⇒ client-kick & reauth bait work) · `No WPS` · `No WEP/TKIP/RC4
anywhere` · `WPA2 uses AES-CCMP` (+ “strong passphrase” caveat, since WPA2-PSK
handshakes are offline-grindable — the fix is WPA3/SAE or a ≥25-char
passphrase, **not** cracking) · `Authentication present` (open BSS ⇒
`traffic` demonstrates the leak) · `No abnormal handshake churn during scan`
(≥20 EAPOL in one passive window ⇒ run `ids`).

### 11.6 MAC classification
`is_randomized`: bit 1 of first octet (locally administered) — iOS/Android
privacy addresses. `is_multicast`: bit 0 (broadcast frames never counted as
clients). Vendor lookup = 24-bit OUI prefix, built-in table +
`manuf`/`nmap` nsel files when present.

### 11.7 Client counting rules
A client counts for an AP when a data frame binds them (To-DS/From-DS), an
association request names that BSSID, or EAPOL flows on that BSS with that
MAC. Broadcast/multicast/NULL/QoS-no-data don't create clients. “Active” =
≥1 data packet. Duplicate MACs across APs are separate bindings.

---

## 12. Sensor-grid positioning guide

**Model:** 3+ fixed receivers (`record --sensor`) at surveyed positions;
each pass writes per-device RSSI rows with its tag; `locate` fuses readings
from different sensors that fall within `--window` seconds.

`sensors.csv` (metres on any consistent local grid; origin arbitrary):

```csv
name,x,y,floor,rssi_offset_db,tx_power_dbm
front-door,0,0,0,,4.0,-4        # this antenna reads 4 dB strong, wants −4 cal
living-room,8,2,0
kitchen,8,12,0
```

`zones.csv` — polygon vertices, one zone per consecutive block (order =
perimeter):

```csv
zone,x,y
living,0,0
living,10,0
living,10,10
living,0,10
kitchen,10,0
kitchen,20,0
kitchen,20,10
kitchen,10,10
```

Pipeline:

```bash
# each box:      record --db /srv/presence-$HOSTNAME.sqlite --sensor $HOSTNAME
#               (systemd unit in §14); merge files (same schema, one DB each —
#                easiest: copy rows with sqlite3 ATTACH, or point all
#                sensors at one shared file on a server)
python3 main.py locate --db merged.sqlite --sensors sensors.csv \
                       --zones zones.csv --recompute
python3 main.py trail  --db merged.sqlite --sensors sensors.csv \
                       --zones zones.csv --mac AC:BC:32:01:02:03 --map -o out/
```

Methods you'll see: `trilateration` (WLS over ≥3 sensors, uncertainty =
2×residual-RMS), `bilateration(ambiguous)` (2 sensors, the better of the
two circle intersections), `nearest-sensor`, and
`nearest-sensor(guarded)` — the **sanity guard**: any fix whose uncertainty
exceeds the grid diagonal or lands >0.6×diag outside the sensor bbox is
demoted, never printed as fantasy. 1 sensor ⇒ zone-granularity hint only.
Indoor reality: expect **room/zone-level** accuracy, metres not centimetres.

---

## 13. The IDS: signatures it detects

| Kind | Trigger (defaults) | Severity | What you're seeing |
|---|---|---|---|
| `deauth-flood` | ≥ `--flood` (5) deauth/disassoc to one BSSID within `--window` (10 s) | high (baselined) / info | someone kicking clients — bait for auto-rejoin tricks; PMF-required networks ignore forged frames |
| `forced-reauth` | Association from a client ≤ window after a deauth targeted it | **critical** | the kick actually *worked*; client is renegotiating on command |
| `handshake-harvest-signature` | deauth → assoc → **EAPOL** within window | **critical** | someone is provoking fresh 4-way handshakes — the capture-for-offline-grind pattern. Mitigation: SAE/WPA3 + PMF required; rotate no secrets mid-incident |
| `eapol-storm` | > flood count of EAPOL on one BSS | high | mass renegotiation; same family as above |
| `beacon-mutation` | same BSSID's (channel, security IE set) changes mid-run | medium | either your reconfig or a live impersonator tweaking its beacon |
| `unknown-bss` | beacon from a BSSID not in the warden baseline (`ids --db … --learn`) | medium | new/novel AP advertising (possibly your SSID) |
| *(from scan)* | `rogue/evil-twin` rows in `*_rogue_alerts.csv` | medium/high | same-SSID multi-vendor / open-clone heuristics |

Mechanics: per-`window` sliding counters per BSSID; per-(kind, BSSID)
30 s cooldown so a burst = one alert; `--follow` streams alerts live;
`-o` exports `ids_alerts.csv`. Live mode uses the same passive sniffer —
**the watchdog has no transmit path; “detection only” is architectural,
not rhetorical.**

---

## 14. Operational recipes

**24/7 own-network monitor on a Pi (the intended deployment):**

```ini
# /etc/systemd/system/wifi-presence.service
[Unit]
Description=Wi-Fi presence recorder (own network)
After=network-online.target

[Service]
WorkingDirectory=/opt/wifi_scener
ExecStart=/opt/wifi_scener/.venv/bin/python main.py record \
    --db /var/lib/wifi/presence.sqlite --sensor kitchen --lan --interval 30
Restart=always
User=root                     # monitor + station dump; drop to cap_net_raw when polished

[Install]
WantedBy=multi-user.target
```

**Capture-then-analyse split** (field box vs desk):

```bash
sudo python3 main.py capture -i wlan0mon -d 3600 -o field.pcap --rotate-mb 64
python3 main.py offline field.pcap -o out/            # full survey tables
python3 main.py ids --pcap field.pcap                 # attack triage
python3 main.py traffic field.pcap -o out/            # what leaked cleartext
python3 main.py frames field.pcap --limit 20          # learn what you captured
```

**Ring-buffer forensic snapshot** — last ~24 h always available, capped:

```bash
sudo python3 main.py capture -i wlan0 -d 864000 -o /var/pcap/loop.pcap \
     --ring-segments 96 --rotate-mb 32       # 96×32 MB ≈ 3 GB, never more
```

**History diffing in pandas:**

```python
import pandas as pd, glob
dev  = pd.concat(map(pd.read_csv, glob.glob("out/*_devices.csv")))
nets = pd.concat(map(pd.read_csv, glob.glob("out/*_networks.csv")))
# busiest hour per SSID:
dev.assign(h=pd.to_datetime(dev.last_seen).dt.hour) \
   .groupby(["associated_ssid","h"]).mac.nunique().unstack(fill_value=0)
# networks that got weaker over the week (join on bssid across scan_ids)
```

**Cron report:** `presence --db home.sqlite --since -24h -o reports/` daily;
email `reports/presence_sessions.csv`.

---

## 15. Python API

```python
from wifiscanner import Engine, export_all
from wifiscanner.backends import survey, sniffer, lan

eng = Engine()
eng.ingest(survey.survey_networks(rescan=True))          # OS-level pass
with sniffer.MonitorMode("wlan0") as mon:                 # root
    sn = sniffer.MonitorSniffer(mon, channels=[1, 6, 11])
    sn.run(30)
    eng.ingest(sn.results()); eng.ingest_unassociated(sn.unassociated)
eng.ingest_lan(lan.lan_inventory())

print(eng.summary()); print(eng.rogue_candidates())
export_all(eng, "output", formats=("csv", "json", "html"))

from wifiscanner.defense import Watchdog, audit_engine
from wifiscanner.frames import annotate_pcap
wd = Watchdog(); ... sniffer loop: wd.feed(pkt)
for row in audit_engine(eng): print(row)
```

`Store` gives `record_engine / sessions / known_devices / get_observations /
record_fixes / learn_warden / prune`; `locate` exposes
`load_sensors/load_zones/Tracker/multilateration` for custom pipelines.

---

## 16. Testing

```bash
python3 tests/make_fixture.py         # builds tests/fixture.pcap (288 frames:
                                      # beacons w/ real RSN/WPS/BSS-load IEs,
                                      # assoc+data+LLC/SNAP-EAPOL per client,
                                      # probe storms, a 9-frame deauth burst,
                                      # 5 BSS incl. an evil twin)
python3 tests/test_wifiscanner.py     # 76 tests, no radio, no root
```

Coverage: RF math round-trips; randomized/multicast MAC rules; OUI; score
ordering + WPS/TKIP penalties; station accounting idempotence; source merge
prefer-richer; dedupe; congestion & recommender; rogue/open-clone; summary
counts; canned `iw`/`netsh` parser fixtures; **pcap→client attribution
exact counts**; IE/RSN parsing; probe & deauth capture; **CSV schema
stability + Excel-safe quoting**; store round-trip + session gap-splitting +
time parsing; **trilateration ±1.2 m on synthetic grid**; bilateration;
zone geometry + dwell; sensor/zone file loaders; **IDS: flood threshold,
deauth→reassoc→EAPOL chain fires critical alerts, beacon mutation, warden
unknown-BSS**; audit rows PASS/FAIL logic; **frames annotator on real bytes
+ EAPOL flag decode + handshake census**; store warden; **traffic: DNS/HTTP
parse, credential alert with value redaction, ARP, SNI parser, protected
skip+count, 802.11 LLC/SNAP reassembly**; ring-buffer rotation on disk; CLI
smoke incl. `record` guardrail refusal and `traffic/ids/audit/frames/presence`
end-to-end subprocess runs; **trust: binding ranks, noisy-OR fusion, RF-vs-
confirmed census, identity ranges; rogue multi-indicator scoring + warden;
privacy: salted pseudonyms, redaction helpers, 0600 files; store retention/
erase/anonymize/ephemeral; IDS confidence + sensitivity + persistence +
adaptive margin; locate confidence + zone-primary display; capture `--ack`
refusal; `db` report/prune/destructive-guard; anonymized exports**.

---

## 17. Platform support & limitations

| | Linux | macOS | Windows |
|---|---|---|---|
| Survey (`scan`/`detail`/`watch`) | ✅ iw/nmcli/iwlist | ✅ airport/system_profiler | ✅ netsh (needs Admin for profiles list) |
| Monitor capture (`monitor/capture/ids/traffic --live`) | ✅ with monitor-capable NIC | ⚠️ only cards already in monitor mode | ❌ driver stack |
| `own` via `iw station dump` (this box = AP) | ✅ | ❌ | ❌ |
| LAN sweep / `--ports` | ✅ | ✅ | ✅ |
| nmap acceleration | ✅ if installed | ✅ | ✅ |
| `traffic/frames/ids --pcap/offline` on captured files | ✅ | ✅ | ✅ |
| `record` history + `presence` | ✅ | ✅ | ✅ |
| `locate`/`trail` from multi-sensor DBs | ✅ | ✅ | ✅ |

Fundamental limits, stated plainly: encrypted payloads are never readable
(and never attacked); RSSI distance estimates are order-of-magnitude;
single-sensor setups cannot trilaterate; 2.4 GHz channel overlap modelling
assumes 20 MHz width; the OUI table ships trimmed — extend with
`/usr/share/nmap/nmap-mac-prefixes` or Wireshark's `manuf` when present.

---

## 18. Troubleshooting FAQ

| Symptom | Cause → fix |
|---|---|
| `backends: none` in `interfaces` | install `iw` (Linux) or be on a Wi-Fi-capable box; `netsh` needs Admin on Windows |
| `monitor mode requires root` | `sudo`, or `--no-monitor-setup` when the iface is already `wlanXmon` |
| Monitor setup fails `busy` | your managed connection holds the NIC — `nmcli device disconnect wlan0` first (auto-restored on exit) |
| Capture starts but 0 frames | NIC lacks monitor support (`iw list` → modes), or nothing on the channels hopped: `-c 1,6,11` to focus, check `dmesg` for firmware |
| `scapy required` messages | `pip install scapy` inside the venv you're running from |
| Colours/tables mangled | `NO_COLOR=1` forces the plain renderer; also fine for `>> log.txt` |
| `traffic` finds nothing | expected on encrypted nets — it only dissects cleartext, by design; use `ids` for attack triage and `offline` for client/AP structure |
| `record` refuses to start | no `--bssid` and not connected to Wi-Fi — point it at **your** AP explicitly |
| presence shows 0 sessions | gap larger than your scan interval? try `--gap 600`; or import a capture first: `record --pcap day.pcap` |
| locate: "no sensor observations" | history was recorded without `--sensor` tags, or sensor names don't match `sensors.csv` |
| Huge/nonsense x,y | you'll now see `nearest-sensor(guarded)` instead — check sensor coords & `--n-exp`, add calibration offsets |
| sqlite locked on shared NAS | WAL over NFS is unreliable — record locally, merge periodically |
| Windows Ctrl-C leaves `netsh` half-run | rerun `netsh wlan show interfaces` — cosmetic; no state is kept |

---

## 19. Legal & ethics

Everything here is **receive-only** and scoped to infrastructure you own or
explicitly authorise. Passive monitoring of public airspace is permitted in
most jurisdictions but not all, and logging *people's* devices isn't the
purpose of this tool (see §1 for what was declined and why). You are
responsible for lawful, consented use. If a design question is "could this
harbor a third party against their will?" — that feature is not getting
merged, here or in forks.

## 20. Changelog

* **v2.2.0** — trust & privacy hardening (the 10 fixes, §21): central
  source+confidence trust model (`trust.py`); RF-observed vs router-confirmed
  census with per-binding evidence ranks; rotating-MAC honesty (observed-MAC
  ranges, never same/different-device claims); privacy modes
  (standard/minimal/ephemeral), salted MAC pseudonyms, auto-enforced retention,
  `db` maintenance (report/prune/erase/anonymize/purge/vacuum); zone-primary
  location with confidence + withheld low-confidence coordinates; capture
  opt-in (`--ack-sensitive`), payload-stripping snaplen, 0600 secure storage
  everywhere; traffic redaction ON by default; IDS confidence/status/evidence,
  `--sensitivity`, beacon persistence, adaptive noisy-air margin; multi-indicator
  rogue scoring (≥2 indicators to declare). **76 tests**.
* **v2.1.0** — `ids` (7-detector passive watchdog + warden baseline),
  `audit` (weakness→attack→fix reports), `frames` (frame anatomy +
  handshake census); raw LLC/SNAP EAPOL detection; fixture rebuilt with
  realistic monitor-style EAPOL; **49 tests**.
* **v2.0.0** — `own`, `record`, `presence` (SQLite history, gap-aware
  sessions), `locate` (WLS trilateration + guard), `trail` (zones, dwell,
  ASCII maps), `capture` (streaming pcap, rotation, ring buffer),
  `traffic` (cleartext dissector, credential redaction); `--db` on all
  survey commands; own-network guardrails.
* **v1.0.0** — passive survey (5 OS backends), monitor-mode client
  attribution, RSN/IE parsing, security grading, rogue detection,
  congestion analysis, CSV×5/JSON/HTML/MD export, rich/ASCII terminal UI.
rk guardrails.
* **v1.0.0** — passive survey (5 OS backends), monitor-mode client
  attribution, RSN/IE parsing, security grading, rogue detection,
  congestion analysis, CSV×5/JSON/HTML/MD export, rich/ASCII terminal UI.

---

## 21. Trust & privacy model

v2.2.0 hardens the ten weaknesses below. The design principle throughout:
**every result carries its source and its confidence, and every byte written
to disk is minimised, permission-locked and retention-bounded.**

| # | Weakness | Fix (where) |
|---|---|---|
| 1 | Client counts stated as fact | `census`: `N✓ router-confirmed + M~ RF-observed` + 0-100 confidence; per-binding evidence ranks (`assoc-table` 98 … `single-frame` 35); router table **correlated**, never double-counted (`models.py`, `engine.py`, `backends/sniffer.py`) |
| 2 | Randomized MACs | `identity_report()`: observed-MAC ranges (min–max physical devices); `identity_note` disclaims **both** directions (distinct rotating addresses are neither distinct devices nor the same device); `oui.classify_mac()` (`models.py`, `engine.py`, `oui.py`) |
| 3 | Long-term tracking | `--privacy-mode standard/minimal/ephemeral`, `--anonymize` (salted HMAC pseudonyms, no hostnames/IPs/probes), auto-enforced retention (default 90 d), anonymized exports (`privacy.py`, `store.py`, `export.py`, `cli.py`) |
| 4 | Noisy location | Every fix: error radius + `confidence` + `zone_confidence`; **zone is the primary answer**; low-confidence coordinates withheld (`Fix.display`); RSSI-spread demotion (`locate.py`) |
| 5 | Sensitive raw PCAP | `--ack-sensitive` opt-in (**required**), `--strip-payloads` 128-B header-only captures, `--max-age-days` retention, 0600 files (`cli.py`, `backends/sniffer.py`) |
| 6 | Traffic-analysis exposure | Metadata-minimal + **redaction ON by default** (URL queries stripped, UA→product token, hostnames truncated, credential patterns scrubbed, values never logged); `--anonymize-ips` for shared reports (`traffic.py`, `privacy.py`) |
| 7 | IDS false positives | Per-alert `confidence`/`status`/`evidence` + “to confirm” hints, `--sensitivity`, beacon persistence (single sighting = 45, persisted = 78), adaptive noisy-air margin, cross-alert corroboration (`defense.py`) |
| 8 | Ambiguous rogue APs | Noisy-OR scoring over 7 independent indicators; `likely-rogue` needs **≥2 indicators and score ≥ 40**; single-indicator groups listed as `unconfirmed`/`low` and never counted (`engine.py`) |
| 9 | No trust model | `trust.py`: canonical sources with base reliability, ranked binding evidence, noisy-OR fusion (never reaches 100), high/medium/low/very-low labels — surfaced in terminal, CSV and JSON for stations, APs, alerts, rogues and fixes |
| 10 | Sensitive history DB | 0600 at creation + world-readable warnings, `policy` table (salt/retention), `--retain-days` enforced on open, `db` command: `--report`, `--prune-days`, `--delete-mac`, `--anonymize-db --yes` (irreversible), `--purge --yes`, `--vacuum` (`store.py`, `cli.py`) |

Operational notes:

* Pair 0600 file permissions with full-disk encryption for captures/DBs at rest;
  no new dependencies were added, so at-rest encryption stays an OS-layer concern.
* Pseudonym salts live in each database's `policy` table and are **never**
  written to exports; per-export salts make shared reports unlinkable.
* `ephemeral` mode makes persistence calls raise instead of writing — use it for
  live triage on airspace you must not retain data about.
