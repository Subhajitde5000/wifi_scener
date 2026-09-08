# wifi_scener — Research-Grade Wireless Laboratory Platform

**Passive Wi-Fi survey · client attribution · presence history · sensor-grid
positioning · raw capture · cleartext-traffic audit · 12-signature wireless IDS ·
hardening reports · 802.11 frame anatomy · WPA/WPA3 crypto lab · 10 synthetic-data
laboratories · unified experiment engine · async telemetry pipeline · research analytics
— one terminal, every artefact in CSV/JSON/HTML/PCAP.**

Version **5.0.0** · Research-Grade Edition · Python ≥ 3.8 · Linux/macOS/Windows · zero mandatory
dependencies · receive-only by default · consent-gated defensive self-test (`inject`) ·
local synthetic-credential labs (`lab`, `wpa-lab`, `mac-lab`, `track-lab`, `stealth-lab`,
`response-lab`, `scan-lab`, `cred-lab`, `priv-lab`, `rf-lab`, `handshake-lab`) ·
unified `experiment` engine.

```
 __      __.__  _____.__    _________
/  \    /  \  |/ ____\  |  /   _____/ ___________  ____   ___________
\   \/\\/   /  \   __\|  |  \_____  \_/ ___\__  \ /    \_/ __ \_  __ \
 \        /|  ||  |  |  |  /        \  \___/ __ \   |  \  ___/|  | \/
  \__/\\  / |__||__|  |__| /_______  /\___  >____  /___|  /\___  >__|
       \/                         \/     \/     \/     \/     \/
  research-grade · reproducible · observable · extensible
```

---

## Table of contents

1. [What it is / isn't — research-grade scope](#1-what-it-is--isnt)
2. [Feature matrix — all 30 capabilities](#2-feature-matrix)
3. [Research-grade architecture — modular infrastructure](#3-research-grade-architecture)
4. [How device counting without joining works — real 802.11](#4-how-device-counting-without-joining-works)
5. [Install — hardware, OS, dependencies](#5-install)
6. [Hardware for monitor mode — real adapters, real drivers](#6-hardware-for-monitor-mode)
7. [Quick start — 10 commands, then the lab tour](#7-quick-start)
8. [Experiment engine — the unified research framework](#8-experiment-engine)
9. [Event pipeline — async telemetry for concurrent experiments](#9-event-pipeline)
10. [Analytics — detection accuracy, benchmarks, comparison](#10-analytics)
11. [Architecture — every module, every interface](#11-architecture)
12. [Command reference — every flag](#12-command-reference)
13. [Output artefacts — every file, every column](#13-output-artefacts)
14. [SQLite history schema & queries — retention, privacy](#14-sqlite-history-schema--queries)
15. [Methodology — every metric, exactly how it is computed](#15-methodology)
16. [Sensor-grid positioning guide — WLS trilateration at zone granularity](#16-sensor-grid-positioning-guide)
17. [The IDS — 12 signatures, confidence, corroboration](#17-the-ids-signatures-it-detects)
18. [Operational recipes — systemd, ring-buffer, pandas diffing](#18-operational-recipes)
19. [Python API — Engine, Watchdog, ExperimentEngine, Pipeline, Analytics](#19-python-api)
20. [Testing — 260+ offline tests, vectors, fixtures](#20-testing)
21. [Platform support & limitations — stated plainly](#21-platform-support--limitations)
22. [Troubleshooting FAQ](#22-troubleshooting-faq)
23. [Legal & ethics — lab-authorized only](#23-legal--ethics)
24. [Changelog](#24-changelog)
25. [Trust & privacy model — 10 fixes](#25-trust--privacy-model)

---

## 1. What it is / isn't

**It is** a PhD-level, passive RF-intelligence and network-ownership **research platform** for *your* airspace. It listens to frames already broadcast, reads your own router's association table, analyses captures you legally hold, and hosts **10 synthetic-data laboratories** plus a **unified experiment engine** that makes every run reproducible, observable and scorable. Every survey, IDS, audit and history feature is receive-only: it never joins a network, clones an AP, cracks a key or decrypts anything outside laboratory key material you own.

There is exactly **one** transmitting command, `inject`, and it is a *self-test rig for your own defences* — canary markers, bounded PMF probes, bounded unicast deauth/disassoc tests and a beacon-only Evil-Twin drill (no client/data path). Every lab that synthesises data does so **offline, with ground truth that never reaches the student** (0600 files, token-gated instructor dashboards). The new `experiment` command wraps any lab in a reproducible lifecycle (START → CONFIG → LAB_EVENT → PACKET/EVIDENCE → DETECTION → ANALYSIS → RESPONSE → RESULT → RESET) with seed, config hash, timeline, artifacts, scoring and comparison.

**It isn't** an attack kit. These remain deliberately absent:

| Not in this tool | What ships instead |
|---|---|
| Decrypt WPA/WPA2/WPA3 traffic outside lab | Protected frames are skipped and *counted*; `traffic` proves what leaks *without* encryption; `wpa-lab` decrypts only lab captures with lab keys you own |
| Deauth/disassoc floods, broadcast kicking, loops | `ids` (7 base + 5 advanced signatures via `AdvancedWatchdog`) detects floods live; `inject` sends only bounded, one-shot, unicast bursts at a device you name |
| Working rogue AP (accepts clients, captures creds) | `ids` + `scan` detect rogue BSSIDs; `inject --mode evil-twin` is beacon-only drill |
| Handshake capture for cracking | `ids` fires **critical** on harvest chains; `handshake-lab` teaches capture/audit/authenticate distinction with real PBKDF2 timing |
| Unrestricted injection / replay | Only `inject`, consent-gated, target-restricted, fully audited, caps enforced |
| Jamming / channel flooding | Hard per-mode caps, minimum inter-frame interval, self-terminating |
| De-anonymising randomized MACs | Flagged for honesty, never correlated; `mac-lab`/`priv-lab` prove why fingerprint ≠ identity |
| Indefinite bystander tracking | `record` refuses without your own BSSID; probe sightings stay ephemeral; retention 90d default |

---

## 2. Feature matrix

| # | Capability | Command(s) | Root? | Monitor? | Provenance |
|---|---|---|---|---|---|
| 1 | Survey all nearby networks, A-to-Z per AP | `scan`, `detail`, `offline` | no | no | LIVE/CAPTURED |
| 2 | Count devices per AP, without joining | `monitor`, `devices`, `full` | yes | yes | LIVE |
| 3 | Full census of your own network (assoc table + RF + LAN) | `own` | optional | optional | LIVE |
| 4 | Presence over time (sessions, roster) | `record`, `presence` | no | no | LIVE |
| 5 | Device location (WLS trilateration + zones) | `locate` | no | no | LIVE |
| 6 | Movement trails + dwell + ASCII map | `trail` | no | no | LIVE |
| 7 | Per-scan device detail (signal/traffic/probes/vendor) | all | mixed | mixed | LIVE |
| 8 | Raw 802.11 capture (pcap, rotation, ring) | `capture` | yes | yes | CAPTURED |
| 9 | Cleartext dissection (DNS/HTTP/SNI/ARP/DHCP/flows) | `traffic` | no(pcap)/yes(live) | yes(live) | CAPTURED/LIVE |
| 10 | Passive wireless IDS (12 signatures, AdvancedWatchdog) | `ids` | yes(live)/no(pcap) | yes(live) | LIVE/CAPTURED |
| 11 | Hardening audit (weakness→attack→fix) | `audit` | no | no | LIVE/CAPTURED |
| 12 | Frame-by-frame 802.11 education | `frames` | no | no | CAPTURED |
| 13 | Channel congestion + best channels | `scan`, `watch` | no | no | LIVE |
| 14 | Rogue/evil-twin detection | `scan` (`*_rogue_alerts.csv`) | no | no | LIVE |
| 15 | LAN inventory (IPs, hostnames, ports, nmap) | `own`, `devices --lan` | no | no | LIVE |
| 16 | Live dashboard | `watch` | no | optional | LIVE |
| 17 | Structured export (5 CSVs + JSON + HTML + MD) | `-o --format` everywhere | no | no | — |
| 18 | **Authorized** injection self-test (6 modes) | `inject` | no(selftest)/yes(live) | yes(live) | SIMULATED |
| 19 | Phishing awareness lab (synthetic creds, local) | `lab` | no | no | SYNTHETIC |
| 20 | WPA/WPA2/WPA3 decryption lab (real crypto) | `wpa-lab` | no | no | CAPTURED |
| 21 | MAC randomization lab (evidence engine, twin trap) | `mac-lab` | no | no | SYNTHETIC |
| 22 | Long-term tracking lab (14d, decoy trap) | `track-lab` | no | no | SYNTHETIC |
| 23 | Stealth detection lab (implant, ps-vs-ss) | `stealth-lab` | no | no | SIMULATED |
| 24 | Response automation lab (R1–R6, FP trap) | `response-lab` | no | no | SIMULATED |
| 25 | Scan/scope lab (virtual estate, sentinel) | `scan-lab` | no | no | SIMULATED |
| 26 | Credential & session lab (6 surfaces vs TLS) | `cred-lab` | no | no | CAPTURED |
| 27 | Privacy & MAC-randomization lab | `priv-lab` | no | no | SYNTHETIC |
| 28 | RF interference lab (4 interferers, resilience) | `rf-lab` | no | no | SIMULATED |
| 29 | Handshake & password-audit lab (3 tiers) | `handshake-lab` | no | no | CAPTURED |
| 30 | **Experiment engine** (unified lifecycle, scoring, comparison) | `experiment` | no | no | ALL |
| 31 | **Event pipeline** (async, WebSocket, back-pressure) | Python API (`pipeline`) | no | no | LIVE |
| 32 | **Analytics** (precision/recall/F1, ROC, benchmarks) | Python API (`analytics`) | no | no | ALL |

Every lab exposes: `make-dataset`/`make-scenario`/`make-fixture` (instructor, 0600 ground truth), `inventory`, `correlate`/`analyze`/`hunt`/`compare`, `exercises`, `score`, `web` (student portal + token-gated instructor dashboard with reset/regenerate).

---

## 3. Research-grade architecture

### Design standard (§1–§2)

Never simplified to toy level. Real standards everywhere: **802.11-2020** management/control/data frame formats, **Radiotap** headers, **802.11i RSN** (AKM selectors: PSK/SAE/8021X), **802.11w PMF**, **WPA2/WPA3** 4-way handshake (EAPOL-Key with MIC + replay counter), **802.11 channelization** (2.4/5/6 GHz, 20/40/80/160 MHz via HT/VHT/HE IEs), **DHCP/ARP/DNS/HTTP/TLS ClientHello SNI**, **PCAP/PCAPNG** linktypes (1/105/127/ETHERNET), **PBKDF2-SHA1** (RFC 6070), **AES-CCM/GCM** (RFC 3610/NIST), **AES-CMAC** (RFC 4493), **AES-KW/KWP** (RFC 3394/5649).

If a component needs hardware not present (monitor NIC, `iw` on macOS), the architecture **designs the integration point** (abstract `SurveyBackend`, `MonitorSniffer`, `CaptureSource`) so the real component plugs in when lab hardware is available — never faked.

### Modular separation (§2)

```
┌─────────────────────────────────────────────────────────────────┐
│  Frontend (rich tables / HTML dashboards / lab web portals)      │
├─────────────────────────────────────────────────────────────────┤
│  API layer (cli.py — 27 commands, argparse, wiring)             │
├─────────────────────────────────────────────────────────────────┤
│  Auth / Scope (lab token-gated instructor routes, --authorized) │
├─────────────────────────────────────────────────────────────────┤
│  Experiment Engine (experiment.py — lifecycle, reproducibility)  │
│  ┌ experiment_id · title · objective · prerequisites            │
│  │  target_resources · config · seed · timeline · observations   │
│  │  artifacts · logs · result · reset · scoring · comparison     │
├─────────────────────────────────────────────────────────────────┤
│  Lab Resource Mgmt (per-lab dataset generators, 0600 ground truth)│
├─────────────────────────────────────────────────────────────────┤
│  Network Monitoring (backends/survey.py — iw/nmcli/iwlist/airport/netsh)│
│  Packet Processing (backends/sniffer.py — scapy, channel hop)    │
│  Protocol Analysis (models.py/engine.py/frames.py — 802.11 IEs) │
├─────────────────────────────────────────────────────────────────┤
│  Detection Engine (defense.py — Watchdog 7 + AdvancedWatchdog 12)│
│  Traffic Engine (traffic.py — cleartext dissection, redaction)  │
│  Locate Engine (locate.py — WLS trilateration, zones)           │
├─────────────────────────────────────────────────────────────────┤
│  Event Pipeline (pipeline.py — async queue, workers, WebSocket) │
├─────────────────────────────────────────────────────────────────┤
│  Data Storage (store.py + experiment.py — WAL SQLite, retention)│
│  Research Datasets (each lab's synthetic pcaps/json, versioned) │
│  Analytics (analytics.py — precision/recall/F1, ROC, benchmarks)│
├─────────────────────────────────────────────────────────────────┤
│  Instructor Console (per-lab /i/<token> + experiment analytics) │
│  Student Environment (portals, evidence, scoring, report export) │
└─────────────────────────────────────────────────────────────────┘
```

Each subsystem has a **clean interface** so it can be replaced, benchmarked or researched independently (e.g. swap `Watchdog` for `AdvancedWatchdog`, swap `Store` backend, plug a real SDR capture source into `MonitorSniffer`).

### Real data contract (§3)

| Provenance | Meaning | Example | Never mislabeled |
|---|---|---|---|
| **LIVE** | Live RF/host observation | `scan`, `monitor`, `capture --live`, `record` | — |
| **CAPTURED** | Pcap/log you hold offline | `offline`, `traffic`, `ids --pcap`, `wpa-lab decrypt` | — |
| **REPLAYED** | Replay of captured data | `frames`, `offline` re-analysis | marked as replay |
| **SIMULATED** | Deterministic simulation | `scan-lab`, `rf-lab`, `response-lab`, `stealth-lab` | labelled simulated |
| **SYNTHETIC** | Generated with ground truth | `mac-lab`, `track-lab`, `priv-lab`, all `make-dataset` | ground truth 0600, never student-visible |

---

## 4. How device counting without joining works

802.11 data frames carry up to four MAC addresses plus To-DS/From-DS flags. Even fully encrypted, **headers are plaintext**:

| Frame (type/subtype) | Field seen | What it proves |
|---|---|---|
| Data/QoS, To-DS=1 | `addr2`=client, `addr3`=AP | client **associated** with that AP |
| Data/QoS, From-DS=1 | `addr1`=client, `addr2`=AP | same binding, downlink |
| Assoc/Reassoc Req (0/0, 0/2) | `addr2→addr3` | definitive join event |
| EAPOL (LLC/SNAP 0x888E) | AP of `addr3` | device just (re)authenticated |
| Beacon/ProbeResp (0/8, 0/5) | full IE set | AP fingerprint |
| ProbeReq (0/4) | `addr2` + SSID | unassociated device + remembered networks |
| Deauth/Disassoc (0/12, 0/11) | `addr1/addr3` | churn or attack (`ids` watches) |

RSSI from Radiotap per frame → per-client min/max/avg + distance estimate. Locally-administered bit (byte 0, bit 1) marks privacy MACs. The engine fuses this with the router's own `iw station dump` association table when you run `own`/`record` on your own AP — that table is **ground truth** (confidence 98) versus RF-observed bindings (confidence 35–85 by evidence kind).

---

## 5. Install

```bash
git clone <repo> && cd wifi_scener
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # scapy + rich
# or: pip install -e ".[full]"  # same, plus entry_points wifiscanner
# or: pip install -e ".[research]"  # + numpy/matplotlib for analytics plots
python3 main.py interfaces               # capability self-check
python3 main.py experiment list          # 7 core experiments in catalogue
```

| Piece | Needed for | Install |
|---|---|---|
| **scapy** | monitor capture, pcap import, frame dissection | `pip install scapy` |
| **rich** | colour tables/panels (graceful ASCII fallback) | `pip install rich` |
| **numpy / matplotlib** | analytics plots, ROC curves (optional) | `pip install -e ".[research]"` |
| `iw` | Linux survey + `station dump` + monitor setup | `apt install iw` |
| `nmcli` | Linux fallback survey | NetworkManager |
| `nmap` | LAN inventory richer/faster (auto-detected) | `apt install nmap` |
| `airmon-ng` | alternative monitor bring-up (`--airmon`) | `apt install aircrack-ng` |

Everything degrades gracefully: without scapy the survey/LAN/history/audit/labs work; monitor commands tell you exactly what to install. No lab needs extra deps beyond stdlib.

---

## 6. Hardware for monitor mode

Monitor mode is needed for: `monitor`, `capture`, `ids` live, `traffic --live`, and over-the-air census in `own`/`full`/`devices`.

* **Linux is reference.** Atheros `ath9k`/`ath10k`, MediaTek `mt76`, Ralink `rt2x00` work out of the box. Check: `iw list | grep -A6 "Supported interface modes" | grep monitor`.
* **Classic choice:** TL-WN722N **v1** (`ath9k_htc`) or any `mt7601u`/`mt76x2u` USB — $15, monitor + injection-capable (but we only use injection for the consent-gated self-test).
* **macOS:** monitor effectively unavailable on modern Macs; use a USB Linux sensor, `offline` locally.
* **Windows:** no monitor via normal driver stack — `netsh wlan` for survey; capture on a Pi/Linux sensor, analyse pcap on Windows.
* **Verify what you have:**

```bash
python3 main.py interfaces
# platform / root? / survey backends / scapy / OUI size / adapter list
python3 main.py experiment analytics --run-id <id>  # after a live run
```

For research throughput: one sensor per channel set is ideal (e.g. three Pis on ch 1/6/11 for 2.4 GHz). The pipeline benchmarks (`pipeline.stats()`) tell you if your worker pool is keeping up: `enqueued`, `processed`, `dropped` (back-pressure), `avg_handler_ms`, `p95_handler_ms`.

---

## 7. Quick start

```bash
# 1. Survey (no root, no radio beyond your normal Wi-Fi)
python3 main.py scan
python3 main.py scan -o output --format csv json html md

# 2. Your own network, authoritatively
python3 main.py own --ports

# 3. Presence history of your AP (Ctrl-C stops, retention 90d default)
python3 main.py record --db home.sqlite --lan
python3 main.py presence --db home.sqlite --since -24h
python3 main.py presence --db home.sqlite --known

# 4. Location from 3 sensors (each: record --sensor kitchen etc.)
python3 main.py locate --db merged.sqlite --sensors sensors.csv --zones zones.csv --recompute
python3 main.py trail --db merged.sqlite --sensors sensors.csv --mac AC:BC:32:01:02:03 --map -o out/

# 5. Raw capture with production storage semantics
sudo python3 main.py capture -i wlan0 -d 86400 -o day.pcap --rotate-mb 64 --ring-segments 16 --strip-payloads

# 6. What leaked cleartext on YOUR network
python3 main.py traffic day.pcap -o out/
# redaction ON by default; --no-redact only with consent

# 7. IDS — is anyone kicking clients or harvesting handshakes?
sudo python3 main.py ids -i wlan0 -d 3600 --db home.sqlite --follow
python3 main.py ids --pcap tests/fixture.pcap   # offline triage

# 8. How to harden
python3 main.py audit -o reports/

# 9. Understand every frame
python3 main.py frames day.pcap --limit 40
python3 main.py frames day.pcap --handshakes

# 10. Verify the IDS path before trusting it (CI-safe, no radio)
python3 main.py inject --mode ids-selftest -o checks/

# 11. Unified experiment engine (research-grade)
python3 main.py experiment list
python3 main.py experiment start --id wireless-ids-001 --config '{"pcap":"tests/fixture.pcap"}' --seed 42
python3 main.py experiment status --run-id <id>
```

Full tour with no hardware:

```bash
python3 tests/make_fixture.py
python3 main.py offline tests/fixture.pcap -o demo/ --format csv json html md
python3 main.py traffic tests/fixture.pcap
python3 main.py ids --pcap tests/fixture.pcap
python3 main.py frames tests/fixture.pcap --filter beacon
python3 main.py experiment list && python3 main.py experiment catalogue
```

---

## 8. Experiment engine

`wifiscanner/experiment.py` — the reusable framework (§4, §8–§10, §13).

### Every experiment supports

| Field | Meaning | Example |
|---|---|---|
| `experiment_id` | stable ID | `wireless-ids-001` |
| `title` | human name | `Wireless IDS — Deauth & Harvest` |
| `objective` | what the student must achieve | `Detect deauth floods and full harvest chains` |
| `prerequisites` | what must exist first | `pcap with handshake, monitor NIC, lab key` |
| `target_resources` | authorized lab resources | `wlan0mon`, `lesson.pcap`, `10.77.*` |
| `configuration` | parameters + seed | `{"window": 10, "flood": 5, "seed": 42}` |
| `start/stop` | lifecycle | `engine.start(id, config, seed)` → `engine.finish(run, result)` |
| `parameters` | configurable variables | `window_s`, `channels`, `intensity` |
| `event_collection` | timeline of phases | START/CONFIG/LAB_EVENT/PACKET/DETECTION/ANALYSIS/RESPONSE/RESULT/RESET |
| `observations` | raw measurements | per-packet RSSI, telemetry rows, flow records |
| `results` | scored outcome | `{"tp": 12, "fp": 1, "f1": 0.96}` |
| `logs` | structured logs | `["[CONFIG] window=10", "[DETECTION] deauth-flood ..."]` |
| `artifacts` | files with hash + provenance | `{"path": "lesson.pcap", "provenance": "CAPTURED", "sha256": "abc1"}` |
| `reset` | wipe and rerun | `engine.reset(run_id)` — timeline cleared, ready to rerun |
| `reproducibility` | deterministic rerun | `seed` + `config` → `reproducibility_hash` (sha256[:16]) — same inputs → same ground truth |
| `instructor_notes` | pedagogy | `Twin trap: simultaneous presence is hard anti-evidence` |
| `student_submission` | answers | `{"q_scope_line": "10.77"}` |
| `scoring` | rubric + feedback | `score 88/100, 3/5 correct, feedback lines` |

### Provenance (§3)

Never present simulated as real. Every artifact is tagged `LIVE`/`CAPTURED`/`REPLAYED`/`SIMULATED`/`SYNTHETIC` and rendered in exports and web UIs.

### Catalogue (pre-registered, extensible)

| ID | Title | Category | Provenance |
|---|---|---|---|
| `wireless-survey-001` | Passive RF Survey & Client Attribution | wireless/survey | LIVE |
| `wireless-ids-001` | Wireless IDS — Deauth & Harvest | wireless/ids | LIVE |
| `crypto-wpa-001` | WPA2 MIC Verification & Decryption | wireless/crypto | CAPTURED |
| `privacy-mac-001` | MAC Randomization Correlation | privacy/tracking | SYNTHETIC |
| `system-stealth-001` | Stealth Implant Detection | system/monitoring | SIMULATED |
| `network-scan-001` | Scope-Controlled Network Scanning | network/scanning | SIMULATED |
| `creds-tls-001` | Cleartext vs TLS Credential Exposure | network/credentials | CAPTURED |

Instructors register more:

```python
from wifiscanner.experiment import ExperimentEngine, ExperimentDef
eng = ExperimentEngine("lab.sqlite")
eng.register(ExperimentDef(
    id="custom-001", title="My RF Experiment",
    objective="Measure channel utilisation under microwave@70",
    category="wireless/rf", data_provenance="SIMULATED",
    prerequisites=["rf-lab baseline"], target_resources=["LAB-AP-3"],
    default_config={"interferer": "microwave", "intensity": 70},
    instructor_notes="Expect ch11 goodput −19% while ch1 flat."))
run = eng.start("custom-001", config={"intensity": 80}, seed=7)
run.log_event("LAB_EVENT", {"channel_util": 78, "snr": 12})
eng.finish(run, result={"goodput_delta": -19.8})
eng.record_metric(run.id, "goodput", -19.8, "ch11 vs baseline")
print(eng.compare_runs([run.id, other_run.id]))
```

### CLI

```bash
wifiscanner experiment catalogue                  # bootstrap 7 definitions
wifiscanner experiment list --db lab.sqlite     # table of definitions
wifiscanner experiment start --id wireless-ids-001 --config '{"pcap":"tests/fixture.pcap"}' --seed 42 --db lab.sqlite
wifiscanner experiment status --run-id <id> --db lab.sqlite
wifiscanner experiment score --run-id <id> --answers answers.json
wifiscanner experiment compare --runs id1,id2 --db lab.sqlite
wifiscanner experiment analytics --run-id <id> --db lab.sqlite
wifiscanner experiment reset --run-id <id> --db lab.sqlite
```

DB is WAL SQLite — multiple students can run concurrently; each run is an independent row, writes are short transactions.

---

## 9. Event pipeline

`wifiscanner/pipeline.py` — async telemetry bus (§12).

```
 packet sources ──▶ IngestBus (bounded Queue) ──▶ worker pool ──▶ handlers
 (sniffer, pcap,    (back-pressure: drops              (IDS, traffic,  ──▶ Store
  host telemetry)     oldest, counts                 locate, etc)       │
                      drops)  │                                       │
                              └─ WebSocket fan-out ──────────────────▶│ frontend
```

* **Bounded queue** (`max_queue=10000` default) with back-pressure: when full, oldest event dropped and `dropped` counter incremented — observable, not silent.
* **Worker pool** (`workers=4` default) — processes events without blocking API workers.
* **Fan-out** — `subscribe(callback)` for WebSocket broadcasters; `on(kind, handler)` for specific detectors.
* **Metrics** — `pipeline.stats()` → `enqueued`, `processed`, `dropped`, `errors`, `queue_depth`, `avg_handler_ms`, `p95_handler_ms`.
* **Graceful fallback** — if no asyncio loop (CLI, tests) it runs synchronously via direct dispatch.

```python
from wifiscanner.pipeline import get_pipeline, PipelineEvent
pipe = get_pipeline()
pipe.on("ids-alert", lambda ev: print(ev.payload))
pipe.subscribe(lambda ev: websocket_broadcast(ev.to_json()))
pipe.start()  # starts 4 worker threads
pipe.emit_now("sniffer", "packet", {"bssid": "AA:..", "rssi": -42}, provenance="LIVE")
print(pipe.stats())
pipe.stop()
```

---

## 10. Analytics

`wifiscanner/analytics.py` — research metrics (§5).

* **`score_ids(ground_truth, alerts, window_s=10)`** — confusion matrix per kind + overall: `tp/fp/fn`, `precision`, `recall`, `f1`, `accuracy`, `fpr`, `avg_latency_ms`, `p95_latency_ms`, plus `unmatched_ground_truth` for false-negative analysis.
* **`score_correlation(ground_truth, predicted)`** — clustering accuracy for MAC labs: pair-level `tp/fp/fn`, `precision`, `recall`, `f1`.
* **`benchmark_throughput(events, window_s=1)`** — `throughput_per_s`, `peak_per_window`, `duration_s`.
* **`compare_experiments(runs)`** — side-by-side table across runs with `delta`, `mean`, `delta_pct` per metric.
* **`roc_curve(scores, thresholds)`** — ROC points from `(score, is_positive)` pairs.
* **`export_comparison_csv(comparison, path)`** — 0600 CSV of comparison table.

```python
from wifiscanner.analytics import score_ids, compare_experiments

gt = [{"kind": "deauth-flood", "bssid": "AA:BB:CC:DD:EE:FF", "start": 100, "end": 110}]
alerts = [{"kind": "deauth-flood", "bssid": "AA:BB:CC:DD:EE:FF", "ts": 103}]
print(score_ids(gt, alerts))
# {'overall': {'precision': 1.0, 'recall': 1.0, 'f1': 1.0, 'avg_latency_ms': 3000, ...}, ...}

runs = [
    {"id": "run-a", "config": {"intensity": 60}, "result": {"goodput": -12.1}, "metrics": {"f1": 0.96}},
    {"id": "run-b", "config": {"intensity": 80}, "result": {"goodput": -19.8}, "metrics": {"f1": 0.88}},
]
print(compare_experiments(runs))
```

All metrics expose **why** a result occurred (per-kind breakdown, latency distribution, unmatched ground truth) — not just a single score.

---

## 11. Architecture

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
                        5×CSV, JSON,       SQLite: scans,  Watchdog 7 +
                        HTML, Markdown     devices, obs.,   AdvancedWatchdog 12
                                           sessions, fixes, hardening audit
                                           warden           frames.py
                        experiment.py      pipeline.py      analytics.py
                        unified lifecycle  async bus        precision/recall/
                        7→N experiments   WebSocket        F1, ROC, benchmarks
                        cli.py (27 cmds) ──► display.py     rich/ASCII
```

| Module | Responsibility | Research-grade detail |
|---|---|---|
| `wifiscanner/models.py` | `AccessPoint`/`Station` dataclasses, RF math (channel↔freq, path-loss ranging, quality), security score/grade/risk, per-binding evidence + census | Confidence 0–100 per binding, router-confirmed vs RF-observed census, identity honesty for rotating MACs |
| `wifiscanner/oui.py` | OUI vendor DB, MAC normalisation, randomized + multicast detection | 24-bit prefix, `(randomized MAC)` sentinel |
| `wifiscanner/backends/survey.py` | `iw`/`nmcli`/`iwlist`/`airport`/`system_profiler`/`netsh` parsers → AP objects | Auto-fallback, 5 backends, real IE parsing |
| `wifiscanner/backends/sniffer.py` | monitor-mode bring-up (`iw`/`airmon-ng`), passive 802.11 collector: full IE/RSN parsing, To-DS/From-DS attribution, channel hopping, streaming pcap writer (rotate + ring) | Never transmits; header-only mode via `snaplen` |
| `wifiscanner/backends/lan.py` | own-AP `station dump`, ARP/ping sweep, PTR hostnames, TCP port sweep, nmap accel, current-connection facts | `authoritative=True` → router-confirmed ground truth |
| `wifiscanner/engine.py` | multi-source merge (richer wins), congestion, best channels, rogue detection (noisy-OR, ≥2 indicators), summary | 7-indicator rogue scoring, 0–100 fused confidence |
| `wifiscanner/store.py` | SQLite WAL: scans/networks/devices/observations/fixes/warden/policy, session splitting, retention, anonymization | 0600, retention enforced on open, per-device erasure |
| `wifiscanner/locate.py` | range model, WLS trilateration/bilateration, nearest-sensor fallback, sanity guard, zones, dwell, ASCII map | Zone-primary answer, low-confidence coordinates withheld, error radius |
| `wifiscanner/traffic.py` | cleartext dissector (DNS/HTTP/TLS-SNI/ARP/DHCP), flows, credential alerts (redacted) | Redaction ON by default, `anonymize_ips` to /24 |
| `wifiscanner/defense.py` | `Watchdog` (7 detectors) + `AdvancedWatchdog` (12: +KRACK, downgrade, CSA, PMF-bypass) | Confidence/status/evidence per alert, sensitivity + adaptive margin |
| `wifiscanner/frames.py` | frame-by-frame annotated 802.11 anatomy | Radiotap → FC → IE-by-IE → LLC/SNAP → EAPOL flags |
| `wifiscanner/inject.py` | *only* transmitter: frame builders, consent gates, hard caps, 0600 audit CSV, offline `run_ids_selftest`, kick/PMF verdict, beacon-only Evil-Twin | Dry-run default, broadcast refused |
| `wifiscanner/experiment.py` | **NEW** Unified experiment lifecycle engine | 7→N catalogue, seed+hash reproducibility, WAL, comparison |
| `wifiscanner/pipeline.py` | **NEW** Async event pipeline, worker pool, WebSocket fan-out | Bounded queue, back-pressure, `stats()` |
| `wifiscanner/analytics.py` | **NEW** Research metrics: `score_ids`, `score_correlation`, `benchmark_throughput`, `compare_experiments`, `roc_curve` | Per-kind FP/FN, latency P95, ROC |
| `wifiscanner/export.py` | CSV×5 / JSON / styled HTML / Markdown writers | 0600, anonymized mode, BOM for Excel |
| `wifiscanner/display.py` | rich tables/panels with full plain-text fallback | `NO_COLOR=1` forces plain |
| `wifiscanner/wcrypto.py` | stdlib AES/CCM/GCM/CMAC/KW/RC4 + PTK/PMK derivation, pinned to vectors | FIPS-197/RFC 3610/4493/3394/NIST-GCM |
| `wifiscanner/wpalab.py` | WPA-lab engine: capture parsing, MIC verify, CCMP/GCMP decrypt, GTK unwrap, web | Student + instructor UIs |
| `wifiscanner/lab.py` | phishing-awareness lab (synthetic creds) | Funnel, debrief pages |
| `wifiscanner/devlab.py` | mac-lab + track-lab: dataset generators, correlation engine, tracker | Twin trap, decoy trap |
| `wifiscanner/hidmon.py` | stealth-lab: scenario, signal engine (concealment 60), alerts | Tick control, ps-vs-ss |
| `wifiscanner/autoresp.py` | response-lab: rule engine R1–R6, 4 modes, approvals, rollback | FP trap (R6 + empty allowlist) |
| `wifiscanner/scanlab.py` | scan-lab: virtual estate, job engine (concurrency+rate), sentinel | 10.77.* only, simulated |
| `wifiscanner/credlab.py` | credential lab: 6 surfaces vs TLS, detector alerts | Synthetic identities |
| `wifiscanner/privlab.py` | privacy lab: clustering, PNO-scrub, scope sentinel | 02:1a:b4 block only |
| `wifiscanner/rflab.py` | RF lab: 4 interferers, detector, resilience exercise | Intensity caps, no RF |
| `wifiscanner/hsaudit.py` | handshake-lab: 3 tiers, PBKDF2 timing, 3-state teaching | Real 4-way handshakes |
| `wifiscanner/cli.py` | argparse surface, 27 commands, guardrails | Every lab wired |

---

## 12. Command reference

Global flags: `-v/--verbose`, `-q/--quiet`, `--no-banner`, `--version`. Shared scan-family flags: `-i`, `-o`, `--prefix`, `--format`, `--sort`, `--limit`, `--db`, `--sensor`, `--retain-days`, `--privacy-mode`, `--anonymize`. Times: `YYYY-MM-DD`, `HH:MM`, `-2h15m`, `now`.

### `scan` — survey nearby APs
`iw` → `nmcli` → `iwlist` → `airport` → `netsh` auto-selection. Flags: `--backend`, `--no-rescan`. Prints AP table, congestion, rogues, summary. `-o` exports, `--db` persists.

### `monitor` — passive device attribution
Puts card in monitor mode (auto, restore-on-exit), hops channels, attributes every data frame to AP↔client pairs. Flags: `-d` (60s), `-c 1,6,11`, `--bands`, `--bssid`, `--hop-interval`, `--airmon`, `--no-monitor-setup`, `--write-pcap`. Needs root+scapy+monitor NIC.

### `own` — authoritative census of YOUR network
Fuses: (1) `iw station dump` of your AP, (2) survey, (3) monitor locked to your BSSID, (4) LAN sweep. Flags: `-d` (25s), `--ports`, `--no-lan`, `--no-monitor`.

### `full` — everything at once
`scan` + `monitor` + LAN + exports; forces `-o output` + HTML. Flags: `-d`, `--bands`, `--lan`, `--ports`.

### `detail <SSID-or-BSSID>` — one network, A-to-Z
Substring match; with root+scapy runs locked monitor pass (`-d` 45s). `--no-monitor` skips.

### `devices` — client-only view
Monitor census and/or `--lan [--subnet 192.168.1.0/24] [--ports]`.

### `watch` — live dashboard
Refreshing (`-n` 8s); `--monitor` folds in monitor pass per cycle.

### `offline <pcap>` — analyse existing captures
Full monitor pipeline on pcap/pcapng (Radiotap/Ethernet/802.11). No root, no radio. All export/DB flags accepted.

### `capture` — raw frame capture, production storage
Streaming writer: `--rotate-mb 64` → `capture-001.pcap`…; `--ring-segments 8` → bounded ring; `--analyze` parses at exit. Flags: `-i -d -c --bands --bssid --hop-interval -o FILE --rotate-mb --ring-segments`, plus `--ack-sensitive`, `--strip-payloads` (128-B header-only), `--max-age-days N`. 0600 files.

### `traffic [pcap] | --live -i IF` — cleartext dissection
Only cleartext frames. Extracts DNS/HTTP+Host+UA, TLS SNI (hand-rolled ClientHello, metadata only), ARP, DHCP; aggregates flows. Credential patterns flagged, values never logged. **Redaction ON by default**; `--no-redact` warns loudly, `--anonymize-ips` masks to /24. Output: `traffic_events.csv` + `traffic_flows.csv` with `-o DIR`. `--max-frames` (200k), `--limit`, live `-d`.

### `record` — continuous presence history (own network, guarded)
`--db presence.sqlite`, `-n` 30s, `-d` 0=forever, `--backend`, `--lan`, `--sensor`, `--bssid AA:..[,BB:..]` explicit own-AP list. **Target rule:** without `--bssid`, auto-targets *your current connection*; with neither, **refuses** (exit 2). `--pcap FILE` = one-shot import. Privacy: `--retain-days` (90 default, enforced on open), `--privacy-mode`, `--anonymize`.

### `presence` — query the history
`--db`, filters `--mac/--ssid/--since/--until`, `--gap` 300s, `--limit` 100, `-o DIR` → `presence_sessions.csv`. `--known` shows roster.

### `locate` — multi-sensor positioning from history
`--sensors sensors.csv` (**required**), `--zones`, `--db`, `--mac`, `--window` 3.0s, `--n-exp` 2.7, `--since/--until`, `--recompute`, `--live -d 20 -i wlan0`. Per-fix table + ASCII map when ≥2 sensors.

### `trail` — movement of one device
`--mac` (**required**), `--db`, optional `--sensors/--zones/--window/--since/--until`, `--map`, `-o DIR` → `trail-<MAC>.csv`. Without `--sensors` degrades to presence-only trail.

### `ids` — passive wireless IDS (7 base, 12 advanced)
Live: `-i wlan0 -d 60` (root; monitor). Offline: `--pcap FILE`. Tuning: `--window` 10.0s, `--flood` 5, `--sensitivity {low,medium,high}` (scales threshold 2×/1×/0.6×). Every alert: `confidence` 0–100 + `status` (unconfirmed/corroborated/confirmed) + `evidence` + “to confirm” hint; beacon mutations must persist across beacons to upgrade; adaptive margin raises bar in noisy air. Warden: `--db warden.sqlite --learn` baselines APs; every beacon from unknown BSSID → `unknown-bss`. `--follow` streams live; `-o DIR` exports `ids_alerts.csv`. Detection only. Advanced: via Python API `AdvancedWatchdog` adds KRACK, downgrade, CSA-spoof, PMF-bypass (+ `research_stats()`).

### `audit` — hardening report
Live scan or `--pcap`/`--ssid` filter; one row per check per BSS: `PASS/WARN/FAIL + severity + fix`. `-o DIR` writes `audit_report.md`.

### `frames` — 802.11 frame anatomy
`frames capture.pcap [--limit 20] [--filter beacon|probe-req|assoc-req|deauth|disassoc|data|handshake]`. Annotates radiotap, FC, address-field semantics, protected-bit, IE-by-IE beacon decode (SSID, rates, DS channel, TIM, country, BSS load, HT/VHT caps, full RSN: group/pairwise/AKM by IEEE name, PMF bits, vendor/WPS), LLC/SNAP ethertype, EAPOL role+flags decoded from bytes. `--handshakes` prints census.

### `inject` — authorized, defensive packet injection (self-test only)
Only transmitter. **Dry run by default**: without `--transmit` it builds frames, prints them and writes audit trail without touching radio. Live needs **root + `--authorized`** (+ `--yes` for kick modes). Hard rate-capped (≤6 probes/4 canaries per channel; ≤4 deauth total — below IDS flood 5), spaced by minimum interval, only unicast AP+client you name, every frame in 0600 `injection_audit.csv`. Floods/broadcast/jam/replay not implemented.

| Mode | Purpose | Transmits? |
|---|---|---|
| `--mode ids-selftest` | synthesise deauth/disassoc/forced-reauth/beacon-mutation/unknown-BSS signatures **offline** and confirm watchdog fires | never (no radio) |
| `--mode probe` | ordinary active scanning probes; `--ssid` for directed, otherwise wildcard | dry run / guarded live |
| `--mode canary` | distinctive probe marker (`--token`) to verify remote sensors log it | dry run / guarded live |
| `--mode pmf-test` | tiny unicast deauth burst at **one of your own clients** (`--bssid`+`--client`), reports PMF works/kicked | root+`--transmit --authorized --yes` |
| `--mode deauth` | bounded, one-shot, unicast deauth/disassoc burst: `--frame-type {deauth,disassoc,both}`, `--direction {ap-to-sta,sta-to-ap}`, `--count` hard-capped | root+`--transmit --authorized --yes` |
| `--mode evil-twin` | beacon-only rogue-AP drill: beacons `--ssid YOUR-OWN-name` from spoofed BSSID on `-c CH`, `--security {open,wpa2}`, `--duration` capped, self-terminating; no probe/assoc/auth/DHCP/data — no client can connect | root+`--transmit --authorized --yes` |

### `experiment` — unified research-grade lifecycle (NEW in 5.0)

```bash
wifiscanner experiment catalogue --db lab.sqlite          # bootstrap 7 definitions
wifiscanner experiment list --db lab.sqlite               # table of all definitions
wifiscanner experiment start --id wireless-ids-001 \
    --config '{"pcap":"tests/fixture.pcap"}' --seed 42 --db lab.sqlite
wifiscanner experiment status --run-id <id> --db lab.sqlite
wifiscanner experiment status --db lab.sqlite             # recent runs table
wifiscanner experiment score --run-id <id> --answers answers.json --db lab.sqlite
wifiscanner experiment compare --runs id1,id2 --db lab.sqlite
wifiscanner experiment analytics --run-id <id> --db lab.sqlite
wifiscanner experiment reset --run-id <id> --db lab.sqlite
```

Every run stores `seed`, `config`, `reproducibility_hash` (sha256 of config+seed), `timeline` (START→CONFIG→LAB_EVENT→PACKET→DETECTION→ANALYSIS→RESPONSE→RESULT→RESET), `observations`, `artifacts` (path+provenance+hash), `logs`, `result`, `score`. WAL SQLite — concurrent student runs safe.

### `db` — history-database maintenance (privacy controls)
`--report` (permissions/size/retention/table counts + world-readable warning), `--prune-days N`, `--delete-mac AA:..`, `--anonymize-db --yes` (irreversible), `--purge --yes`, `--vacuum`. Destructive actions require `--yes`.

### `lab` — captive-portal phishing awareness lab (training simulation)
Fully local, RFC 2606 synthetic roster (`traineeNN@lab.example`), instructor token-gated dashboard, funnel, Indicators/Compare/Learn debrief pages. Flags: `--bind`/`--port` (127.0.0.1:8808), `--db`, `--accounts`, `--ssid`, `--instructor-token`, `--duration`, `--reset --yes` / `--rotate-roster`, `--self-test` (12 checks offline), `-o DIR` export.

### `wpa-lab` — WPA/WPA2/WPA3 decryption laboratory
Six actions: `make-fixture` (instructor builds cryptographically real lab capture), `inventory`, `try` (MIC verify one candidate), `decrypt` (full bundle), `exercises`, `web` (student/instructor). Real crypto via `wcrypto` (FIPS-197/RFC 3610/4493/3394/NIST-GCM). Flags: `--ssid`, `--password`/`--psk`/`--pmk`/`--key-file`, `--cipher`, `--channel`, `--no-handshake`, `--limit`, `--bind/--port/--db/--instructor-token`.

### `mac-lab` — MAC randomization & deanonymization lab
Seven actions: `make-dataset`, `inventory`, `correlate`, `explain`, `score`, `exercises`, `web`. Evidence engine (+40 fingerprint · +25 Jaccard SSIDs · +15 hand-off · RSSI/cadence/addr-type, anti-evidence −70/−100 simultaneous), twin trap, hypothesis-labelled clusters, scored clustering. Flags: `--seed`, `--fresh`, `--min`, `--submit`, `--limit`, `--bind/--port/--db`.

### `track-lab` — long-term device tracking & privacy lab
Seven actions: `make-dataset`, `inventory`, `history`, `patterns`, `compare`, `score`, `exercises`, `web`. 14-day synthetic history, Student-A routine vs Decoy-A′ trap vs Visitor-B rotator, visit sessionization, heatmaps, dwell, movement edges, `compare --since 2d` retention lesson.

### `stealth-lab` — hidden monitoring & stealth detection lab
Seven actions: `make-scenario`, `telemetry`, `hunt`, `explain`, `compare`, `alerts`, `score`, `exercises`, `web`. 4-day host telemetry, implant beats (install→keepalives→night flip→ps-vs-ss concealment→respawn/rename→unlink), signal engine (concealment 60 > mimicry 40), IT monitor must-NOT-accuse.

### `response-lab` — automatic response lab
Five actions: `cast`, `rules`, `simulate`, `exercises`, `score`, `web`. Seeded IDS stream on designated test devices, rulebook R1–R6 (R6 disabled), modes dry-run/approval/auto/manual, simulated firewall, approval queue, rollback, detect→decide→respond→result audit, FP metrics (R6 + empty allowlist → blocks IT scanner).

### `scan-lab` — large-scale scanning & scope-control lab
Seven actions: `make-dataset`, `inventory`, `scan`, `compare`, `score`, `exercises`, `web`. Virtual estate `10.77.*`, simulated concurrent scans (live progress, rate limiting), scope sentinel refusing out-of-scope before probing with alerts, duplicate-IP conflicts.

### `cred-lab` — credential & session security lab
Nine actions: `make-fixture`, `dissect`, `exposures`, `tls`, `alerts`, `report`, `compare`, `exercises`, `score`, `web`. Twin legs: 6 plaintext surfaces (Basic/Form/FTP/Telnet/SNMPv1/Cookie) vs TLS (only SNI), synthetic identities (`LAB-STUDENT-*`).

### `priv-lab` — wireless privacy & MAC-randomization lab
Seven actions: `make-dataset`, `inventory`, `correlate`, `compare`, `exercises`, `score`, `web`. Synthetic `02:1a:b4` block, probe-fingerprint clustering, PNO-scrub impact, scope sentinel for lab AP.

### `rf-lab` — RF interference & Wi-Fi resilience lab
Eight actions: `baseline`, `inject`, `compare`, `investigate`, `resilience`, `exercises`, `score`, `web`. Deterministic metric engine (util/SNR/loss/latency/goodput) for 3 APs on ch 1/6/11, 4 interferer profiles + intensity caps, detector classification, rechannel exercise. No RF transmitted.

### `handshake-lab` — WPA handshake capture & password-auditing lab
Nine actions: `make-dataset`, `inventory`, `analyze`, `audit`, `compare`, `authenticate`, `exercises`, `score`, `web`. Real 4-way handshakes on lab SSID `LabHS3-Intro`, 3 wordlist tiers (easy/medium/expert-resistant), PBKDF2 timing, CAPTURED≠AUDITED≠AUTHENTICATED distinction.

### `interfaces` — capability report
platform, root?, backends, scapy?, OUI size, each wireless interface with mode/MAC/channel.

---

## 13. Output artefacts

All files UTF-8 **with BOM** (Excel), RFC-4180 quoting, header always, filenames `wifi-<scanid>_*` or your `--prefix`. Every row carries `scan_id` so repeated scans concatenate in pandas. 0600 files; `--anonymize` → salted per-export unlinkable pseudonyms, hostnames/IPs/probes dropped.

### `<prefix>_networks.csv` — 49 columns, one row per BSS

| Column | Meaning |
|---|---|
| `scan_id` | run id (UTC-stamped) |
| `bssid`/`ssid`/`hidden` | identity; `hidden=1` = no SSID in beacon |
| `vendor` | OUI vendor of BSSID |
| `band`/`channel`/`frequency_mhz`/`channel_width_mhz` | RF (20/40/80/160 from HT/VHT/HE) |
| `rssi_dbm`/`rssi_min_dbm`/`rssi_max_dbm`/`noise_dbm`/`snr_db` | signal over whole run |
| `signal_quality_pct`/`signal_bars`/`estimated_distance_m` | derived quality + path-loss distance (§15.3) |
| `encryption`/`ciphers`/`auth_suites`/`pmf` | RSN/WPA (`pmf`: required/optional/disabled) |
| `wps` | WPS IE advertised |
| `security_score`/`security_grade`/`risks` | 0–100 / A+…F / `;`-joined codes (§15.2) |
| `phy_modes`/`max_rate_mbps` | a/b/g/n/ac/ax/be + top basic rate |
| `beacon_interval_tu`/`dtim_period`/`country`/`mesh` | beacon internals |
| `beacons_seen`/`data_packets` | frames attributed (monitor only) |
| `connected_devices`/`active_devices`/`confirmed_devices`/`rf_only_devices`/`census_confidence`/`census_note`/`ap_confidence` | census with trust (§15.1) |
| `client_macs` | `|`-joined MACs |
| `bss_load_sta_count`/`channel_utilization_pct` | BSS Load IE (element 11) — AP's own claim |
| `eapol_frames`/`deauth_frames` | handshake joins and deauth activity |
| `first_seen`/`last_seen`/`source` | wall-clock bounds; sources merged e.g. `iw+monitor+lan` |

### `<prefix>_devices.csv` — 30 columns, one row per client

`scan_id`, `mac`, `vendor`, `is_randomized`, `associated_bssid`, `associated_ssid`, `ip_address`, `hostname`, `open_ports`, `rssi_dbm`(+min/max), `signal_quality_pct`, `estimated_distance_m`, `channel`, `packets`, `data_packets`, `bytes_seen`, `dwell_s`, `probed_ssids`, `state` (`associated`/`unassociated/probing`/`lan`), `first_seen`, `last_seen`, plus trust columns: `sources`, `evidence`, `binding_confidence`, `confidence` (label), `confirmed` (0/1), `identity_class`, `identity_note`.

### Also

| File | Contents |
|---|---|
| `*_channels.csv` | per band: channel, ap_count, overlapping_aps (2.4 GHz ±4), total_interferers, clients, strongest_rssi, SSIDs |
| `*_rogue_alerts.csv` | SSID, bssid_count, bssids, severity, reasons, indicators, score, verdict (§15.4) |
| `*_summary.csv` | scan-level metrics (`metric,value`) |
| `presence_sessions.csv` | `presence -o`: mac, bssid, ssid, first/last_seen, duration_s, sightings, avg/min/max_rssi |
| `trail-<MAC>.csv` | ts, time, mac, x, y, unc_m, error_radius_m, zone, zone_confidence, method, confidence, sensor_count, display |
| `traffic_events.csv` | time, ts, src/dst_mac, src, dst, proto, summary, detail, alert (redacted) |
| `traffic_flows.csv` | src, dst, proto, packets, bytes, first, last, notes |
| `ids_alerts.csv` | time, severity, kind, bssid, ssid, src, dst, confidence, confidence_label, status, evidence, detail |
| `audit_report.md` | checkbox per BSS: `[x]/[!]/[ ]` |
| `experiments.sqlite` | `experiment` engine DB: experiments + runs + analytics |
| `<prefix>.json` | everything nested: `{scan_id, generated_at, summary, connection, networks[], devices[], channel_congestion, rogue_alerts}` |
| `<prefix>.html` | standalone dark dashboard: summary cards, rogue banner, AP/device tables, channel bars, recommended channels |
| `<prefix>.md` | quick notes: summary bullets, rogue alerts, AP table |

---

## 14. SQLite history schema & queries

`Store` (WAL mode). Tables:

```sql
scans(scan_id PK, ts, duration, mode, sensor, networks, devices, meta)
  mode: scan|monitor|full|devices|offline|own|record|locate-live|pcap-import|experiment
networks(scan_id, ts, sensor, bssid, ssid, channel, band, rssi, security, grade, clients)
devices(scan_id, ts, sensor, mac, bssid, ssid, state, rssi, packets, data, bytes, ip, hostname, randomized, probed,
        sources, evidence, binding_confidence, confirmed)
observations(ts, sensor, mac, bssid, rssi, freq)   -- raw feeds for locate
fixes(ts, mac, x, y, unc, method, sensors, zone, confidence)
warden(bssid PK, ssid, meta, first_seen, last_seen, seen)
policy(key PK, value)                               -- salt, retention, privacy_mode
-- experiment engine (experiments.sqlite, also WAL)
experiments(id PK, title, objective, category, provenance, prerequisites, target_resources,
            parameters_schema, default_config, instructor_notes, max_duration_s, version, created_at)
runs(id PK, experiment_id, status, config, seed, started_at, finished_at, timeline, observations,
     artifacts, result, logs, reproducibility_hash, student_id, score)
analytics(run_id, metric, value, meta, ts)
```

Indexed: `devices(mac,ts)`, `devices(ssid,ts)`, `observations(mac,ts)`, `fixes(mac,ts)`, `runs(experiment_id,started_at)`.

```bash
sqlite3 home.sqlite "SELECT ssid, COUNT(DISTINCT mac) FROM devices
  WHERE ts > strftime('%s','now','-7 days') GROUP BY ssid;"
sqlite3 experiments.sqlite "SELECT experiment_id, status, COUNT(*) FROM runs GROUP BY experiment_id, status;"
```

Retention: `Store.prune(days)` + `experiment` engine's `retention_days` enforced on every open. `db --report` warns if world-readable.

**Session semantics** (`presence`): rows for (mac,bssid) within `--gap` seconds collapse into one session; a longer silence or AP change starts a new one. Probe requests never persisted.

---

## 15. Methodology

### 15.1 Source merge (engine)
Keyed by BSSID, richer-wins: first non-empty SSID wins (hidden→named promotes), channel/freq/country/DTIM fill if missing, RSSI keeps max (+running min/max), security union minus `OPEN` when real exists, PHY/ciphers/AKMs union, flags OR'd, counters summed, time bounds merged, clients merged by MAC, sources `iw+monitor+lan`.

### 15.2 Security score & grade (models.py — exact)
Base: OPEN 5 · WEP 15 · WPA-only 35 · WPA2 70 · WPA2+WPA3 transition 80 · WPA3-only 100. Modifiers: WPS −25 · TKIP −15 · PMF required +5 · PMF disabled/unknown −5. Clamp 0–100. Grade: ≥90 `A+` · ≥80 `A` · ≥70 `B` · ≥55 `C` · ≥35 `D` · else `F`. Risks: `open-network`, `wep`, `wpa1-legacy`, `tkip-cipher-deprecated`, `wps-enabled:pixie-dust`, `no-pmf:deauth-possible`, `hidden-ssid`, `very-close-transmitter`.

### 15.3 RSSI → quality → distance
`quality%` = Microsoft linear map (−100→0, −50→100). Bars: 4-block glyph. Distance inverts log-distance:

```
FSPL₁ₘ(f) = 20·log10(f_MHz) − 27.55
d = 10 ^ ((Tx − FSPL₁ₘ − (RSSI + sensor_offset)) / (10·n))
Tx default 20 dBm · n default 2.7 (2.0 free, 3.5 dense)
```

Clamped 0.1–2000 m (survey) / 0.2–500 m (locate). Order-of-magnitude; walls/antenna move it — that's why `locate` reports uncertainty.

### 15.4 Rogue / evil-twin scoring (multi-indicator)
Per SSID with ≥2 BSSIDs, each indicator scores evidence — `open-clone` 45, `security-mismatch` 25, `vendor-mismatch` 20, `warden-unknown` 20, `pmf-mismatch` 15, `signal-anomaly` 10, `channel-anomaly` 10 — fused with noisy-OR into `score` 0-100. `likely-rogue` requires **≥2 indicators AND score ≥ 40** (`high` for open clones, else `medium`); single-indicator → `unconfirmed` (`low`), never counted as rogue. Warden: beacon from unknown BSSID → `unknown-bss`; beacon (channel,security) changed mid-run → `beacon-mutation` (low until persists).

### 15.5 Audit checks (each = weakness → attack → fix)
`WPA3/PMF-required` · `PMF protects management frames` · `No WPS` · `No WEP/TKIP/RC4` · `WPA2 uses AES-CCMP` (+ ≥25-char passphrase caveat) · `Authentication present` · `No abnormal handshake churn` (≥20 EAPOL ⇒ run `ids`).

### 15.6 MAC classification
`is_randomized`: bit 1 of byte 0 (locally-administered). `is_multicast`: bit 0. Vendor = 24-bit OUI, built-in + `manuf`/`nmap` nsel when present.

### 15.7 Client counting rules
Data frame binding (To-DS/From-DS), assoc req naming BSSID, or EAPOL on that BSS with that MAC. Broadcast/multicast/NULL/QoS-no-data don't create clients. “Active” = ≥1 data packet. Duplicate MACs across APs are separate bindings. `census_confidence` = noisy-OR of per-client `binding_confidence` and data-packets evidence, minus 10 if no router confirmation.

### 15.8 Analytics scoring (analytics.py — exact)
IDS `score_ids`: alert is TP if within `[start−window, end+window]` of matching ground-truth interval (same `kind`+`bssid`); otherwise FP; unmatched ground truth → FN; latency = `alert_ts − start`. Then `precision=tp/(tp+fp)`, `recall=tp/(tp+fn)`, `f1=2pr/(p+r)`, `fpr=fp/(fp+tn)`, `p95` from sorted latencies. Correlation `score_correlation`: pair-level `tp/fp/fn` over all 2-combinations within each ground-truth cluster vs predicted clusters.

---

## 16. Sensor-grid positioning guide

**Model:** 3+ fixed receivers (`record --sensor`) at surveyed positions; each pass writes per-device RSSI rows with its tag; `locate` fuses readings from different sensors within `--window` seconds.

`sensors.csv` (metres, any consistent local grid, origin arbitrary):

```csv
name,x,y,floor,rssi_offset_db,tx_power_dbm
front-door,0,0,0,,4.0,-4        # antenna reads 4 dB strong → −4 cal
living-room,8,2,0
kitchen,8,12,0
```

`zones.csv` — polygon vertices, one zone per consecutive block (order = perimeter):

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
# each box: record --db /srv/presence-$HOSTNAME.sqlite --sensor $HOSTNAME
# merge DBs (same schema): sqlite3 ATTACH or point all at one shared file
python3 main.py locate --db merged.sqlite --sensors sensors.csv --zones zones.csv --recompute
python3 main.py trail --db merged.sqlite --sensors sensors.csv --zones zones.csv --mac AC:BC:32:01:02:03 --map -o out/
```

Methods: `trilateration` (WLS ≥3 sensors, uncertainty = 2×residual-RMS), `bilateration(ambiguous)` (2 sensors, better circle intersection), `nearest-sensor`, `nearest-sensor(guarded)` — sanity guard: uncertainty > grid diagonal or landing >0.6×diag outside sensor bbox ⇒ demoted, never fantasy. 1 sensor ⇒ zone hint only. **Indoor reality: room/zone-level, metres not centimetres** — that's why every fix carries `uncertainty_m` + `confidence` + `zone` as primary answer.

---

## 17. The IDS: signatures it detects

Base `Watchdog` (7) + `AdvancedWatchdog` (12) — 100% receive-only.

| # | Kind | Trigger (defaults) | Severity | What you're seeing |
|---|---|---|---|---|
| 1 | `deauth-flood` | ≥`--flood` (5) deauth/disassoc to one BSSID in `--window` (10s) | high/baselined or info | someone kicking clients — bait for auto-rejoin; PMF-required ignore forged |
| 2 | `forced-reauth` | Assoc from client ≤window after deauth targeting it | **critical** | kick *worked*; client renegotiating on command |
| 3 | `handshake-harvest-signature` | deauth→assoc→**EAPOL** in window | **critical** | provoking fresh 4-way handshakes for offline grind. Fix: WPA3/SAE+PMF required |
| 4 | `eapol-storm` | >flood count of EAPOL on one BSS | high | mass renegotiation; often paired with kicking |
| 5 | `beacon-mutation` | same BSSID (channel,security IE) changes mid-run | medium (45→78 when persists 3 beacons) | your reconfig or live impersonator |
| 6 | `unknown-bss` | beacon from BSSID not in warden baseline (`--learn`) | medium | new/novel AP (possibly your SSID) |
| 7 | *(scan)* `rogue/evil-twin` rows in `*_rogue_alerts.csv` | same-SSID multi-vendor/open-clone heuristics | medium/high | clone detection without monitor |
| 8 | `krack-reinstall` *(advanced)* | replayed EAPOL Msg3 with same replay counter | **critical** | KRACK key-reinstall signature |
| 9 | `downgrade-attack` *(advanced)* | RSN IE falls back from WPA3/PMF-required to WPA2/open | **critical** | WPA3→WPA2 downgrade attack |
| 10 | `pmf-bypass-attempt` *(advanced)* | deauth still kicks PMF-required BSS | **critical** | 802.11w not enforced both ends |
| 11 | `channel-switch-spoof` *(advanced)* | CSA (IE 37) + beacon mutation on declared channel | medium | CSA-injection redirect |
| 12 | `evil-twin-channel-anomaly` *(advanced)* | same SSID on far channels with signal anomaly | medium | clone on quiet channel |

Mechanics: per-`window` sliding counters per BSSID; per-(kind,BSSID) 30s cooldown so burst=one alert; `--follow` streams live; `-o` exports `ids_alerts.csv`. Adaptive margin: if ≥3 BSSIDs each show ≥2 deauths in-window, air is noisy → require +2 frames before calling any single AP a flood (single-AP attacks unaffected). Every alert carries `confidence` + `status` (unconfirmed/corroborated/confirmed) + `evidence` + “to confirm” hint.

```python
from wifiscanner.defense import AdvancedWatchdog
wd = AdvancedWatchdog(window_s=10, flood_frames=5, sensitivity="medium")
# ... feed scapy packets ...
print(wd.research_stats())
# {'frames': 1234, 'alerts': 3, 'timeline_events': 7, 'krack_candidates': 1, ...}
```

---

## 18. Operational recipes

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
User=root
[Install]
WantedBy=multi-user.target

# experiment engine as a long-lived service
[Service]
ExecStart=/opt/wifi_scener/.venv/bin/python -m wifiscanner.experiment
```

**Capture-then-analyse split (field box vs desk):**

```bash
sudo python3 main.py capture -i wlan0mon -d 3600 -o field.pcap --rotate-mb 64
python3 main.py offline field.pcap -o out/
python3 main.py ids --pcap field.pcap
python3 main.py traffic field.pcap -o out/
python3 main.py frames field.pcap --limit 20
python3 main.py experiment start --id wireless-ids-001 --config '{"pcap":"field.pcap"}' --db lab.sqlite
```

**Ring-buffer forensic snapshot** — last ~24 h always available, capped:

```bash
sudo python3 main.py capture -i wlan0 -d 864000 -o /var/pcap/loop.pcap --ring-segments 96 --rotate-mb 32  # ~3 GB max
```

**History diffing in pandas:**

```python
import pandas as pd, glob
dev = pd.concat(map(pd.read_csv, glob.glob("out/*_devices.csv")))
nets = pd.concat(map(pd.read_csv, glob.glob("out/*_networks.csv")))
dev.assign(h=pd.to_datetime(dev.last_seen).dt.hour).groupby(["associated_ssid","h"]).mac.nunique().unstack(fill_value=0)
# benchmark IDS across seeds:
from wifiscanner.analytics import score_ids
print(score_ids(ground_truth, alerts))
```

**Verify a new IDS sensor before trusting it (deploy check / CI):**

```bash
wifiscanner inject --mode ids-selftest -o checks/   # exit 0 = 4/4 signatures
wifiscanner inject --mode canary -i wlan0mon --channels 1,6,11 --no-monitor-setup --transmit --authorized
wifiscanner ids -i wlan0mon --follow   # grep token on remote sensor
sudo wifiscanner inject --mode pmf-test -i wlan0mon -c 6 --no-monitor-setup --bssid AA:.. --client <mac> --transmit --authorized --yes
# exit 0 = PMF works; 1 = kicked (set 802.11w REQUIRED); 3 = inconclusive
sudo wifiscanner inject --mode evil-twin -i wlan0mon -c 6 --no-monitor-setup --ssid YourOWN --security open --duration 30 --transmit --authorized --yes
# then: wifiscanner ids --db warden.sqlite -i wlan0mon  → unknown-bss
#       wifiscanner scan  → clone in *_rogue_alerts.csv
```

**Research comparison across intensities:**

```bash
for i in 60 70 80; do
  wifiscanner rf-lab inject --interferer microwave --intensity $i --ticks 30 > run-$i.json
done
python3 -c "from wifiscanner.analytics import compare_experiments; import json, glob; print(compare_experiments([json.load(open(f)) for f in glob.glob('run-*.json')]))"
```

---

## 19. Python API

```python
from wifiscanner import Engine, export_all
from wifiscanner.backends import survey, sniffer, lan
from wifiscanner.defense import Watchdog, AdvancedWatchdog, audit_engine
from wifiscanner.frames import annotate_pcap
from wifiscanner.experiment import ExperimentEngine, ExperimentDef
from wifiscanner.pipeline import get_pipeline
from wifiscanner.analytics import score_ids, compare_experiments

# Survey + monitor
eng = Engine()
eng.ingest(survey.survey_networks(rescan=True))
with sniffer.MonitorMode("wlan0") as mon:
    sn = sniffer.MonitorSniffer(mon, channels=[1,6,11])
    sn.run(30)
    eng.ingest(sn.results()); eng.ingest_unassociated(sn.unassociated)
eng.ingest_lan(lan.lan_inventory())
print(eng.summary()); print(eng.rogue_candidates())
export_all(eng, "output", formats=("csv","json","html"))

# IDS (7-signature) and advanced (12-signature)
wd = Watchdog(window_s=10, flood_frames=5, sensitivity="medium")
awd = AdvancedWatchdog(window_s=10, flood_frames=5)
# ... feed: wd.feed(pkt) ...
print(wd.results()); print(awd.research_stats())

# Unified experiment lifecycle
exp_eng = ExperimentEngine("lab.sqlite")
run = exp_eng.start("wireless-ids-001", config={"pcap": "tests/fixture.pcap"}, seed=42)
run.log_event("PACKET", {"frames": 288})
exp_eng.finish(run, result={"alerts": 3, "f1": 0.96})
exp_eng.record_metric(run.id, "f1", 0.96)
print(exp_eng.compare_runs([run.id, other.id]))

# Async pipeline
pipe = get_pipeline()
pipe.on("packet", lambda ev: print(ev.kind, ev.payload))
pipe.start(); pipe.emit_now("lab", "test", {"x": 1}); print(pipe.stats()); pipe.stop()

# Analytics
print(score_ids(ground_truth, alerts))
print(compare_experiments([{"id": "a", "config": {"i": 60}, "result": {"g": -12}, "metrics": {"f1": 0.96}}]))

# Locate
from wifiscanner.locate import load_sensors, load_zones, Tracker
tracker = Tracker(load_sensors("sensors.csv"), load_zones("zones.csv"), window_s=3.0)
fixes = tracker.fixes(observations)
```

`Store` exposes `record_engine / sessions / known_devices / get_observations / record_fixes / learn_warden / prune / delete_device / anonymize_history / storage_report`.

---

## 20. Testing

```bash
python3 tests/make_fixture.py         # builds tests/fixture.pcap (288 frames: beacons w/ real RSN/WPS/BSS-load,
                                      # assoc+data+LLC/SNAP-EAPOL per client, probe storms, 9-frame deauth burst, 5 BSS incl. evil twin)
python3 -m pytest tests/ -q            # all offline; no radio, no root
# or individually:
python3 tests/test_wifiscanner.py     # core: RF math, OUI, scoring, merge, pcap→attribution exact counts, IE/RSN, probes/deauth, CSV schema
python3 tests/test_injection.py       # injection gates/builders/selftest, LAA MAC, broadcast refusal, caps, dry-run 0600 audit
python3 tests/test_lab.py             # phishing lab: roster/store/HTTP/API/reset, 12-check self-test
python3 tests/test_wpalab.py          # WPA lab: crypto vectors (FIPS-197/RFC 3610/4493/3394), decrypt, web, vectors→decrypt→web
python3 tests/test_devlab.py          # mac-lab+track-lab: datasets, correlation engine, tracker, traps, scoring, both webs, CLI smoke
python3 tests/test_solabs.py          # stealth+response: telemetry scenario, signal engine, concealment beats, FP story, rollback, audit chain
python3 tests/test_biglabs.py         # scan+cred: estate + sentinel scope refusals + rate/concurrency + cred 6 surfaces + TLS opaque + web
python3 tests/test_privrf.py          # priv+rf: rotation clustering, scope refusal, scrub impact, what-if, 4 interferers, resilience
python3 tests/test_hsaudit.py         # handshake lab: real 4-way capture validation, 3 tiers, PBKDF2 timing, 3-state, web, regen/destroy
# => 260+ tests total, all offline; nothing transmits

# Advanced modules (no hardware):
python3 -c "from wifiscanner.experiment import ExperimentEngine, ExperimentDef; e=ExperimentEngine(':memory:'); print(e.register(ExperimentDef(id='t',title='T',objective='O')))"
python3 -c "from wifiscanner.pipeline import get_pipeline; p=get_pipeline(); p.emit_now('test','demo',{'x':1}); print(p.stats())"
python3 -c "from wifiscanner.analytics import score_ids; print(score_ids([{'kind':'deauth-flood','bssid':'AA:BB:CC:DD:EE:FF','start':0,'end':10}],[{'kind':'deauth-flood','bssid':'AA:BB:CC:DD:EE:FF','ts':5}]))"
python3 -c "from wifiscanner.defense import AdvancedWatchdog; print(AdvancedWatchdog().research_stats())"
python3 main.py experiment list --db :memory: -q  # catalogue smoke
```

Coverage: RF math round-trips; randomized/multicast MAC; OUI; score ordering + WPS/TKIP penalties; station accounting idempotence; source merge prefer-richer; dedupe; congestion & recommender; rogue/open-clone; summary counts; canned `iw`/`netsh` parser fixtures; **pcap→client attribution exact counts**; IE/RSN; probe & deauth; CSV schema stability + Excel quoting; store round-trip + session gap-splitting + time parsing; **trilateration ±1.2 m on synthetic grid**; bilateration; zone geometry + dwell; **IDS: flood threshold, deauth→reassoc→EAPOL chain fires critical, beacon mutation, warden unknown-BSS**; audit PASS/FAIL; frames annotator + handshake census; traffic DNS/HTTP/credential redaction/ARP/SNI/protected-skip; ring-buffer rotation; CLI smoke incl. `record` guardrail and `experiment` lifecycle; trust binding ranks, noisy-OR fusion, privacy salted pseudonyms, 0600 files, `AdvancedWatchdog` 12-signature stats, `pipeline` queue/back-pressure, `analytics` precision/recall/F1/ROC.

---

## 21. Platform support & limitations

|  | Linux | macOS | Windows |
|---|---|---|---|
| Survey (`scan`/`detail`/`watch`) | ✅ iw/nmcli/iwlist | ✅ airport/system_profiler | ✅ netsh (Admin for profiles) |
| Monitor capture (`monitor/capture/ids/traffic --live`) | ✅ with monitor-capable NIC | ⚠️ only if already in monitor | ❌ driver stack |
| `own` via `iw station dump` (this box = AP) | ✅ | ❌ | ❌ |
| LAN sweep / `--ports` | ✅ | ✅ | ✅ |
| nmap accel | ✅ if installed | ✅ | ✅ |
| `traffic/frames/ids --pcap/offline` on files | ✅ | ✅ | ✅ |
| `record` history + `presence` | ✅ | ✅ | ✅ |
| `locate`/`trail` from multi-sensor DBs | ✅ | ✅ | ✅ |
| `experiment` engine | ✅ | ✅ | ✅ |
| `pipeline` async bus | ✅ | ✅ | ✅ |

Fundamental limits, stated plainly: encrypted payloads never readable (and never attacked) outside lab captures with lab keys; RSSI distance is order-of-magnitude; single-sensor cannot trilaterate; 2.4 GHz overlap assumes 20 MHz; OUI table ships trimmed — extend with `/usr/share/nmap/nmap-mac-prefixes` or Wireshark `manuf`.

---

## 22. Troubleshooting FAQ

| Symptom | Cause → fix |
|---|---|
| `backends: none` in `interfaces` | install `iw` (Linux) or be on Wi-Fi-capable box; `netsh` needs Admin on Windows |
| `monitor mode requires root` | `sudo`, or `--no-monitor-setup` when already `wlanXmon` |
| Monitor setup fails `busy` | managed connection holds NIC — `nmcli device disconnect wlan0` first (auto-restored on exit) |
| Capture starts but 0 frames | NIC lacks monitor (`iw list` → modes), or nothing on channels hopped: `-c 1,6,11`, check `dmesg` |
| `scapy required` | `pip install scapy` inside the venv you're running from |
| Colours mangled | `NO_COLOR=1` forces plain renderer; fine for `>> log.txt` |
| `traffic` finds nothing | expected on encrypted nets — it only dissects cleartext by design; use `ids`/`offline` for structure |
| `record` refuses to start | no `--bssid` and not connected — point at **your** AP explicitly |
| presence 0 sessions | gap larger than scan interval? `--gap 600`; or `record --pcap day.pcap` first |
| locate: "no sensor observations" | history recorded without `--sensor` tags, or names don't match `sensors.csv` |
| Huge/nonsense x,y | now `nearest-sensor(guarded)` — check sensor coords & `--n-exp`, add calibration offsets |
| sqlite locked on NAS | WAL over NFS unreliable — record locally, merge periodically |
| `experiment` DB locked | each student use their own `--db` file, or use WAL default; `lsof` the DB file |
| pipeline `dropped` rising | queue full → raise `max_queue` or `workers`, or lower ingest rate |

---

## 23. Legal & ethics

Everything scoped to infrastructure you own or explicitly authorise. All survey/IDS/audit/history/lab-synthetic features are **receive-only** or operate on **synthetic/lab-only data** (synthetic MAC block `02:1a:b4`, synthetic SSIDs `LabNet-*`/`LabHS3-*`, synthetic estate `10.77.*`, synthetic identities `LAB-STUDENT-*`). Passive monitoring of public airspace is permitted in most jurisdictions but not all, and logging people's devices isn't the purpose (see §1 for what was declined).

`inject` follows the same rule a licensed radio engineer follows when testing a network they operate: transmit only on your own airspace, minimally, logged, with explicit consent. The deauth self-test briefly and reversibly disconnects **one device you name** if PMF is off — authorised, low-impact verification of a security setting (fire-alarm test). Never pointed at third parties: broadcast targets and above-flood-threshold are refused in code. You remain responsible for lawful, consented use in your jurisdiction.

If a design question is "could this harm a third party against their will?" — that feature is not getting merged.

---

## 24. Changelog

* **v5.0.0** — **Research-Grade Edition** — unified `experiment` engine (lifecycle, seed+hash reproducibility, WAL, timeline START→RESET, scoring, comparison), `pipeline` async telemetry bus (bounded queue, back-pressure, worker pool, WebSocket fan-out, `stats()`), `analytics` research metrics (per-kind precision/recall/F1/accuracy/FPR + latency P95, correlation pair-level scoring, throughput benchmarks, `compare_experiments` with delta/mean, ROC, CSV export), `AdvancedWatchdog` (12 signatures: base 7 + KRACK replay-counter, WPA3→WPA2 downgrade, PMF-bypass confirmation, CSA-spoof — with `research_stats()` and full timeline), version bump to 5.0.0, `setup.py` `research` extra, 27th CLI command `experiment`. Documentation rewritten to research-grade standard (§3/§8/§9/§10, expanded §11/§17/§20). **260+ tests**, all offline.
* **v4.1.0** — `handshake-lab`: WPA handshake capture & password-auditing lab. Real 4-way handshakes for lab SSID `LabHS3-Intro` on `02:1a:c3`, 3 wordlist tiers (easy/medium/expert-resistant), `analyze`/`audit`/`compare`/`authenticate`, PBKDF2 timing, CAPTURED≠AUDITED≠AUTHENTICATED, web :8829, instructor regen/destroy. 246 tests.
* **v4.0.0** — `priv-lab` (wireless privacy & MAC randomization, 0600 synthetic `02:1a:b4`, clustering, PNO-scrub 349→0, what-if, scope sentinel) + `rf-lab` (RF interference & resilience, deterministic engine for 3 APs ch 1/6/11, 4 interferers, intensity caps, detector, rechannel). 232 tests.
* **v3.0.0** — `scan-lab` (virtual estate `10.77.*`, simulated concurrent scans, sentinel scope refusals, duplicate-IP conflicts) + `cred-lab` (twin legs: 6 plaintext surfaces vs TLS, synthetic `LAB-STUDENT-*`, report bundle). 210 tests.
* **v2.9.0** — `stealth-lab` (4-day host telemetry, implant beats, signal engine, ps-vs-ss, IT monitor trap) + `response-lab` (IDS stream on designated test devices, rulebook R1–R6, 4 modes, simulated firewall, approvals, rollback, FP trap). 188 tests.
* **v2.8.0** — `mac-lab` (evidence engine, twin trap, hypothesis clusters, scored clustering) + `track-lab` (14-day history, visit sessionization, heatmaps, retention contrast, decoy trap, rotator). 166 tests.
* **v2.7.0** — `wpa-lab`: real capture pipeline, MIC verification, authorised CCMP/GCMP decrypt, GTK unwrap, web lab, stdlib crypto pinned to vectors (FIPS-197/RFC 3610/4493/3394/NIST-GCM). 143 tests.
* **v2.6.0** — `lab`: captive-portal phishing awareness lab, local, synthetic roster, funnel + debrief, 12-check self-test. 126 tests.
* **v2.5.0** — Evil-Twin detection drill (`inject --mode evil-twin`, beacon-only, hard-capped, audited). 117 tests.
* **v2.4.0** — Full deauth/disassoc test + IDS subtype fix (subtype 10 disassoc vs 11 auth). 110 tests.
* **v2.3.0** — Authorized injection for defensive self-test: `ids-selftest`, probe, canary, PMF test. 101 tests.
* **v2.2.0** — Trust & privacy hardening (10 fixes): source+confidence trust model, RF-vs-confirmed census, rotating-MAC honesty, privacy modes, zone-primary location, 0600 secure storage, redaction, IDS confidence, multi-indicator rogue. 76 tests.
* **v2.1.0** — `ids` (7-detector watchdog + warden), `audit`, `frames`; LLC/SNAP EAPOL; fixture with monitor-style EAPOL. 49 tests.
* **v2.0.0** — `own`, `record`, `presence`, `locate` (WLS), `trail`, `capture` (streaming pcap, ring), `traffic`; `--db` on survey; guardrails.
* **v1.0.0** — Passive survey (5 OS backends), monitor-mode attribution, RSN parsing, security grading, rogue detection, congestion, CSV×5/JSON/HTML/MD, rich/ASCII.

---

## 25. Trust & privacy model

v2.2.0 hardens ten weaknesses; v5.0 adds research-grade observability. Principle: **every result carries its source and its confidence, and every byte to disk is minimised, 0600-locked and retention-bounded.**

| # | Weakness | Fix (where) |
|---|---|---|
| 1 | Client counts stated as fact | `census`: `N✓ router-confirmed + M~ RF-observed` + confidence 0–100; per-binding evidence ranks (`assoc-table` 98 … `single-frame` 35); router table correlated, never double-counted (`models.py`, `engine.py`, `sniffer.py`) |
| 2 | Randomized MACs | `identity_report()`: observed-MAC ranges (min–max physical devices); `identity_note` disclaims both directions; never claims same/different device (`models.py`, `oui.py`) |
| 3 | Long-term tracking | `--privacy-mode standard/minimal/ephemeral`, `--anonymize` (salted HMAC pseudonyms), auto-enforced retention (90d), `experiment` engine per-run retention |
| 4 | Noisy location | Every fix: error radius + `confidence` + `zone_confidence`; **zone primary**; low-confidence coordinates withheld (`locate.py`) |
| 5 | Sensitive raw PCAP | `--ack-sensitive` (warns), `--strip-payloads` 128-B header-only, `--max-age-days`, 0600 files, `experiment` artifacts tagged provenance |
| 6 | Traffic-analysis exposure | Metadata-minimal + **redaction ON** (URL queries stripped, UA→product token, hostnames truncated, credential patterns scrubbed); `--anonymize-ips` to /24 (`traffic.py`, `privacy.py`) |
| 7 | IDS false positives | Per-alert `confidence`/`status`/`evidence` + “to confirm” hints, `--sensitivity`, beacon persistence (1=45, 3=78), adaptive noisy-air margin, cross-alert corroboration (`defense.py`) |
| 8 | Ambiguous rogue APs | Noisy-OR over 7 indicators; `likely-rogue` needs **≥2 and score≥40**; single-indicator → `unconfirmed`/`low` never counted (`engine.py`) |
| 9 | No trust model | `trust.py`: canonical sources, ranked evidence, noisy-OR fusion, high/medium/low/very-low — surfaced in terminal/CSV/JSON |
| 10 | Sensitive history DB | 0600 at creation + world-readable warnings, `policy` table (salt/retention), `db --report`/`--prune`/`--delete-mac`/`--anonymize-db`/`--purge`/`--vacuum` (`store.py`) |

Operational notes:

* Pair 0600 files with full-disk encryption for captures/DBs at rest; at-rest encryption stays OS-layer.
* Pseudonym salts live in each DB's `policy`/`experiments` table and never in exports; per-export salts make shared reports unlinkable.
* `ephemeral` mode raises instead of writing — for live triage on airspace you must not retain.
* `pipeline` back-pressure: `dropped` counter is your signal to raise `max_queue`/`workers` or lower ingest rate — drops are measured, never silent.
* `AdvancedWatchdog` (12 signatures) is the research extension; base `Watchdog` (7 signatures) remains the stable, tested baseline — both share wire-format `Alert`.

---

*Built for reproducibility. Shipped for observability. Designed for research.*
