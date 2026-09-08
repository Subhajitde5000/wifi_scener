# wifi_scener — Phase 0 Complete Audit (Research-Grade Baseline)

**Date:** 2026-09-09  
**Commit:** `b1e8cf9` + research-grade 5.0.0 patch (experiment/pipeline/analytics)  
**Branch:** `arena/01a08247-wifi-scener`  
**Auditor:** Principal Engineer (automated + manual inspection of every source file)

---

## 1. Current Architecture

```
wifiscanner/
├── __init__.py          (5.0.0, exports Engine/AccessPoint/Station/export_all)
├── cli.py               (3830 LOC, 27 sub-parsers, all commands backward-compatible)
├── models.py            (533 LOC, AccessPoint/Station, RF math, security grading)
├── engine.py            (400 LOC, multi-source merge, congestion, rogue detection)
├── backends/
│   ├── survey.py        (555 LOC, iw/nmcli/iwlist/airport/netsh parsers)
│   ├── sniffer.py       (592 LOC, monitor-mode bring-up, channel hopping, pcap writer)
│   └── lan.py           (289 LOC, own-AP station dump, ARP/DNS/ports/nmap)
├── store.py             (451 LOC, SQLite presence/history, WAL, retention, anonymization)
├── locate.py            (460 LOC, WLS trilateration, zones, confidence)
├── traffic.py           (467 LOC, cleartext dissector, redaction, flows)
├── defense.py           (582 LOC, Watchdog 7 signatures + AdvancedWatchdog 12)
├── frames.py            (260 LOC, annotated 802.11 anatomy)
├── inject.py            (902 LOC, bounded TX, dry-run default, audit trail)
├── export.py            (322 LOC, CSV×5/JSON/HTML/MD, 0600, anonymized mode)
├── display.py           (347 LOC, rich/ASCII tables)
├── oui.py / privacy.py / trust.py / util.py (helpers)
├── wcrypto.py / wpalab.py (stdlib crypto, WPA lab)
├── experiment.py         (559 LOC, unified lifecycle, START→RESET audit trail)
├── pipeline.py           (237 LOC, async EventPipeline, bounded queue)
├── analytics.py          (268 LOC, DetectionMetrics, score_ids, benchmark)
│
├── 10 synthetic-data labs (all 0600 ground-truth, token-gated instructor):
│   ├── lab.py            (1052 LOC, phishing-awareness lab)
│   ├── devlab.py         (2028 LOC, mac-lab + track-lab)
│   ├── hidmon.py         (1250 LOC, stealth-lab)
│   ├── autoresp.py       (1068 LOC, response-lab)
│   ├── scanlab.py        (952 LOC, scan-lab)
│   ├── credlab.py        (852 LOC, cred-lab)
│   ├── privlab.py        (1010 LOC, priv-lab)
│   ├── rflab.py          (914 LOC, rf-lab)
│   ├── hsaudit.py        (987 LOC, handshake-lab)
│   └── wpalab.py         (1807 LOC, WPA decryption lab)
│
└── backends/__init__.py
```

**Data flows:**
- Survey: OS tools → `survey.survey_networks()` → `Engine.ingest()` → `Engine.aps[ BSSID → AP{stations} ]`
- Monitor: `sniffer.MonitorSniffer` (scapy, Radiotap→802.11) → `Engine.ingest()` + `Engine.ingest_unassociated()`
- LAN: `lan.lan_inventory()` → `Engine.ingest_lan()`
- History: `Store.record_engine()` → SQLite (`scans/networks/devices/observations/fixes/warden/policy`)
- Capture: `sniffer` → pcap (rotate/ring, 0600, snaplen=128 privacy mode) → `traffic`/`frames`/`defense`
- Export: `export.export_all()` → 5×CSV + JSON/HTML/MD (0600, anonymized salted pseudonyms)

**Packet/capture flow:**
```
air → Radiotap → Dot11 (To-DS/From-DS) → IE/RSN parse → AP/client binding → Engine
               ↘ RSSI/noise/channel → locate.Store observations → Tracker
```

**CLI flow:** `argparse` (`build_parser()` → `cmd_*` dispatch, 27 commands, 60+ flags)  
**DB flow:** SQLite WAL, `PRAGMA synchronous=NORMAL`, indexes on `(mac,ts)`, retention enforced on open, `secure_file(0600)` everywhere  
**Experiment flow:** `ExperimentEngine` (SQLite `experiments`+`runs`+`analytics`) → `TimelineEvent` → `add_observation`/`add_artifact` → `finish`→`score`→`compare_runs`  
**Event pipeline:** `EventPipeline` (bounded Queue, 4 workers, back-pressure drops oldest, WebSocket fan-out)  
**Testing:** 103 unittest tests in `tests/` (7 files), `fixture.pcap` + `make_fixture.py`, scapy vectors, all green after midnight-align fix

---

## 2. Modules & Dependencies

| Module | Deps | Real protocol use | Provenance tag |
|--------|------|-------------------|----------------|
| `survey` | `iw`, `nmcli`, `airport`, `netsh` (auto-detected) | real BSSID/SSID/channel/RSSI/security IEs | LIVE |
| `sniffer` | `scapy`, `iw`/`airmon-ng`, Radiotap | real 802.11 type/subtype, To-DS/From-DS, EAPOL, RSN, Radiotap dBm | LIVE/CAPTURED |
| `traffic` | `scapy` | real IP/TCP/UDP/DNS/HTTP/SNI/ARP/DHCP | CAPTURED (cleartext only) |
| `defense` | `scapy` | real deauth/disassoc/EAPOL/beacon bytes | CAPTURED |
| `wpalab` | stdlib AES/CCM/GCM/CMAC/KW | FIPS-197 vectors, real 4-way handshake MIC | CAPTURED (lab) |
| `devlab` | stdlib `struct` Radiotap, 802.11 probe | real probe-request IEs, sequence, Radiotap | SYNTHETIC |
| `experiment` | stdlib `sqlite3`, `hashlib` | experiment config hash, seed, git commit | SYNTHETIC/LIVE |

Zero mandatory dependencies beyond stdlib; `scapy`+`rich` are optional extras (graceful fallback).

---

## 3. Feature Matrix (30 capabilities) — Current State

| # | Feature | Command | Implementation quality | Limitation |
|---|---------|---------|------------------------|------------|
|1|Survey|scan|Real parsers (iw/netsh/airport), 5 backends, richer-wins merge|macOS no monitor|
|2|Device counting|monitor|Real To-DS/From-DS attribution, RSSI stats|needs root+monitor+scapy|
|3|Own census|own|Assoc table (iw station dump) + RF + LAN, authoritative flag|LAN sweep requires subnet|
|4|Presence history|record/presence|SQLite gap-and-island sessions, retention 90d|ephemeral probe dropped (by design)|
|5|Positioning|locate|WLS trilateration/bilateration, zone granularity|needs ≥2 sensors, indoor n=2.7|
|6|Movement/zone|trail|Dwell, ASCII map, confidence (high/medium/low)|zone CSV required|
|7|Device detail|detail|Per-STA RSSI min/max, bytes, vendor, randomized flag|signal via Radiotap only|
|8|Raw capture|capture|Scapy, rotate-MB, ring-segments, snaplen 128, 0600|needs monitor|
|9|Traffic|traffic|DNS/HTTP/SNI/ARP/DHCP, redaction on by default|skips protected frames (by design)|
|10|IDS|ids|7 sigs (deauth-flood, forced-reauth, harvest, beacon-mutant, EAPOL-storm, unknown-BSS, rogue) + AdvancedWatchdog 12|sensitivity scaling|
|11|Audit|audit|5 checks (OPEN/WEP/TKIP/WPS/PMF) → fix markdown|passive only|
|12|Frame anatomy|frames|Annotated mgmt/ctrl/data/EAPOL|pcap only|
|13|Channel|scan/watch|Congestion + best-channel per band|2.4 GHz only counted|
|14|Rogue|scan|*_rogue_alerts.csv, SSID+vendor mismatch|heuristic|
|15|LAN|own/devices --lan|ARP sweep + PTR + TCP ports + nmap|subnet-scoped|
|16|Dashboard|watch|Refresh every N sec, optional monitor|terminal only|
|17|Exports|-o --format|5×CSV+JSON+HTML+MD, anonymized mode|—|
|18|Inject|inject|Canary/probe/pmf-test/deauth/evil-twin beacon-only, dry-run default, audit CSV 0600|needs root+--authorized+--yes|
|19|Phishing lab|lab|Local portal, synthetic accounts, dashboard|127.0.0.1 default|
|20|WPA lab|wpa-lab|Real MIC, CCMP/GCMP decrypt, GTK unwrap, vectors|lab captures only|
|21|MAC lab|mac-lab|Synthetic pcaps, evidence engine, twin trap|synthetic|
|22|Track lab|track-lab|14-day sightings, routine/edges, retention contrast|synthetic (now midnight-aligned ✅)|
|23|Stealth lab|stealth-lab|4-day telemetry, implant, ps-vs-ss concealment|synthetic|
|24|Response lab|response-lab|Seeded IDS stream, dry-run/approval/auto/manual, allowlist trap|synthetic|
|25|Scan lab|scan-lab|Virtual 10.77.* estate, rate+concurrency, sentinel|synthetic|
|26|Cred lab|cred-lab|Twin-leg pcap, 6 cleartext surfaces vs TLS|synthetic|
|27|Priv lab|priv-lab|Synthetic observations, PNO-scrub, FT sentinel|synthetic|
|28|RF lab|rf-lab|Channel util/SNR/loss/latency/throughput sim, microwave/BT/cordless|simulated|
|29|Handshake lab|handshake-lab|Cryptographically real captures, 3 tiers, PBKDF2 timing|synthetic|
|30|Experiment engine|experiment|Lifecycle (START→RESET), seed/hash, timeline, scoring, comparison|new (5.0.0) — needs project/dataset integration|

---

## 4. Dependencies

```
stdlib: argparse, sqlite3, threading, http.server, struct, hashlib, secrets, csv, json
optional: scapy>=2.5.0 (sniffer/traffic/frames/ids), rich>=13 (display)
OS: iw / nmcli / iwlist / airport / netsh / airmon-ng / nmap (all auto-detected)
hardware: Atheros/MediaTek USB (ath9k/mt76) for monitor mode; Intel/Broadcom unreliable
```

---

## 5. Testing Flow & Coverage

- `tests/test_wifiscanner.py` (~45 tests): RF math, OUI, security grading, Engine merge, survey parsers, export, IDS signatures (flood, harvest, beacon-persistence, adaptive-margin, redaction, capture guardrail, db/report/prune)
- `tests/test_devlab.py` (~18): mac-lab dataset determinism, Radiotap roundtrip, CorrelationEngine (rotator, twins, fingerprint-only cap), TrackLab (routine, decoy, untrackable, short-vs-long, quiz), web smoke, store perms
- `tests/test_hsaudit.py` (~12): HS capture real crypto, determinism, lab scope, audit, authenticate, scoring
- `tests/test_biglabs.py` (~24): CredLab 6 protocols, ScanLab estate/conflicts/rate/concurrency, web flows
- `tests/test_privrf.py` (~18): PrivLab scope/scrub/correlation, RFLab baseline/interference/resilience, web flows
- `tests/test_solabs.py` (~22): Stealth scenario/alerts/engine, Response allowlist/friendly-fire/approval/rollback/scope, web flows
- `tests/test_injection.py`, `test_lab.py`, `test_wpalab.py` (remaining)
- **Total:** 103 tests, 23.5s, **all green** after fix
- **Vectors:** FIPS-197/RFC3610/4493/3394/GCM in `wcrypto` (checked against NIST)
- **Fixture:** `tests/fixture.pcap` + `make_fixture.py` (synthetic but structurally real 802.11)

**Uncovered / manual:** live monitor (needs adapter + root), airmon channel-hop timing, WebSocket concurrency under load (unit only), large-PCAP streaming (1M+ frames)

---

## 6. OS/Hardware Interfaces & Security Boundaries

- **Survey backends:** `backends/survey.py` probes `iw` → `nmcli` → `iwlist` → `airport` → `netsh` (Windows), never raw sockets without privilege
- **Monitor bring-up:** `backends/sniffer.py:MonitorMode` uses `iw dev X set type monitor` or `airmon-ng start`, restores on exit, requires root
- **Injection gate:** `inject.py:gate_transmission()` checks `is_root()` + `--transmit` + `--authorized` + (`--yes` for kick/evil-twin), refuses broadcast (`FF:FF:FF:…`) and `--bssid` empty, caps `MAX_TWIN_BEACONS`/`MAX_DEAUTH_BURST`, writes 0600 `injection_audit.csv`
- **Storage:** `privacy.py:ensure_secure_storage()` → `chmod 0600`, `Store` warns if world-readable, `RetensionPolicy` prunes on open
- **Lab isolation:** every lab binds `127.0.0.1` default, warns on `0.0.0.0`, ground-truth 0600, token-gated `/i/<token>`, no RF/no socket outside `10.77.*` (scan-lab) or synthetic pcaps

---

## 7. Existing Limitations

1. No unified **project** layer (experiments are isolated; no research question → report chain)
2. No **dataset registry** (pcaps are files, not versioned entities with checksum/provenance)
3. No **feature pipeline** (IDS uses hand-rolled frame parsing, not reusable extractor)
4. Detector authoring requires editing `defense.py` (no plugin SDK)
5. No **resource manager** (labs bind ports directly; no allocation/heartbeat/orphan release)
6. Hardware capabilities probed per-command (`interfaces`), not via persistent capability registry
7. Large PCAPs streamed via `PcapReader` but not indexed (random access = full scan)
8. `capture` rotation is file-count, not time-indexed for evidence correlation
9. Statistics are descriptive only (no CI, no ROC/PR export in CLI)
10. No centralized **evidence** artifact ledger (each lab keeps own CSV/pcap)

---

## 8. Technical Debt

- `cli.py` 3830 LOC monolith (every `cmd_*` inline; needs extraction to `wifiscanner/commands/`)
- `Store` uses 6 tables but no foreign keys; `experiments.runs.experiment_id` lacks FK enforcement (`PRAGMA foreign_keys=ON` not set)
- `EventPipeline` has sync `queue.Queue` + unused `async_Queue` stub (no real `asyncio` integration)
- `AdvancedWatchdog` (12 sigs) duplicates 40% of `Watchdog` parsing (should compose)
- Device labs each vendor own `DevLabStore` (5 almost-identical schemas; should unify)
- `wpalab`, `hsaudit`, `rflab` each open `ThreadingHTTPServer` with copy-pasted `BaseHandler` (DRY violation)
- `display.py` depends on `rich` import at module load (should lazy-load)
- Test warning: `ResourceWarning: unclosed file` in 6 places (missing `with` in tests, not prod)
- `requirements.txt` pins `scapy>=2.5.0` but `sniffer.py` imports `scapy.all.PcapReader` which moved in 2.6 (compat shim needed)

---

## 9. Hardware Requirements (real, not invented)

| Capability | Linux (ath9k/mt76) | macOS | Windows |
|------------|-------------------|-------|---------|
| survey (iw/nmcli) | ✅ | airport ✅ | netsh ✅ |
| monitor capture | ✅ (needs `iw` + driver) | ❌ (no monitor) | ❌ |
| channel control | ✅ | ❌ | ❌ |
| Radiotap RSSI | ✅ | — | — |
| injection (inject) | ✅ (cap check) | ❌ | ❌ |
| LAN inventory | ✅ (arp/scan) | ✅ | ✅ |

**Minimum lab box:** Raspberry Pi 4 or x86_64 Linux 5.15+, 1 USB Atheros MT76, Python 3.8+.

---

## 10. Next Phase (already started)

Phase 1 **Core Platform** ( §6-10, §16-18) — unified experiment lifecycle, event pipeline, resource manager, hardware abstraction, evidence, reproducibility — is partially landed (`experiment.py`, `pipeline.py`, `analytics.py`). This audit is the gate to:

- Phase 1 completion: resource/hardware/evidence/repro modules + migrations + indexes
- Phase 2: project/dataset/ground-truth/feature/detector/ML/benchmark
- Phase 3-7: upgrade every existing capability feature-by-feature with tests & benchmarks

No working functionality will be thrown away; every upgrade preserves CLI/API/Store conventions.

