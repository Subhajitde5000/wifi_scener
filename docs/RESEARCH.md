# Wireless Cybersecurity Research & Experimentation Platform — 5.1.0

> **One workstation, every phase:** Research Question → Hypothesis → Experiment Design → Variables → Lab Environment → Execution → Measurements → Evidence → Analysis → Detector → Benchmark → Comparison → Reproduction → Dataset → Report

This document is the operating manual for the research platform added in **5.1.0** on top of the 5.0 toolkit. Every existing CLI command (`scan`, `monitor`, `ids`, `lab`, `wpa-lab`, `mac-lab`, `track-lab`, `stealth-lab`, `response-lab`, `scan-lab`, `cred-lab`, `priv-lab`, `rf-lab`, `handshake-lab`, `experiment`) still works unchanged.

## 1. Why a platform, not a toolkit

The pre-5.1 tools are excellent at single tasks (survey, locate, dissect a pcap, run one lab, boot an IDS). A research project needs them **together**, repeatedly, reproducibly, under a common provenance contract:

* every frame knows where it came from (LIVE / CAPTURED / REPLAYED / SIMULATED / SYNTHETIC — §3)
* every dataset is versioned + checksummed + linked to the run that made it
* every detection carries confidence + status (`unconfirmed` by default) and points back to the features that produced it
* every run emits a full timeline (`START → CONFIG → LAB_EVENT → PACKET/EVIDENCE → DETECTION → ANALYSIS → RESPONSE → RESULT → RESET`, §16) and a reproducibility manifest (`software_version + dataset + feature version + detector version + seed`, §34)
* resources (radios, sensors, replay backends) are allocated exclusively and reaped if orphaned (§17)
* student and instructor live in the **same** workstation, with the instructor console token-gated (§32–33)

Without this, comparisons are anecdote and re-runs diverge.

## 2. Architecture

```
wifiscanner/
  experiment.py        14-state lifecycle engine (DRAFT→ARCHIVED) + timeline bus
  pipeline.py          async EventPipeline (bounded queue → WebSocket fan-out)
  analytics.py         score_ids / benchmark_throughput / compare_experiments
  research/
    projects.py        Project + ProjectStore (question → hypothesis → literature)
    datasets.py        Dataset + DatasetStore (versioned, sha256, provenance)
    features.py        FeaturePipeline (RAW → parser → decoder → extraction)
    detectors.py       Detector SDK + Registry + builtin deauth/beacon
    benchmarks.py      BenchmarkSuite (accuracy / latency / throughput / csv)
    stats.py           describe / CI / outliers / pearson / compare_groups
    resources.py       LabResource + ResourceManager (heartbeat + reaper)
    evidence.py        EvidenceStore (append-only, hot/warm/cold, audit)
    hardware.py        CapabilityProbe (real iw / scapy / root checks)
    repro.py           reproducibility manifest (fingerprint, write/verify)
    report.py          bundle builder (report.md + report.json + metrics.csv + manifest.json)
    viz.py             sparkline / hist_ascii / confusion_matrix / svg_line|bars
    web.py             unified workstation (student + instructor, stdlib http.server)
```

* **Persistence** — every store is SQLite WAL + `PRAGMA foreign_keys=ON`, indexes on hot paths, `0600` via `privacy.ensure_secure_storage`. Schemas are created with `IF NOT EXISTS`; migrations are additive.
* **Hardware abstraction** — `CapabilityProbe.probe()` runs real checks (`iw list` for monitor, `scapy_available()`, `is_root()`, backend list, interface enumeration) and caches the result. `require(capability)` raises a precise `RuntimeError` if absent; callers degrade gracefully.
* **No mandatory deps** — `scapy` and `rich` are imported lazily; offline paths work without them. Genuine missing capabilities produce warnings, not crashes.
* **Security defaults** — `research.sqlite` and every exported CSV/JSON/PCAP is `0600`; evidence ledger is append-only with an audit table; replay/dataset provenance is never mixed without labeling.

## 3. Project lifecycle ( §7 )

```python
from wifiscanner.research.projects import ProjectStore
ps = ProjectStore("research.sqlite")
proj = ps.create(title="Deauth robustness", research_question="Does PMF defeat deauth?",
                 hypothesis="With PMF required, deauth flood → 0 disconnects", owner="alice")
ps.update_status(proj.id, "ACTIVE")
ps.add_note(proj.id, "Literature: 802.11w §10.3.4", author="alice")
ps.add_experiment(proj.id, "wireless-ids-001", "run-abc123")
```

CLI:

```
wifiscanner research project-create --title "Deauth robustness" --question "Q?" --owner alice
wifiscanner research project-list
wifiscanner research project-show --project-id proj-xxxx
```

Statuses: `DRAFT → ACTIVE → ARCHIVED` (explicit, auditable).

## 4. Dataset platform ( §9 )

Every dataset is `kind` (`live|captured|imported|replayed|synthetic|derived|labeled`) + `provenance` (`LIVE/CAPTURED/REPLAYED/SIMULATED/SYNTHETIC`) + `sha256` + `size_bytes` + `retention_days` + `artifact_path` + `schema_json`.

```python
from wifiscanner.research.datasets import DatasetStore
ds = DatasetStore("research.sqlite")
d = ds.register(title="1h capture", kind="captured", provenance="CAPTURED",
                source="capture.pcap", artifact_path="capture.pcap")
assert ds.verify(d.id)          # hash matches file on disk
ds.bump_version(d.id, "capture-v2.pcap")
```

CLI:

```
wifiscanner research dataset-register --title "1h capture" --artifact capture.pcap --provenance CAPTURED
wifiscanner research dataset-list
wifiscanner research dataset-verify --dataset-id ds-xxxx
```

Derived feature datasets are produced by `FeaturePipeline.to_dataset_store()` and appear as `kind=derived`.

## 5. Feature pipeline ( §11 )

```
RAW CAPTURE → FRAME PARSER (wpalab.Frame80211) → PROTOCOL DECODER (walk_ies)
            → NORMALIZATION → FEATURE EXTRACTION → FeatureDataset → DatasetStore / Detector
```

Features per frame: mgmt (beacon interval, SSID, channel, RSN cipher/akm, PMF, WPS, vendor), ctrl (RTS/CTS/ACK), data (ToDS/FromDS, retry, protected, size), radiotap (rssi/noise/snr/rate/channel), timing (inter-arrival, burst, beacon jitter), device (OUI, randomized, probe fingerprint), traffic (dns/http/sni/arp/dhcp hooks), window stats (by_type, rssi mean/stdev, inter-arrival p50/p95, duration, throughput).

```python
from wifiscanner.research.features import FeaturePipeline
fd = FeaturePipeline().extract_pcap("tests/fixture.pcap")
print(fd.window_stats)   # by_type, rssi, inter_arrival_ms, duration_s, throughput_fps
fd2 = FeaturePipeline().extract_pcap("tests/fixture.pcap")
# deterministic: same pcap → same sha256
```

CLI:

```
wifiscanner research feature-extract --pcap tests/fixture.pcap
```

## 6. Detector SDK ( §12 )

Subclass `Detector`, implement `detect(self, features: List[FrameFeatures]) -> List[Detection]`. Every detector has `id`, `version`, `default_config`, `fingerprint()`, `test_harness(features)` and `benchmark(feature_sets)`.

```python
from wifiscanner.research.detectors import Detector, DetectorRegistry, Detection
class MyDeauth(Detector):
    id = "my-deauth-001"; version = "1.0.0"; kind = "signature"
    def detect(self, features):
        return [Detection(ts=f.ts, kind="deauth-flood", bssid=f.bssid, confidence=70)
                for f in features if f.frame_type=="mgmt" and f.subtype in (10,12)]

reg = DetectorRegistry()
reg.register(MyDeauth())               # raises ValueError on duplicate id
det = reg.get("my-deauth-001")
dets, metrics = det.run(features)
print(det.test_harness(features))      # passed / metrics / detections
print(det.benchmark([features]))       # latency p50/p95, throughput
```

Built-ins: `builtin-deauth-flood` (sliding window, threshold 5) and `builtin-beacon-mutation` (RSN/WPS/channel flip). They have been validated against `tests/fixture.pcap` (288 frames): deauth flood fires once, beacon mutation fires zero — neither is a false positive.

CLI:

```
wifiscanner research detector-list
wifiscanner research detector-test --detector builtin-deauth-flood --pcap tests/fixture.pcap
```

## 7. Benchmark & statistics ( §14-15 )

`BenchmarkSuite` runs every registered detector on the **same** `FeatureDataset` (and same ground truth, if supplied) and ranks by F1 then latency. `stats` provides `describe`, `confidence_interval` (normal-approx, labeled derived), `outliers_iqr`, `pearson`, `compare_groups`.

```python
from wifiscanner.research.benchmarks import BenchmarkSuite
from wifiscanner.research.detectors import DetectorRegistry, BUILTIN_DETECTORS
from wifiscanner.research.features import FeaturePipeline
fd = FeaturePipeline().extract_pcap("tests/fixture.pcap")
reg = DetectorRegistry()
for d in BUILTIN_DETECTORS: reg.register(d)
suite = BenchmarkSuite()
for det in reg.list(): suite.run_detector(det, fd, dataset_id="fixture", dataset_version=fd.version)
print(suite.compare())     # runs + ranking + summary
suite.report("benchmark_report.json")  # also writes benchmark_report.csv
```

CLI:

```
wifiscanner research benchmark --pcap tests/fixture.pcap
wifiscanner research stats-demo
```

Every benchmark row records `latency_ms.wall_ms`, `throughput`, `accuracy.overall.{precision,recall,f1}` (if ground truth supplied) and `detector_version + dataset_version + seed`.

## 8. Lab resource manager ( §17 )

```python
from wifiscanner.research.resources import ResourceManager
rm = ResourceManager("research.sqlite")
r = rm.register(kind="adapter", name="wlan0", capabilities=["monitor_mode","packet_capture"])
tok = rm.allocate(r.id, "exp-1", "run-1", lease_s=300)  # exclusive
rm.heartbeat(tok)
rm.release(tok)
rm.reap_orphans()  # frees allocations whose heartbeat or lease expired
```

CLI:

```
wifiscanner research resource-register --kind adapter --title wlan0
wifiscanner research resource-list
wifiscanner research resource-allocate --dataset-id res-xxxx --project-id run-1
wifiscanner research resource-release --dataset-id alloc-xxxx
```

## 9. Evidence ledger ( §28, §34 )

```python
from wifiscanner.research.evidence import EvidenceStore
es = EvidenceStore("research.sqlite")
ev = es.add(kind="pcap", title="capture", path="capture.pcap", provenance="CAPTURED",
            experiment_id="wireless-ids-001", run_id="run-abc")
assert es.verify(ev.id)
es.set_retention(ev.id, "warm")
new = es.supersede(ev.id, "capture-corrected.pcap")  # old.retention → superseded, new row created
print(es.audit_trail(ev.id))
```

CLI:

```
wifiscanner research evidence-list
wifiscanner research evidence-list --project-id proj-xxxx
```

## 10. Hardware abstraction ( §18 )

```python
from wifiscanner.research.hardware import CapabilityProbe
cp = CapabilityProbe()
hc = cp.probe()                 # real: iw list, scapy, root, interfaces
print(hc.caps)                  # packet_capture / radiotap / monitor_mode / ...
print(cp.report())              # platform + root + backends + interfaces + details
cp.require("packet_capture")    # raises RuntimeError with actionable detail if absent
```

CLI:

```
wifiscanner research hardware
```

## 11. Reproducibility & reporting ( §34, §33, §35 )

```python
from wifiscanner.research.repro import build_manifest, write_manifest
from wifiscanner.research.report import write_report
from wifiscanner.research.viz import sparkline, confusion_matrix_ascii, svg_line

manifest = build_manifest(experiment_id="wireless-ids-001", run_id="run-abc", seed=42,
                          dataset={"id": "ds-1", "sha256": "abcd"},
                          detector={"id": "my-deauth-001", "version": "1.0.0"},
                          config={"threshold": 5})
write_manifest("output/manifest.json", manifest)

files = write_report("output", title="Deauth robustness", question="Q?", hypothesis="H",
                     experiment={"id": "wireless-ids-001"}, dataset={"id":"ds-1"},
                     metrics=[{"metric":"f1","value":0.9}], manifest=manifest,
                     stats={"count": 288})
print(sparkline([1,2,3,2,1]))
```

CLI report via the web workstation (below) or by calling `report.write_report` programmatically.

## 12. Unified workstation ( §32-33 )

One URL, every research object:

```
wifiscanner research web --bind 127.0.0.1 --port 8830 --db research.sqlite
# → http://127.0.0.1:8830/                student workspace
# → http://127.0.0.1:8830/instructor?token=…  instructor console (keep private)
```

Pages: `/` (counts + hardware), `/projects`, `/experiments` (catalogue + 20 recent runs), `/datasets`, `/detectors`, `/resources`, `/evidence`, `/hardware`, `/instructor` (allocations, project/dataset/evidence totals, reap control, hardware summary). JSON APIs under `/api/*` for notebooks.

Every graph is backed by real backend values; nothing is invented for presentation. The `viz` module supplies ASCII + SVG helpers for RSSI histories, confusion matrices and ROC-style comparisons without external JS.

## 13. Failure recovery & operational contract

* **DB corruption / disk full** — each store opens WAL and commits per-transaction; callers catch `sqlite3.OperationalError` and surface a precise message. Manifest writes are atomic (tmp → rename) where possible.
* **Stale allocations** — `ResourceManager` reap runs every 30 s in the web server and via `wifiscanner research resource-list` (any read can opportunistically reap). Leases are explicit (`lease_s`) and heartbeats are mandatory.
* **IDS / detector bugs** — `Detector.run` wraps `detect` and always returns `metrics` (even on 0 detections). `Watchdog`/`AdvancedWatchdog` (12 signatures) remain the production live IDS; research detectors never replace them without `benchmark` proving equivalence.
* **Hardware absent** — `CapabilityProbe` reports `details` with actionable next steps (`missing: scapy, monitor, root`). `require()` raises with that detail; callers show the warning and degrade to offline (`--pcap`) mode.
* **Lab isolation** — the web workstation binds to `127.0.0.1` by default. `0.0.0.0` emits a `log.warning` and the docs note “classroom LANs only”.

## 14. Performance notes

* `FeaturePipeline.extract_pcap` is streaming (8 KiB chunks for hash, per-frame parse, no full-pcap copy). It caps at `max_frames=500_000`; larger pcaps are sampled and logged.
* `Detector.benchmark` and `BenchmarkSuite` reuse the same feature lists; no re-parse per repeat.
* `stats.describe` is O(n); `compare_groups` is pairwise means; no p-values are invented (CI is labeled derived).
* The research DB (`research.sqlite`) is shared; each store creates its own tables with `IF NOT EXISTS`. For production scale, split per-concern DBs.

## 15. Upgrade cadence for the 24 legacy features

Every feature upgraded feature-by-feature, with its own tests, benchmark and docs delta:

1. `audit` → labresource-tagged, evidence emitting
2. `capture` → already ring/rotation + 0600 + strip-payloads (§38)
3. `cred-lab` → evidence + dataset + reproducibility (§24)
4. `defense/ids` → research mode (signatures testable as `Detector`, benchmarked)
5. `display` → viz helpers (§35)
6. `engine` → timeline bus wired into `ExperimentEngine`
7. `export` → anon + retention + evidence lineage
8. `frames` → feature extraction path (§11)
9. `handshake-lab` → dataset + detector + report
10. `hidmon/stealth-lab` → resource allocation + evidence
11. `inject` → authorization gates + audit log + evidence
12. `lab` → project linkage + evidence
13. `locate` → feature stream + dataset
14. `mac-lab` → correlation as `Detector`
15. `devlab/track-lab` midnight-aligned (fixed)
16. `oui` → feature enrichment (OUI lookup per-frame)
17. `privacy` → anonymize paths in datasets/evidence
18. `response-lab` → approval pipeline as resource
19. `scan-lab` → estate as resource pool
20. `sniffer` → live feature extraction path
21. `store` → dataset + evidence bridging
22. `traffic` → redaction + feature hooks
23. `wpalab` → parser reused by feature pipeline
24. `rflab` → interference as detector input

Each upgrade carries unit + integration + regression tests, error handling, docs, config and an operational smoke via `research hardware` / `research detector-test`.

## 16. Quick-start (copy-paste)

```bash
# 1. hardware check
wifiscanner research hardware

# 2. create project
wifiscanner research project-create --title "Deauth robustness" --question "Does PMF defeat deauth?" --owner alice

# 3. capture or use fixture.pcap
wifiscanner research feature-extract --pcap tests/fixture.pcap

# 4. list + test detectors
wifiscanner research detector-list
wifiscanner research detector-test --detector builtin-deauth-flood --pcap tests/fixture.pcap

# 5. benchmark all detectors identically
wifiscanner research benchmark --pcap tests/fixture.pcap

# 6. open the unified workstation
wifiscanner research web --port 8830
# then browse http://127.0.0.1:8830/  and  http://127.0.0.1:8830/instructor?token=...
```

## 17. Further reading

* `wifiscanner/experiment.py` — the 14-state machine, reproducibility hash, comparison helpers
* `wifiscanner/pipeline.py` — the async bus (bounded queue → websocket)
* `wifiscanner/analytics.py` — scoring, throughput, comparison
* `docs/AUDIT.md` — Phase 0 audit (architecture, 30-capability matrix, debt)
* `docs/PHASE1.md` — Phase 1 scaffolding report (this release)
* `.github/workflows/ci.yml` — CI on 3.9/3.11/3.12
