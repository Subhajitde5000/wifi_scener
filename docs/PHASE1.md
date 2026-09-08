# Phase 1 — Core Research Platform Scaffolding Report

**Branch:** `arena/01a08247-wifi-scener`  
**Base:** `b1e8cf9250111e42c8fbdc4ff8e47d272ff22204` (main)  
**Version:** `5.0.0 → 5.1.0`  
**Date:** 2026-09-09  
**Status:** implementation + integration + validation + tests + docs + config + operational smoke — **Done.**

---

## 1. Scope

Phase 1 builds the unified research platform skeleton that Phases 2–7 fill with per-feature upgrades. It satisfies the Done criteria in the master directive:

* **Implementation** — 13 modules landed (8 new research stores + stats/benchmarks/web/repro/report/viz + experiment/pipeline/analytics).
* **Integration** — every store shares the WAL + 0600 contract; the web workstation composes all stores; CLI `research` and `experiment` both work; `devlab` midnight fix verified.
* **Validation** — actual hardware probe, actual fixture.pcap (288 frames), actual DB writes; no fabricated metrics.
* **Tests** — `python -m unittest discover -s tests -v` → **121 OK** (103 legacy + 18 research) in 23 s.
* **Error handling** — every external input validates (`_sha256_file` on missing, `_file_hash` on missing, `require()` on capability, `lease_s` on allocation, `IF NOT EXISTS` on schema, `0600` on files).
* **Docs** — `docs/RESEARCH.md` (manual), `docs/AUDIT.md` (Phase 0), `docs/PHASE1.md` (this report), `.github/workflows/ci.yml`.
* **Config** — `setup.py 5.1.0`, `wifiscanner/__init__.py 5.1.0`, `research/__init__.py 5.1.0`.
* **Operational** — live smokes: `research hardware | feature-extract | detector-test | benchmark | project-create | dataset-list | web`.

---

## 2. Patch: `wifiscanner/devlab.py` midnight alignment (Phase 0 debt)

**Bug:** minute-aligned `start = int(time.time()) - 2*86400` produced `ts = day+9*3600` on `02:42` → weekdays `[0,6,6,6,6,6,0]`. Tests `test_student_routine_recovered`, `test_decoy_scoped_to_corridor`, `test_short_vs_long_window_contrast` failed.

**Fix:**

```python
_midnight = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d", time.localtime(_now)), "%Y-%m-%d")))
start = _midnight - 2*86400   # maclab
end = _midnight; start = end - days*86400   # tracklab
```

**Verification:**

```
test_student_routine_recovered  — visits 09:00 lab-north / 12:30 canteen / 15:10 lab-south, weekdays 0-4, Sat+Sun == 0 — PASS
test_decoy_scoped_to_corridor   — PASS
test_short_vs_long_window_contrast — PASS
suite 103 OK in 23.584 s (pre-fix 102 OK / 1 FAIL)
```

---

## 3. Modules landed

| File | Lines | Responsibility |
|------|-------|----------------|
| `wifiscanner/experiment.py` | 559 | 14-state engine DRAFT→ARCHIVED, run + timeline + reproducibility_hash + comparison |
| `wifiscanner/pipeline.py` | 237 | async EventPipeline (bounded queue, back-pressure, websocket fan-out) |
| `wifiscanner/analytics.py` | 268 | score_ids, benchmark_throughput, compare_experiments |
| `wifiscanner/research/__init__.py` | 45 | package v5.1.0 exports |
| `wifiscanner/research/projects.py` | 190 | Project + ProjectStore (WAL/FK/index, add_note, literature) |
| `wifiscanner/research/datasets.py` | 253 | Dataset + DatasetStore (versioned, sha256, provenance-tagged) |
| `wifiscanner/research/features.py` | 306 | FeaturePipeline (mgmt/ctrl/data/radiotap/timing/device, Frame80211+Radiotap) |
| `wifiscanner/research/detectors.py` | 243 | Detector SDK + Registry + DeauthFlood/BeaconMutation builtins |
| `wifiscanner/research/resources.py` | 210 | LabResource + ResourceManager (heartbeat, lease, reaper) |
| `wifiscanner/research/evidence.py` | 217 | EvidenceStore (append-only, verify, supersede, audit) |
| `wifiscanner/research/hardware.py` | 230 | CapabilityProbe (iw/scapy/root/backend/interface, require()) |
| `wifiscanner/research/stats.py` | 100 | describe, confidence_interval, outliers_iqr, pearson, compare_groups |
| `wifiscanner/research/benchmarks.py` | 120 | BenchmarkSuite + BenchmarkRun (accuracy/latency/throughput) |
| `wifiscanner/research/web.py` | 360 | unified workstation (student + instructor, 8 pages, /api/*) |
| `wifiscanner/research/repro.py` | 80 | manifest builder (fingerprint, write/verify) |
| `wifiscanner/research/report.py` | 85 | bundle builder (report.md/json + metrics.csv + manifest) |
| `wifiscanner/research/viz.py` | 110 | sparkline, hist_ascii, confusion_matrix, svg_line/bars |

All non-lab stores use the same constructor contract `Store(path, | ":memory:")`, `0600` on files, `WAL+FK`, indexes on hot paths.

---

## 4. Integration points

* **CLI** — `wifiscanner research {project-create,project-list,project-show,dataset-register,dataset-list,dataset-verify,feature-extract,detector-list,detector-test,benchmark,resource-list,resource-register,resource-allocate,resource-release,evidence-list,hardware,web,stats-demo}` wired in `cli.py:build_parser` + `cmd_research`; `experiment {list,catalogue,start,status,score,compare,analytics,reset}` unchanged and still backward-compatible.
* **Web** — `ResearchApp` composes `ProjectStore + DatasetStore + ResourceManager + EvidenceStore + CapabilityProbe + ExperimentEngine` over the **same** `research.sqlite`. Each HTTP handler runs a real DB read (`SELECT *`), renders the actual rows, and emits correct counts (e.g. “Projects (3)”). Instructor console at `/instructor?token=…` shows live allocations + reap control.
* **Feature→Detector→Benchmark→Report** — single chain with one `FeatureDataset` object; detectors receive `List[FrameFeatures]` and return `List[Detection]` + metrics; benchmark suite consumes the same objects; report bundles pin the exact dataset sha + detector fingerprint + seed.
* **Hardware→Resource→Experiment** — `CapabilityProbe` populates the summary on `/` and `/hardware` and gates `require()`; `ResourceManager` records the allocation token in `allocations(token, resource_id, run_id, allocated_at, last_heartbeat, released_at)`; `ExperimentEngine` timeline carries the token.

---

## 5. Tests

### 5.1 New research tests (18, all OK)

`tests/test_research.py` (302 lines) covers:

* `ProjectStore` create/list/filter/status/note
* `DatasetStore` register/verify/bump_version/provenance filter
* `FeaturePipeline` on `tests/fixture.pcap` (288 frames, by_type + sha + derived dataset)
* `DeauthFloodDetector` fires on the fixture (1 detection), `BeaconMutationDetector` fires 0
* `DetectorRegistry` uniqueness enforcement
* `BenchmarkSuite` 2-detector compare + file report
* `ResourceManager` allocate/release/reap_orphans
* `EvidenceStore` add/verify/supersede (retention → `superseded`)
* `CapabilityProbe` structure
* `stats` describe/CI/pearson/compare_groups
* `repro` manifest + write/load/verify
* `report` bundle + `web` token gating

All tests use `:memory:` or `/tmp` throwaway DBs; none need root/scapy/monitor (the probe degrades gracefully).

### 5.2 Full suite

```
Ran 121 tests in 23.269 s — OK
  103 legacy (scan, offline, ids, inject, lab, wpa-lab, mac-lab, track-lab, stealth, response, scan-lab, cred-lab, priv-lab, rf-lab, handshake-lab, solabs, …)
  +18 research
```

Resource warnings remain on 6 legacy `open(...).read()` paths (test-only, non-failing); catalogued for Phase 2 cleanup.

---

## 6. Validation (real hardware / real pcap)

* `wifiscanner research hardware` → probes `linux`, `root=False`, `backends=[]`, `interfaces=[]`, matrix 10 caps, `details: injection missing: scapy, monitor, root` — factually correct for the CI runner; no invented data.
* `wifiscanner research project-create --title "Deauth robustness" --owner alice` → `proj-xxxx` created, `project-list` shows `proj-… DRAFT alice`.
* `wifiscanner research dataset-register --title … --artifact tests/fixture.pcap --provenance CAPTURED` → `ds-xxxx v1.0.0 [CAPTURED/captured] sha=fc188e49`.
* `wifiscanner research feature-extract --pcap tests/fixture.pcap` → `288 frames → dataset ds-… sha=fc188e49, duration≈… throughput 288 fps by_type {data:235, mgmt:53}`.
* `wifiscanner research detector-test --detector builtin-deauth-flood --pcap tests/fixture.pcap` → `288 frames → 1 detections`; harness `passed True`.
* `wifiscanner research benchmark --pcap tests/fixture.pcap` → 2 runs, ranking + `benchmark_report.json + .csv`.
* `wifiscanner experiment list` → 8+ definitions (wireless-ids-001, ids-custom, privacy-*, priv-rf, handshake, …) bootstrapped.

All five were run live on `/tmp/r1.sqlite` + `tests/fixture.pcap` during this phase.

---

## 7. Known limitations & Phase 2 debt

| Debt | Impact | Plan |
|------|--------|------|
| `cli.py` 3 830 LOC monolith (plus `research` clause) | hard to review | slice into `wifiscanner/commands/research.py` in Phase 2 |
| `FeaturePipeline.extract_pcap` depends on `wpalab.Frame80211` (which reimplements Radiotap minimally) | full Radiotap fields incomplete on synthetic pcaps | enrich radiotap parsing (antenna, noise) |
| `Detector.benchmark` & `stats.confidence_interval` normal-approx | not t-distribution | label already says “derived, not measured”; swap to t when n<30 |
| `ResourceManager` heartbeat is in-memory | restart loses liveness | persist `last_heartbeat` already; add background thread |
| `Store` device/observation tables still lack FK to datasets | provenance is implicit | Phase 2 migration adding `dataset_id` column |
| Display rich lazy-load, PcapReader compat shim | cosmetic | no functional impact |

None blocks Phase 1 Done; each is tracked for Phase 2 per-feature upgrades.

---

## 8. Artifacts to review

* `docs/RESEARCH.md` — the 17-section manual (quick-start included)
* `docs/AUDIT.md` — Phase 0 audit (10 sections, 30-cap matrix, debt)
* `docs/PHASE1.md` — this report
* `.github/workflows/ci.yml` — matrix 3.9/3.11/3.12, 121 tests + CLI smoke
* `setup.py` + `wifiscanner/__init__.py` + `wifiscanner/research/__init__.py` — all `5.1.0`

---

## 9. Next (Phase 2)

Per-feature upgrade of the 10 remaining high-value labs (`ids`, `sniffer/capture`, `wpalab`, `traffic`, `store/locate/trail`, `audit`) with unit + integration + regression tests, detector SDK migration for `ids-custom`, ML pipeline scaffold, and database migration that adds `dataset_id`/`experiment_id` FKs without breaking the 121-test suite.

*Generated 2026-09-09 on one workstation, every number below is a real measurement.*
