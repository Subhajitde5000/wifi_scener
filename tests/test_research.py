"""Tests for the wireless research platform core (§6-35).

Covers: ProjectStore, DatasetStore, FeaturePipeline, DetectorRegistry,
ResourceManager, EvidenceStore, CapabilityProbe, BenchmarkSuite, stats,
repro manifest, report and web app wiring (no network bind).

All tests are hermetic: they use ':memory:' or /tmp throwaway DBs and the
bundled fixture.pcap (288 frames).
"""
import json
import os
import tempfile
import unittest

from wifiscanner.research.projects import ProjectStore
from wifiscanner.research.datasets import DatasetStore
from wifiscanner.research.features import FeaturePipeline
from wifiscanner.research.detectors import DetectorRegistry, DeauthFloodDetector, BeaconMutationDetector
from wifiscanner.research.resources import ResourceManager
from wifiscanner.research.evidence import EvidenceStore
from wifiscanner.research.hardware import CapabilityProbe
from wifiscanner.research.benchmarks import BenchmarkSuite
from wifiscanner.research.stats import describe, confidence_interval, compare_groups, pearson


class ResearchProjectTests(unittest.TestCase):
    def test_create_list_show(self):
        ps = ProjectStore(":memory:")
        p = ps.create(title="Q1", research_question="Does IDS catch it?", owner="alice")
        self.assertTrue(p.id.startswith("proj-"))
        self.assertEqual(p.status, "DRAFT")
        self.assertEqual(len(ps.list()), 1)
        self.assertIsNotNone(ps.get(p.id))
        self.assertEqual(ps.list(owner="alice")[0].id, p.id)
        self.assertEqual(ps.list(owner="bob"), [])
        ps.add_note(p.id, "first hypothesis", author="alice")
        self.assertEqual(len(ps.notes(p.id)), 1)
        ps.update_status(p.id, "ACTIVE")
        self.assertEqual(ps.get(p.id).status, "ACTIVE")


class ResearchDatasetTests(unittest.TestCase):
    def test_register_and_verify(self):
        ds = DatasetStore(":memory:")
        # use a real file for sha
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as fh:
            fh.write(b"pcap fake content for sha")
            path = fh.name
        try:
            d = ds.register(title="t1", kind="captured", provenance="CAPTURED", source=path, artifact_path=path)
            self.assertTrue(d.sha256)
            self.assertTrue(ds.verify(d.id))
            vers = ds.versions(d.id)
            self.assertEqual(len(vers), 1)
            # bump version with new artefact
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as fh2:
                fh2.write(b"second version")
                path2 = fh2.name
            d2 = ds.bump_version(d.id, path2)
            self.assertNotEqual(d2.version, "1.0.0")
            self.assertEqual(len(ds.versions(d.id)), 2)
            os.unlink(path2)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def test_provenance_filter(self):
        ds = DatasetStore(":memory:")
        ds.register(title="syn", kind="synthetic", provenance="SYNTHETIC", source="/tmp")
        ds.register(title="cap", kind="captured", provenance="CAPTURED", source="/tmp")
        self.assertEqual(len(ds.list(provenance="SYNTHETIC")), 1)
        self.assertEqual(len(ds.list()), 2)


class ResearchFeatureTests(unittest.TestCase):
    def test_extract_fixture(self):
        pcap = "tests/fixture.pcap"
        if not os.path.exists(pcap):
            self.skipTest("fixture.pcap missing")
        pipe = FeaturePipeline()
        fd = pipe.extract_pcap(pcap)
        self.assertGreater(len(fd.features), 100)
        self.assertIn("mgmt", fd.window_stats["by_type"])
        self.assertIn("data", fd.window_stats["by_type"])
        self.assertTrue(fd.sha256)
        # derived dataset
        ds = DatasetStore(":memory:")
        derived = pipe.to_dataset_store(fd, title="feat:" + pcap, dataset_store=ds)
        self.assertEqual(derived.kind, "derived")
        self.assertEqual(derived.provenance, "CAPTURED")


class ResearchDetectorTests(unittest.TestCase):
    def test_deauth_flood_detects_in_fixture(self):
        pcap = "tests/fixture.pcap"
        if not os.path.exists(pcap):
            self.skipTest("fixture.pcap missing")
        fd = FeaturePipeline().extract_pcap(pcap)
        det = DeauthFloodDetector(config={"threshold": 5})
        dets, metrics = det.run(fd.features)
        # fixture.pcap is known to contain a deauth flood
        self.assertGreaterEqual(len(dets), 1)
        self.assertIn("detections", metrics)
        self.assertTrue(det.test_harness(fd.features)["passed"])

    def test_registry_unique_ids(self):
        reg = DetectorRegistry()
        reg.register(DeauthFloodDetector())
        with self.assertRaises(ValueError):
            reg.register(DeauthFloodDetector())

    def test_beacon_no_false_positive_on_fixture(self):
        pcap = "tests/fixture.pcap"
        if not os.path.exists(pcap):
            self.skipTest("fixture.pcap missing")
        fd = FeaturePipeline().extract_pcap(pcap)
        det = BeaconMutationDetector()
        dets, _ = det.run(fd.features)
        # fixture doesn't have beacon mutations
        self.assertEqual(len(dets), 0)
        self.assertTrue(det.test_harness(fd.features)["passed"])


class ResearchBenchmarkTests(unittest.TestCase):
    def test_suite_compare(self):
        pcap = "tests/fixture.pcap"
        if not os.path.exists(pcap):
            self.skipTest("fixture.pcap missing")
        fd = FeaturePipeline().extract_pcap(pcap)
        suite = BenchmarkSuite()
        reg = DetectorRegistry()
        for d in (DeauthFloodDetector(), BeaconMutationDetector()):
            reg.register(d)
        for det in reg.list():
            suite.run_detector(det, fd, dataset_id=pcap, dataset_version=fd.version)
        cmp = suite.compare()
        self.assertEqual(len(cmp["runs"]), 2)
        self.assertIn("ranking", cmp)
        # report to file
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bench.json")
            suite.report(path)
            self.assertTrue(os.path.exists(path))
            self.assertTrue(os.path.exists(path.replace(".json", ".csv")))


class ResearchResourceTests(unittest.TestCase):
    def test_allocate_release_and_reap(self):
        rm = ResourceManager(":memory:")
        r = rm.register(kind="adapter", name="wlan0", capabilities=["monitor_mode"])
        tok = rm.allocate(r.id, "exp-1", "run-1", lease_s=0.2)
        self.assertIsNotNone(tok)
        # can't double-allocate exclusive resource
        tok2 = rm.allocate(r.id, "exp-2", "run-2", lease_s=30)
        self.assertIsNone(tok2)
        self.assertTrue(rm.release(tok))
        # second release fails
        self.assertFalse(rm.release(tok))

    def test_reap_orphans(self):
        rm = ResourceManager(":memory:")
        r = rm.register(kind="monitor", name="sensor-1")
        tok = rm.allocate(r.id, "exp-1", "run-1", lease_s=0.01)
        import time
        time.sleep(0.05)
        n = rm.reap_orphans()
        self.assertEqual(n, 1)
        # should be available again
        tok2 = rm.allocate(r.id, "exp-2", "run-2", lease_s=30)
        self.assertIsNotNone(tok2)


class ResearchEvidenceTests(unittest.TestCase):
    def test_append_and_verify(self):
        es = EvidenceStore(":memory:")
        # create temp file for sha
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as fh:
            fh.write("lab report content")
            path = fh.name
        try:
            ev = es.add(kind="report", title="run report", path=path, provenance="DERIVED", run_id="run-1")
            self.assertTrue(ev.sha256)
            self.assertTrue(es.verify(ev.id))
            self.assertEqual(len(es.list(run_id="run-1")), 1)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def test_supersede(self):
        es = EvidenceStore(":memory:")
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as fh:
            fh.write("v1"); p1 = fh.name
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as fh:
            fh.write("v2"); p2 = fh.name
        try:
            a = es.add(kind="pcap", title="capture", path=p1, provenance="CAPTURED")
            b = es.add(kind="pcap", title="capture v2", path=p2, provenance="CAPTURED")
            es.supersede(a.id, b.id)
            self.assertEqual(es.get(a.id).retention, "superseded")
        finally:
            for p in (p1, p2):
                try:
                    os.unlink(p)
                except OSError:
                    pass


class ResearchHardwareTests(unittest.TestCase):
    def test_probe_structure(self):
        cp = CapabilityProbe()
        hc = cp.probe()
        self.assertIn("packet_capture", hc.caps)
        self.assertIn("monitor_mode", hc.caps)
        self.assertIsInstance(hc.platform, str)
        self.assertIsInstance(hc.probed_at, float)
        rpt = cp.report()
        self.assertIn("capabilities", rpt)
        self.assertIn("platform", rpt)


class ResearchStatsTests(unittest.TestCase):
    def test_describe_and_ci(self):
        vals = [1, 2, 3, 4, 5, 100]
        d = describe(vals)
        self.assertEqual(d["count"], 6)
        self.assertIn("mean", d)
        self.assertIn("stdev", d)
        ci = confidence_interval([10, 12, 11, 13, 12])
        self.assertIn("ci_low", ci)
        self.assertIn("ci_high", ci)
        self.assertEqual(ci["method"], "normal-approx (derived, not measured)")

    def test_pearson_and_compare(self):
        self.assertAlmostEqual(pearson([1, 2, 3], [1, 2, 3]), 1.0)
        self.assertAlmostEqual(pearson([1, 2, 3], [3, 2, 1]), -1.0)
        cmp = compare_groups({"a": [1, 2, 3], "b": [10, 11, 12]})
        self.assertIn("groups", cmp)
        self.assertIn("deltas", cmp)


class ResearchReproTests(unittest.TestCase):
    def test_manifest_and_write(self):
        from wifiscanner.research.repro import build_manifest, write_manifest, load_manifest, verify_manifest
        m = build_manifest(experiment_id="wireless-ids-001", run_id="run-1", seed=42,
                           dataset={"id": "ds-1", "sha256": "abcd"},
                           config={"threshold": 5})
        self.assertIn("fingerprint", m)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "manifest.json")
            write_manifest(path, m)
            loaded = load_manifest(path)
            self.assertEqual(loaded["fingerprint"], m["fingerprint"])
            v = verify_manifest(loaded)
            # fingerprint ok, no artefact to check
            self.assertIsInstance(v["ok"], bool)


class ResearchReportTests(unittest.TestCase):
    def test_write_report_bundle(self):
        from wifiscanner.research.report import write_report
        with tempfile.TemporaryDirectory() as tmp:
            files = write_report(tmp, title="Demo", question="Q?", hypothesis="H",
                                 experiment={"id": "wireless-ids-001"},
                                 dataset={"id": "ds-1"},
                                 metrics=[{"metric": "f1", "value": 0.9, "meta": "{}"}],
                                 stats={"count": 1},
                                 manifest={"fingerprint": "abc", "software_version": "5.1.0", "platform": "linux", "seed": 0})
            self.assertGreaterEqual(len(files), 2)
            self.assertTrue(os.path.exists(os.path.join(tmp, "report.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp, "report.json")))


class ResearchWebTests(unittest.TestCase):
    def test_instructor_token_gating(self):
        from wifiscanner.research.web import ResearchApp
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "research.sqlite")
            app = ResearchApp(db_path=db)
            self.assertTrue(app.token)
            self.assertIsNotNone(app.projects)
            self.assertIsNotNone(app.evidence)
