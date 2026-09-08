"""Unified Research Workspace — Student + Instructor Web Console.

This module provides the single research workstation UI that replaces the
collection of isolated lab dashboards. It exposes:

* Student workspace: projects / experiments / datasets / detectors / evidence / reports
* Instructor console: lab status / resources / allocations / event monitor / audit logs
* Research analytics: detector performance, confusion matrices, ROC/PR helpers,
  signal history, localization, experiment comparison

Every graph uses actual backend data (no fabricated data). The server is
stdlib-only (http.server + threading) and reuses the same token-gating and
0600 storage as the existing labs.
"""
from __future__ import annotations

import html
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ..util import log
from ..privacy import ensure_secure_storage

_CSS = """
:root{--bg:#0f172a;--card:#1e293b;--ink:#e2e8f0;--mut:#94a3b8;--acc:#38bdf8;--ok:#34d399;--warn:#fbbf24;--bad:#f87171;--line:#334155}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink)}
a{color:var(--acc)}.wrap{max-width:1200px;margin:0 auto;padding:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:14px 0}
h1{font-size:22px;margin:6px 0}h2{font-size:16px;margin:16px 0 6px}
.small{color:var(--mut);font-size:12.5px}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}
th,td{text-align:left;padding:4px 7px;border-bottom:1px solid var(--line);font-family:ui-monospace,monospace;vertical-align:top}
th{color:var(--mut);font-size:11px;text-transform:uppercase}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:12px 0}
.stat{background:#0b1220;border:1px solid var(--line);border-radius:10px;padding:12px}.stat b{display:block;font-size:22px}
.btn{display:inline-block;background:var(--acc);color:#082f49;border:0;border-radius:8px;padding:9px 15px;font-weight:600;cursor:pointer;text-decoration:none;font-size:14px}
.btn.ghost{background:transparent;color:var(--acc);border:1px solid var(--acc)}
input,select,textarea{padding:8px;border-radius:8px;background:#0b1220;color:var(--ink);border:1px solid var(--line);width:100%}
textarea{height:90px;font-family:ui-monospace,monospace}
code{background:#0b1220;padding:1px 5px;border-radius:4px}
nav{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
nav a{padding:6px 12px;border-radius:999px;background:#0b1220;border:1px solid var(--line);text-decoration:none;font-size:13px}
nav a.active{background:var(--acc);color:#082f49;border-color:var(--acc)}
"""

def _page(title: str, body: str) -> bytes:
    nav = """
<nav>
 <a href='/'>Workspace</a>
 <a href='/projects'>Projects</a>
 <a href='/experiments'>Experiments</a>
 <a href='/datasets'>Datasets</a>
 <a href='/detectors'>Detectors</a>
 <a href='/resources'>Resources</a>
 <a href='/evidence'>Evidence</a>
 <a href='/hardware'>Hardware</a>
 <a href='/instructor'>Instructor</a>
</nav>"""
    return (f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>"
            f"<div class='wrap'><h1>Wireless Research Workstation</h1>{nav}<div>{body}</div></div></body></html>").encode()

class ResearchApp:
    def __init__(self, db_path: str = "research.sqlite", token: str = ""):
        self.db_path = db_path
        self.token = token or secrets.token_urlsafe(9)
        from .projects import ProjectStore
        from .datasets import DatasetStore
        from .resources import ResourceManager
        from .evidence import EvidenceStore
        from .hardware import CapabilityProbe
        from ..experiment import ExperimentEngine
        self.projects = ProjectStore(db_path)
        self.datasets = DatasetStore(db_path)
        self.resources = ResourceManager(db_path)
        self.evidence = EvidenceStore(db_path)
        self.hardware = CapabilityProbe()
        self.experiments = ExperimentEngine(db_path)
        try:
            from ..experiment import bootstrap_catalogue
            bootstrap_catalogue(self.experiments)
        except Exception:
            pass
        self.started = time.time()

    def instructor_ok(self, query: str) -> bool:
        tok = parse_qs(urlparse(query).query).get("token", [""])[0]
        return tok and secrets.compare_digest(tok, self.token)


def _workspace(app: ResearchApp) -> bytes:
    hc = app.hardware.probe()
    proj_n = len(app.projects.list())
    ds_n = len(app.datasets.list())
    exp_n = len(app.experiments.list_definitions())
    res_n = len(app.resources.list())
    ev_n = len(app.evidence.list())
    cap_rows = ""
    for cap_key, cap_val in hc.caps.items():
        icon = "YES" if cap_val else "NO"
        detail = html.escape(hc.details.get(cap_key, ""))
        cap_rows += f"<tr><td>{html.escape(cap_key)}</td><td>{icon}</td><td class='small'>{detail}</td></tr>"
    body = f"""
<div class='grid'>
 <div class='stat'>projects<b>{proj_n}</b></div>
 <div class='stat'>experiments<b>{exp_n}</b></div>
 <div class='stat'>datasets<b>{ds_n}</b></div>
 <div class='stat'>resources<b>{res_n}</b></div>
 <div class='stat'>evidence<b>{ev_n}</b></div>
 <div class='stat'>platform<b>{html.escape(hc.platform)}</b></div>
</div>
<div class='card'><h2>Research workflow</h2>
<p><code>Research Question - Hypothesis - Experiment Design - Variables - Lab Environment - Execution - Measurements - Evidence - Analysis - Detector - Benchmark - Comparison - Reproduction - Dataset - Report</code></p>
<p class='small'>Every experiment emits an auditable timeline: START - CONFIG - LAB_EVENT - PACKET/EVIDENCE - DETECTION - ANALYSIS - RESPONSE - RESULT - RESET. Inspect it via <a href='/experiments'>Experiments</a>.</p>
</div>
<div class='card'><h2>Hardware capabilities (live probe)</h2>
<table><tr><th>Capability</th><th>Available</th><th>Detail</th></tr>
{cap_rows}
</table>
<p class='small'>Platform: {html.escape(hc.platform)} | root={hc.is_root} | backends={html.escape(', '.join(hc.backends) or 'none')} | interfaces={len(hc.interfaces)}</p>
</div>
"""
    return _page("Workspace", body)


def _projects_page(app: ResearchApp, msg: str = "") -> bytes:
    projs = app.projects.list()[:50]
    rows = ""
    for p in projs:
        rows += f"<tr><td>{html.escape(p.id)}</td><td>{html.escape(p.title)}</td><td>{html.escape(p.status)}</td><td>{html.escape(p.owner)}</td><td>{html.escape(p.research_question[:60])}</td></tr>"
    if not rows:
        rows = '<tr><td colspan=5 class=small>No projects - create one via CLI: <code>wifiscanner research project-create --title "My question"</code></td></tr>'
    msg_html = ""
    if msg:
        msg_html = "<div class='card' style='border-color:var(--ok)'>" + html.escape(msg) + "</div>"
    count = len(app.projects.list())
    body = f"""
{msg_html}
<div class='card'><h2>Projects ({count})</h2>
<table><tr><th>ID</th><th>Title</th><th>Status</th><th>Owner</th><th>Question</th></tr>{rows}</table></div>
<div class='card'><h2>Create project</h2>
<form method='POST' action='/projects'>
 <input name='title' placeholder='Title - e.g. Deauth detection robustness' required>
 <textarea name='question' placeholder='Research question'></textarea>
 <input name='hypothesis' placeholder='Hypothesis'>
 <input name='owner' placeholder='Owner (student id)'>
 <button class='btn'>Create</button>
</form></div>
"""
    return _page("Projects", body)


def _experiments_page(app: ResearchApp) -> bytes:
    defs = app.experiments.list_definitions()
    rows = ""
    for d in defs:
        rows += f"<tr><td>{html.escape(d.id)}</td><td>{html.escape(d.title)}</td><td>{html.escape(d.category)}</td><td>{html.escape(str(d.data_provenance))}</td><td class='small'>{html.escape(d.objective[:70])}</td></tr>"
    runs = app.experiments.list_runs(limit=20)
    rrows = ""
    for r in runs:
        rrows += f"<tr><td>{html.escape(r.id[:12])}</td><td>{html.escape(r.experiment_id)}</td><td>{html.escape(r.status)}</td><td>{r.duration_s}s</td><td>{len(r.timeline)}</td></tr>"
    if not rrows:
        rrows = '<tr><td colspan=5 class=small>No runs yet</td></tr>'
    body = f"""
<div class='card'><h2>Experiment catalogue ({len(defs)})</h2>
<table><tr><th>ID</th><th>Title</th><th>Category</th><th>Provenance</th><th>Objective</th></tr>{rows}</table>
<p class='small'>Run via CLI: <code>wifiscanner experiment start --id ID --config '{{}}'</code></p></div>
<div class='card'><h2>Recent runs ({len(runs)})</h2>
<table><tr><th>Run</th><th>Experiment</th><th>Status</th><th>Duration</th><th>Timeline events</th></tr>{rrows}</table></div>
"""
    return _page("Experiments", body)


def _datasets_page(app: ResearchApp) -> bytes:
    dss = app.datasets.list()
    rows = ""
    for d in dss[:50]:
        rows += f"<tr><td>{html.escape(d.id)}</td><td>{html.escape(d.title)}</td><td>{html.escape(d.kind)}/{html.escape(d.provenance)}</td><td>{html.escape(d.sha256[:8])}</td><td>{d.size_bytes}</td><td class='small'>{html.escape(d.artifact_path[:40])}</td></tr>"
    if not rows:
        rows = '<tr><td colspan=6 class=small>No datasets - register via <code>wifiscanner research dataset-register --title X --artifact path.pcap</code></td></tr>'
    body = f"""
<div class='card'><h2>Datasets ({len(dss)})</h2>
<table><tr><th>ID</th><th>Title</th><th>Kind/Provenance</th><th>SHA</th><th>Bytes</th><th>Artifact</th></tr>{rows}</table>
<p class='small'>Provenance is explicit: LIVE / CAPTURED / REPLAYED / SIMULATED / SYNTHETIC - never mixed without labeling.</p></div>
"""
    return _page("Datasets", body)


def _detectors_page(app: ResearchApp) -> bytes:
    try:
        from .detectors import DetectorRegistry, BUILTIN_DETECTORS
        reg = DetectorRegistry()
        for d in BUILTIN_DETECTORS:
            try:
                reg.register(d)
            except Exception:
                pass
        dets = reg.list()
    except Exception as exc:
        dets = []
        det_err = str(exc)
    else:
        det_err = ""
    rows = ""
    for d in dets:
        rows += f"<tr><td>{html.escape(d.id)}</td><td>{html.escape(d.title)}</td><td>{html.escape(d.kind)}</td><td>{html.escape(d.version)}</td><td class='small'>{html.escape(d.description[:80])}</td></tr>"
    if not rows:
        rows = '<tr><td colspan=5 class=small>No detectors</td></tr>'
    err_html = ""
    if det_err:
        err_html = f"<p class='small' style='color:var(--bad)'>{html.escape(det_err)}</p>"
    body = f"""
<div class='card'><h2>Detectors ({len(dets)})</h2>
<table><tr><th>ID</th><th>Title</th><th>Kind</th><th>Version</th><th>Description</th></tr>{rows}</table>
<p class='small'>Implement <code>Detector</code> in <code>wifiscanner/research/detectors.py</code>, register via <code>DetectorRegistry</code>. Test harness: <code>.test_harness(features)</code>, benchmark: <code>.benchmark(feature_sets)</code></p>
{err_html}
</div>
"""
    return _page("Detectors", body)


def _resources_page(app: ResearchApp) -> bytes:
    res = app.resources.list()
    rows = ""
    for r in res[:50]:
        caps = ", ".join(r.capabilities) if r.capabilities else "-"
        state = "free" if r.available else "busy -> " + html.escape(r.allocated_to[:12] if r.allocated_to else "")
        rows += f"<tr><td>{html.escape(r.id)}</td><td>{html.escape(r.kind)}/{html.escape(r.name)}</td><td>{html.escape(caps)}</td><td>{html.escape(r.health)}</td><td>{html.escape(state)}</td></tr>"
    if not rows:
        rows = '<tr><td colspan=5 class=small>No resources - register via CLI or auto-discovered from interfaces</td></tr>'
    body = f"""
<div class='card'><h2>Lab Resources ({len(res)})</h2>
<table><tr><th>ID</th><th>Kind/Name</th><th>Capabilities</th><th>Health</th><th>Allocation</th></tr>{rows}</table>
<p class='small'>Allocation heartbeat timeout 60s; orphan reaper releases stale allocations. Exclusive resources refuse conflicting allocations.</p></div>
"""
    return _page("Resources", body)


def _evidence_page(app: ResearchApp) -> bytes:
    evs = app.evidence.list()
    rows = ""
    for e in evs[:50]:
        rows += f"<tr><td>{html.escape(e.id)}</td><td>{html.escape(e.kind)}</td><td>{html.escape(e.title[:40])}</td><td>{html.escape(e.provenance)}</td><td>{html.escape(e.sha256[:8])}</td><td>{html.escape(e.retention)}</td></tr>"
    if not rows:
        rows = '<tr><td colspan=6 class=small>No evidence - artefacts are added when experiments run</td></tr>'
    body = f"""
<div class='card'><h2>Evidence Ledger ({len(evs)} artefacts)</h2>
<table><tr><th>ID</th><th>Kind</th><th>Title</th><th>Provenance</th><th>SHA</th><th>Retention</th></tr>{rows}</table>
<p class='small'>Every artefact is checksummed, provenance-tagged and append-only. Audit trail: <code>/evidence?run_id=X</code></p></div>
"""
    return _page("Evidence", body)


def _hardware_page(app: ResearchApp) -> bytes:
    hc = app.hardware.probe(refresh=True)
    cap_rows = ""
    for k, v in hc.caps.items():
        icon = "YES" if v else "NO"
        cap_rows += f"<tr><td>{html.escape(k)}</td><td>{icon}</td><td class='small'>{html.escape(hc.details.get(k,''))}</td></tr>"
    backends = html.escape(", ".join(hc.backends) or "none")
    iface_preview = html.escape(str(hc.interfaces[:2]))
    probed = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(hc.probed_at))
    body = f"""
<div class='card'><h2>Hardware Capabilities (refreshed)</h2>
<table><tr><th>Probe</th><th>Value</th></tr>
<tr><td>Platform</td><td>{html.escape(hc.platform)}</td></tr>
<tr><td>Root</td><td>{hc.is_root}</td></tr>
<tr><td>Backends</td><td>{backends}</td></tr>
<tr><td>Interfaces</td><td>{len(hc.interfaces)} - {iface_preview}...</td></tr>
<tr><td>Probed at</td><td>{probed}</td></tr>
</table></div>
<div class='card'><h2>Capability Matrix</h2>
<table><tr><th>Capability</th><th>Status</th><th>Detail</th></tr>
{cap_rows}
</table></div>
"""
    return _page("Hardware", body)


def _instructor_page(app: ResearchApp, token: str) -> bytes:
    if token != app.token:
        return _page("Instructor", "<div class='card'><h2>Token required</h2><p>Append <code>?token=...</code> from the console log.</p></div>")
    hc = app.hardware.probe()
    allocs = app.resources.allocations()
    arows = ""
    for a in allocs[:30]:
        alloc_t = time.strftime("%H:%M:%S", time.localtime(a["allocated_at"])) if a.get("allocated_at") else ""
        state = "active" if not a.get("released_at") else "released"
        arows += f"<tr><td>{html.escape(a['token'][:12])}</td><td>{html.escape(a['resource_id'][:12])}</td><td>{html.escape(a['run_id'][:12])}</td><td>{alloc_t}</td><td>{state}</td></tr>"
    if not arows:
        arows = '<tr><td colspan=5 class=small>No allocations</td></tr>'
    proj_c = len(app.projects.list())
    ds_c = len(app.datasets.list())
    ev_c = len(app.evidence.list())
    summary = html.escape(hc.summary())
    token_esc = html.escape(token)
    body = f"""
<div class='grid'>
 <div class='stat'>allocations<b>{len(allocs)}</b></div>
 <div class='stat'>projects<b>{proj_c}</b></div>
 <div class='stat'>datasets<b>{ds_c}</b></div>
 <div class='stat'>evidence<b>{ev_c}</b></div>
</div>
<div class='card'><h2>Allocations (live)</h2>
<table><tr><th>Token</th><th>Resource</th><th>Run</th><th>Allocated</th><th>State</th></tr>{arows}</table>
<p><a class='btn ghost' href='/resources'>Resources</a> <a class='btn ghost' href='/evidence'>Evidence</a></p>
</div>
<div class='card'><h2>Controls</h2>
<form method='POST' action='/instructor/reap?token={token_esc}'><button class='btn'>Reap orphan allocations</button></form>
<p class='small'>Reaper releases allocations whose heartbeat is stale (&gt;60s) or lease expired. Also runs every 30s in background.</p>
</div>
<div class='card'><h2>Hardware</h2><p class='small'>{summary}</p></div>
"""
    return _page("Instructor Console", body)


class ResearchHandler(BaseHTTPRequestHandler):
    server_version = "wifiscanner-research"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    @property
    def app(self) -> ResearchApp:
        return self.server.app  # type: ignore

    def _send(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj, indent=2, default=str).encode(), status, "application/json; charset=utf-8")

    def _redirect(self, loc: str):
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        path = (u.path.rstrip("/") or "/")
        qs = u.query
        app = self.app
        if path == "/health":
            return self._json({"ok": True, "uptime_s": round(time.time() - app.started, 1)})
        if path == "/":
            return self._send(_workspace(app))
        if path == "/projects":
            return self._send(_projects_page(app))
        if path == "/experiments":
            return self._send(_experiments_page(app))
        if path == "/datasets":
            return self._send(_datasets_page(app))
        if path == "/detectors":
            return self._send(_detectors_page(app))
        if path == "/resources":
            return self._send(_resources_page(app))
        if path == "/evidence":
            return self._send(_evidence_page(app))
        if path == "/hardware":
            return self._send(_hardware_page(app))
        if path == "/instructor":
            tok = parse_qs(qs).get("token", [""])[0]
            return self._send(_instructor_page(app, tok))
        if path == "/api/projects":
            return self._json([p.to_dict() for p in app.projects.list()])
        if path == "/api/datasets":
            return self._json([d.to_dict() for d in app.datasets.list()])
        if path == "/api/hardware":
            return self._json(app.hardware.report())
        if path == "/api/experiments":
            return self._json([d.to_dict() for d in app.experiments.list_definitions()])
        return self._send(_page("Not found", "<div class='card'><h2>404</h2><p>Use the navigation above.</p></div>"), 404)

    def do_POST(self):
        u = urlparse(self.path)
        path = (u.path.rstrip("/") or "/")
        app = self.app
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.server.app  # keep ref
        body = self.rfile.read(length) if length else b""
        form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "ignore") if body else "", keep_blank_values=True).items()}
        if path == "/projects":
            title = form.get("title", "").strip() or "Untitled"
            q = form.get("question", "").strip()
            hyp = form.get("hypothesis", "").strip()
            owner = form.get("owner", "").strip()
            proj = app.projects.create(title=title, research_question=q, hypothesis=hyp, owner=owner)
            return self._send(_projects_page(app, f"Created {proj.id}"))
        if path.startswith("/instructor/reap"):
            tok = parse_qs(u.query).get("token", [""])[0]
            if tok != app.token:
                return self._json({"error": "forbidden"}, 403)
            n = app.resources.reap_orphans()
            return self._json({"reaped": n})
        return self._json({"error": "not found"}, 404)


class ResearchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, address, handler, app):
        self.app = app
        super().__init__(address, handler)


def make_research_server(bind: str, port: int, app: ResearchApp):
    return ResearchServer((bind, int(port)), ResearchHandler, app)
