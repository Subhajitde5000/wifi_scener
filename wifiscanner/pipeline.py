"""Event Pipeline — async telemetry bus for concurrent experiments.

Requirement §12 (Performance) + §13 (Observability): handles concurrent
packet processing, event queues, background workers and streaming telemetry
without blocking API workers.

Architecture
------------
                    ┌─────────────┐
  packet sources ──▶ │  IngestBus  │ ──▶ worker pool ──▶ handlers
  (sniffer, pcap,   │  (asyncio   │     (IDS, traffic,  ──▶ Store
   host telemetry)   │   Queue)    │      locate, etc)       │
                    └──────┬──────┘                         │
                           │ WebSocket broadcaster ────────▶│ frontend
                           └───────────────────────────────▶│ analytics

* IngestBus: bounded asyncio.Queue with back-pressure (drops oldest if full,
  counts drops for observability).
* Workers: configurable pool that processes events without blocking the API.
* Broadcaster: fan-out to WebSocket subscribers (live dashboards).
* All components expose metrics (queue depth, throughput, drops, latency).

The pipeline degrades gracefully: if no event loop is running (e.g. CLI,
tests) it falls back to synchronous direct dispatch.
"""
from __future__ import annotations

import asyncio
import collections
import json
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .util import log


@dataclass
class PipelineEvent:
    """Single event flowing through the pipeline."""
    ts: float
    source: str           # sniffer / pcap / telemetry / lab
    kind: str             # packet / ids-alert / traffic-event / observation / fix
    payload: Dict[str, Any] = field(default_factory=dict)
    provenance: str = "LIVE"
    experiment_id: str = ""
    run_id: str = ""

    def to_dict(self) -> dict:
        return {
            "ts": self.ts, "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
            "source": self.source, "kind": self.kind,
            "payload": self.payload, "provenance": self.provenance,
            "experiment_id": self.experiment_id, "run_id": self.run_id,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# --------------------------------------------------------------- pipeline

class EventPipeline:
    """Thread-safe, async-capable event pipeline."""

    def __init__(self, max_queue: int = 10000, workers: int = 4):
        self.max_queue = max_queue
        self.workers = workers
        # Sync fallback queue (used when no asyncio loop)
        self._sync_queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._async_queue: Optional[asyncio.Queue] = None
        self._handlers: Dict[str, List[Callable]] = collections.defaultdict(list)
        self._subscribers: List[Callable] = []
        self._lock = threading.Lock()
        self._running = False
        self._threads: List[threading.Thread] = []
        # Metrics
        self.enqueued = 0
        self.processed = 0
        self.dropped = 0
        self.errors = 0
        self._latencies: collections.deque = collections.deque(maxlen=1000)

    # ---- handlers

    def on(self, kind: str, handler: Callable[[PipelineEvent], None]) -> None:
        """Register a handler for a specific event kind (or '*' for all)."""
        with self._lock:
            self._handlers[kind].append(handler)

    def subscribe(self, callback: Callable[[PipelineEvent], None]) -> None:
        """Subscribe to all events (e.g. WebSocket broadcaster)."""
        with self._lock:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable) -> None:
        with self._lock:
            self._subscribers = [c for c in self._subscribers if c is not callback]

    # ---- enqueue

    def emit(self, event: PipelineEvent) -> bool:
        """Enqueue an event. Returns False if dropped due to back-pressure."""
        self.enqueued += 1
        # Try async queue first if available
        if self._async_queue is not None:
            try:
                self._async_queue.put_nowait(event)
                self._fanout(event)
                return True
            except asyncio.QueueFull:
                self.dropped += 1
                log.warning("pipeline queue full (%d), dropping %s event", self.max_queue, event.kind)
                return False
        # Sync fallback
        try:
            self._sync_queue.put_nowait(event)
        except queue.Full:
            try:
                self._sync_queue.get_nowait()  # drop oldest
            except queue.Empty:
                pass
            self.dropped += 1
            try:
                self._sync_queue.put_nowait(event)
            except queue.Full:
                return False
        self._fanout(event)
        # Direct dispatch if not running workers
        if not self._running:
            self._dispatch(event)
        return True

    def emit_now(self, source: str, kind: str, payload: Optional[dict] = None,
                 provenance: str = "LIVE", experiment_id: str = "", run_id: str = "") -> bool:
        return self.emit(PipelineEvent(
            ts=time.time(), source=source, kind=kind,
            payload=payload or {}, provenance=provenance,
            experiment_id=experiment_id, run_id=run_id))

    # ---- dispatch

    def _dispatch(self, event: PipelineEvent) -> None:
        t0 = time.time()
        handlers = []
        with self._lock:
            handlers.extend(self._handlers.get(event.kind, []))
            handlers.extend(self._handlers.get("*", []))
        for handler in handlers:
            try:
                handler(event)
            except Exception as exc:
                self.errors += 1
                log.warning("pipeline handler error for %s: %s", event.kind, exc)
        self.processed += 1
        self._latencies.append((time.time() - t0) * 1000)

    def _fanout(self, event: PipelineEvent) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for cb in subs:
            try:
                cb(event)
            except Exception:
                pass

    # ---- lifecycle

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        for i in range(self.workers):
            t = threading.Thread(target=self._worker_loop, name=f"pipeline-w{i}", daemon=True)
            t.start()
            self._threads.append(t)
        log.info("pipeline started (%d workers, queue=%d)", self.workers, self.max_queue)

    def stop(self) -> None:
        self._running = False
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()
        log.info("pipeline stopped (enqueued=%d processed=%d dropped=%d errors=%d)",
                 self.enqueued, self.processed, self.dropped, self.errors)

    def _worker_loop(self) -> None:
        while self._running:
            try:
                event = self._sync_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            self._dispatch(event)

    # ---- metrics

    def stats(self) -> dict:
        avg_lat = sum(self._latencies) / len(self._latencies) if self._latencies else 0
        return {
            "enqueued": self.enqueued, "processed": self.processed,
            "dropped": self.dropped, "errors": self.errors,
            "queue_depth": self._sync_queue.qsize(),
            "avg_handler_ms": round(avg_lat, 2),
            "p95_handler_ms": round(sorted(self._latencies)[int(len(self._latencies) * 0.95)] if self._latencies else 0, 2),
            "workers": self.workers, "max_queue": self.max_queue,
            "running": self._running,
        }

    # ---- async helpers (for WebSocket servers)

    async def async_emit(self, event: PipelineEvent) -> None:
        if self._async_queue is None:
            self._async_queue = asyncio.Queue(maxsize=self.max_queue)
        await self._async_queue.put(event)
        self._fanout(event)

    async def async_consume(self):
        """Async generator for WebSocket handlers."""
        if self._async_queue is None:
            self._async_queue = asyncio.Queue(maxsize=self.max_queue)
        while True:
            event = await self._async_queue.get()
            yield event


# ------------------------------------------------------------------ global

_default_pipeline: Optional[EventPipeline] = None


def get_pipeline() -> EventPipeline:
    global _default_pipeline
    if _default_pipeline is None:
        _default_pipeline = EventPipeline()
    return _default_pipeline
