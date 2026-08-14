"""
agent/orchestration/linux_ids_adapter.py
============================================
Wires linux_collector.LinuxTelemetryCollector into ThreatFusionEngine and
the shared telemetry_scores.jsonl output, WITHOUT modifying
linux_collector.py or linux_model_adapter.py at all.

How: LinuxTelemetryCollector already does all the hard work (bpftrace
capture, per-PID buffering, windowing to exactly 500 syscalls) and then
calls self.run_inference(...) once a window is full. That method
currently talks to LinuxModelAdapter directly and only prints to console.
This subclass overrides ONLY that one method -- everything else
(start(), process_event(), the bpftrace subprocess handling, the buffer
logic) is inherited unchanged from the original class.

Effect: Linux syscall events now flow through the same fusion_engine +
save_event() pipeline as the other 5 models, and show up in
telemetry_scores.jsonl like everything else -- instead of being an
invisible, separate console-only pathway.

Usage (see run_all.py's start_linux_ids()):
    from orchestration.linux_ids_adapter import LinuxIDSAdapter
    collector = LinuxIDSAdapter(engine, save_event)
    threading.Thread(target=collector.start, daemon=True).start()
"""
from __future__ import annotations

from typing import Callable

from agent.linux_collector import LinuxTelemetryCollector


class LinuxIDSAdapter(LinuxTelemetryCollector):
    def __init__(self, fusion_engine, save_event_fn: Callable[..., None]):
        super().__init__()
        self.engine = fusion_engine
        self.save_event = save_event_fn

    def run_inference(self, timestamp, pid, uid, process, sequence):
        """
        Overrides LinuxTelemetryCollector.run_inference(). Same signature,
        same call site (invoked by the inherited process_event() once a
        500-syscall window is full) -- just routes the result through
        fusion_engine instead of calling LinuxModelAdapter directly.
        """
        score = self.engine.score_process_event(syscall_sequence=sequence)
        if score is None:
            # Model unavailable/failed -- matches how every other collector
            # in run_all.py silently skips a None score rather than crashing.
            return

        verdict = self.engine.get_verdict(score)
        print(f"[linux_ids]  {process:<20} pid={pid} uid={uid} -> {score:.3f} ({verdict})")
        self.save_event(
            "linux_ids", score, verdict,
            pid=pid, uid=uid, process=process, timestamp=timestamp,
        )
