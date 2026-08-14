"""
agent/run_all.py
=================
AEGIS - OS-aware wiring script: detects the host operating system, then
starts only the collectors compatible with it, printing live scored
verdicts from ThreatFusionEngine for each one.

Place this file in the same agent/ folder as fusion_engine.py and
live_collectors.py, then run:

    python run_all.py                # auto-detects OS (default)
    python run_all.py --os windows   # manual override, for testing only
    python run_all.py --os linux

WHAT WILL WORK IMMEDIATELY (no extra setup, on either OS):
    - Zero-Day      (already proven working)
    - CICIDS        (model file confirmed present -- should load)

WHAT NEEDS ONE-TIME SETUP FIRST (instructions printed at startup if missing):
    - EMBER         -> needs PE_WATCH_DIR below to exist
    - HDFS          -> point HDFS_LOG_PATH below at a real log file
    - Windows Adv.  -> Windows only; install + configure Sysmon first
    - Linux IDS     -> Linux only; needs bpftrace installed + root/sudo

--------------------------------------------------------------------------
ORCHESTRATION NOTE (OS-aware collector selection)
--------------------------------------------------------------------------
This file does NOT contain any collector's actual capture logic -- that
still lives entirely in live_collectors.py, scapy_flow_collector.py, and
linux_collector.py, unmodified. This file only:

    1. Detects the host OS (agent/orchestration/os_detector.py)
    2. Looks up which collectors are compatible with that OS
       (agent/orchestration/telemetry_registry.py)
    3. Calls each compatible collector's start function exactly once
       (agent/orchestration/collector_manager.py)

Every "start_*" function below is unchanged in what it does internally
compared to the previous version of this file -- they are just wrapped
in functions now so the orchestrator can decide, per-OS, which ones to
call, instead of this file unconditionally calling all of them.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent          # .../agent/
_PROJECT_ROOT = _HERE.parent                      # .../AEGIS/

# Both paths are needed: _HERE for this file's existing bare imports
# (`from fusion_engine import ...`), _PROJECT_ROOT for linux_collector.py's
# package-qualified import (`from agent.linux_model_adapter import ...`).
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_PROJECT_ROOT))

from fusion_engine import ThreatFusionEngine  # noqa: E402
from live_collectors import (  # noqa: E402
    ZeroDayEventCollector,
    PEFileCollector,
    HDFSLogCollector,
    WindowsAPICollector,
)
from scapy_flow_collector import ScapyFlowCollector  # noqa: E402
from watchdog.observers import Observer  # noqa: E402

from orchestration.os_detector import resolve_os  # noqa: E402
from orchestration.collector_manager import print_banner, run_collectors  # noqa: E402
from orchestration.telemetry_registry import collectors_for_platform  # noqa: E402

# ---------------------------------------------------------------------------
# EDIT THESE PATHS for your machine before running EMBER / HDFS collectors
# ---------------------------------------------------------------------------
PE_WATCH_DIR = r"C:\Users\%USERNAME%\Downloads"   # Windows-style; adjust for Linux paths as needed
HDFS_LOG_PATH = str(_HERE / "test.log")

# ---------------------------------------------------------------------------
# CLI: --os override (manual, for testing only -- auto-detect is default)
# ---------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="AEGIS OS-aware telemetry agent")
parser.add_argument(
    "--os", dest="os_override", default=None, choices=["windows", "linux", "Windows", "Linux"],
    help="Manually force a telemetry profile (windows/linux). Default: auto-detect.",
)
args = parser.parse_args()

OS_NAME = resolve_os(args.os_override)
COMPATIBLE_COLLECTORS = collectors_for_platform(OS_NAME)
PROFILE_NAME = OS_NAME.upper()

engine = ThreatFusionEngine()
print("[run_all] ThreatFusionEngine initialised. Check the [loader] lines above")
print("[run_all] for 'Loaded X' vs 'Missing artefact' / 'Failed to load' per model.\n")

# ---------------------------------------------------------------------------
# JSONL output -- every scored event (from every model) is appended here,
# one JSON object per line, in addition to being printed to the console.
# ---------------------------------------------------------------------------
OUTPUT_DIR = _HERE / "telemetry_output"
OUTPUT_FILE = OUTPUT_DIR / "telemetry_scores.jsonl"
OUTPUT_DIR.mkdir(exist_ok=True)

_write_lock = threading.Lock()


def save_event(model: str, score: float, verdict: str, **extra):
    """Append one scored event as a JSON line to telemetry_scores.jsonl."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "score": round(score, 4),
        "verdict": verdict,
        **extra,
    }
    line = json.dumps(event, default=str)
    with _write_lock:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


print(f"[run_all] Scored events will also be saved to: {OUTPUT_FILE}\n")

# Handles kept at module scope so the shutdown block at the bottom can stop
# whichever collectors actually got started this run.
_running_handles: dict = {}


# ===========================================================================
# 1. Zero-Day -- cross-platform, no setup needed
# ===========================================================================

def start_zero_day() -> None:
    def handle_zeroday_event(event_id, process_name, user_name, ip):
        score = engine.score_windows_event(event_id, process_name, user_name, ip)
        if score is None:
            return
        verdict = engine.get_verdict(score)
        print(f"[zero_day]   {process_name:<30} ({user_name}@{ip}) -> {score:.3f} ({verdict})")
        save_event("zero_day", score, verdict, process_name=process_name, user_name=user_name, ip=ip)

    zday = ZeroDayEventCollector(on_event=handle_zeroday_event)
    zday.start(poll_interval=2.0)
    _running_handles["zero_day"] = zday


# ===========================================================================
# 2. CICIDS -- scapy-based real packet/byte counts. Cross-platform, but
#    requires Administrator/root + Npcap (Windows) or raw-socket privileges
#    (Linux).
# ===========================================================================

def start_cicids() -> None:
    net_collector = ScapyFlowCollector(flow_timeout=2.0)
    net_collector.start()  # raises if scapy/privileges unavailable -- caught by collector_manager
    print("[run_all] CICIDS scapy sniffer started (real packet/byte counts).")
    _running_handles["cicids"] = net_collector

    def network_loop():
        while True:
            for flow in net_collector.pop_completed_flows():
                score = engine.score_network_flow(flow)
                if score is not None:
                    verdict = engine.get_verdict(score)
                    dest_port = int(flow['Destination Port'])
                    print(f"[cicids]     port={dest_port:<5} fwd_pkts={int(flow['Total Fwd Packets']):<4} "
                          f"bwd_pkts={int(flow['Total Backward Packets']):<4} -> {score:.6f} ({verdict})")
                    save_event("cicids", score, verdict, destination_port=dest_port,
                               fwd_packets=flow['Total Fwd Packets'], bwd_packets=flow['Total Backward Packets'])
            time.sleep(1.0)

    threading.Thread(target=network_loop, daemon=True).start()


# ===========================================================================
# 3. EMBER -- needs a real folder to watch for new/modified .exe/.dll files.
#    Cross-platform (watchdog), path syntax differs by OS -- adjust
#    PE_WATCH_DIR above for Linux if used there.
# ===========================================================================

def start_ember() -> None:
    def handle_pe_features(pe_features: dict, meta: dict):
        score = engine.score_file(pe_features)
        if score is not None:
            verdict = engine.get_verdict(score)
            fname = Path(meta["file_path"]).name
            print(f"[ember]      {fname:<25} sha256={meta['sha256'][:12]}... -> {score:.3f} ({verdict})")
            save_event("ember", score, verdict, file_path=meta["file_path"], sha256=meta["sha256"])

    pe_dir = Path(PE_WATCH_DIR.replace("%USERNAME%", Path.home().name))
    if not pe_dir.exists():
        raise FileNotFoundError(
            f"watch folder does not exist: {pe_dir} "
            f"(create it, or edit PE_WATCH_DIR at the top of this file)"
        )

    pe_collector = PEFileCollector(
        on_new_pe_features=handle_pe_features,
        feature_names=getattr(engine, "_ember_features", None),
    )
    pe_observer = Observer()
    pe_observer.schedule(pe_collector, path=str(pe_dir), recursive=False)
    pe_observer.start()
    print(f"[run_all] EMBER collector watching: {pe_dir}")
    _running_handles["ember"] = pe_observer


# ===========================================================================
# 4. HDFS -- needs a real log file path set in HDFS_LOG_PATH above.
#    Cross-platform (watchdog).
# ===========================================================================

def start_hdfs() -> None:
    def handle_block_text(raw_text: str):
        score = engine.score_log_line(raw_text)
        if score is not None:
            verdict = engine.get_verdict(score)
            print(f"[hdfs]       block scored -> {score:.3f} ({verdict})")
            save_event("hdfs", score, verdict)

    hdfs_path = Path(HDFS_LOG_PATH)
    if not hdfs_path.exists():
        raise FileNotFoundError(
            f"set HDFS_LOG_PATH to a real file (currently: {HDFS_LOG_PATH})"
        )

    hdfs_collector = HDFSLogCollector(on_block_text=handle_block_text)
    hdfs_collector.start_flush_thread()
    hdfs_observer = Observer()
    hdfs_observer.schedule(hdfs_collector, path=str(hdfs_path.parent), recursive=False)
    hdfs_observer.start()
    print(f"[run_all] HDFS collector watching: {hdfs_path}")
    _running_handles["hdfs"] = hdfs_observer


# ===========================================================================
# 5. Windows Advanced -- WINDOWS ONLY. Needs Sysmon installed + configured.
#    Download: https://learn.microsoft.com/sysinternals/downloads/sysmon
#    Install:  sysmon64.exe -accepteula -i  (as Administrator)
#    Logs to "Microsoft-Windows-Sysmon/Operational" -- once that exists,
#    WindowsAPICollector reads it automatically. No path to edit here.
#    Never attempted on Linux -- the registry excludes it from that
#    platform's profile, so this function is simply never called there.
# ===========================================================================

def start_windows_advanced() -> None:
    win_collector = WindowsAPICollector()
    win_collector.start()  # raises RuntimeError internally if not on Windows
    print("[run_all] Windows Advanced collector started (reading Sysmon log).")
    print("[run_all] NOTE: scoring for this model requires wiring get_sequence(pid)")
    print("[run_all]       into score_process_event(api_call_sequence=...) per PID --")
    print("[run_all]       not auto-looped here since it needs a specific PID to watch.")
    _running_handles["windows_advanced"] = win_collector


# ===========================================================================
# 6. Linux IDS -- LINUX ONLY. Uses orchestration.linux_ids_adapter.LinuxIDSAdapter,
#    a thin subclass of the existing linux_collector.LinuxTelemetryCollector
#    (bpftrace-based, system-wide syscall capture). linux_collector.py
#    itself is completely unmodified -- the adapter only overrides
#    run_inference() so results flow through ThreatFusionEngine and land in
#    the shared telemetry_scores.jsonl, same as the other 5 collectors,
#    instead of the original class's console-only, direct-to-model path.
#    Needs bpftrace installed + root/sudo.
# ===========================================================================

def start_linux_ids() -> None:
    from orchestration.linux_ids_adapter import LinuxIDSAdapter

    collector = LinuxIDSAdapter(engine, save_event)
    # start() blocks (reads a subprocess pipe in a loop), so it must run in
    # its own background thread, same pattern as the CICIDS network_loop.
    t = threading.Thread(target=collector.start, daemon=True)
    t.start()
    print("[run_all] Linux IDS collector started (bpftrace syscall capture,")
    print("[run_all]       wired through ThreatFusionEngine via LinuxIDSAdapter).")
    _running_handles["linux_ids"] = collector


# ===========================================================================
# Orchestration -- detect OS, print banner, start only what's compatible
# ===========================================================================

print_banner(OS_NAME, PROFILE_NAME, COMPATIBLE_COLLECTORS)

START_FNS = {
    "zero_day": start_zero_day,
    "cicids": start_cicids,
    "ember": start_ember,
    "hdfs": start_hdfs,
    "windows_advanced": start_windows_advanced,
    "linux_ids": start_linux_ids,
}

print("Starting telemetry collection...\n")
results = run_collectors(OS_NAME, START_FNS)

# ===========================================================================
# Keep running
# ===========================================================================

print("\n[run_all] All available collectors started. Press Ctrl+C to stop.\n")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[run_all] Stopping...")
    for name, handle in _running_handles.items():
        stop = getattr(handle, "stop", None)
        if callable(stop):
            try:
                stop()
            except Exception:
                pass
