"""
agent/run_all.py
=================
AEGIS - Final wiring script: starts every collector relevant to a Windows
machine (Linux IDS is skipped -- N/A on Windows) and prints live scored
verdicts from ThreatFusionEngine for each one.

Place this file in the same agent/ folder as fusion_engine.py and
live_collectors.py, then run:

    python run_all.py

WHAT WILL WORK IMMEDIATELY (no extra setup):
    - Zero-Day      (already proven working in your terminal)
    - CICIDS        (model file confirmed present -- should now load)

    - EMBER         (fixed -- was gated behind a broken `import ember`; now
                     uses ember_features.py, place it in agent/ alongside
                     this file. Just needs PE_WATCH_DIR below to exist.)

WHAT NEEDS ONE-TIME SETUP FIRST (instructions printed at startup if missing):
    - HDFS          -> point HDFS_LOG_PATH below at a real log file
    - Windows Adv.  -> install + configure Sysmon first (see docstring)
"""
from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fusion_engine import ThreatFusionEngine  # noqa: E402
from live_collectors import (  # noqa: E402
    ZeroDayEventCollector,
    PEFileCollector,
    HDFSLogCollector,
    WindowsAPICollector,
)
from scapy_flow_collector import ScapyFlowCollector  # noqa: E402
from watchdog.observers import Observer  # noqa: E402

# ---------------------------------------------------------------------------
# EDIT THESE PATHS for your machine before running EMBER / HDFS collectors
# ---------------------------------------------------------------------------
PE_WATCH_DIR = r"C:\Users\%USERNAME%\Downloads"   # where new .exe/.dll files show up
HDFS_LOG_PATH = str(Path(__file__).resolve().parent / "test.log")

engine = ThreatFusionEngine()
print("[run_all] ThreatFusionEngine initialised. Check the [loader] lines above")
print("[run_all] for 'Loaded X' vs 'Missing artefact' / 'Failed to load' per model.\n")

# ---------------------------------------------------------------------------
# JSONL output -- every scored event (from every model) is appended here,
# one JSON object per line, in addition to being printed to the console.
# ---------------------------------------------------------------------------
OUTPUT_DIR = Path(__file__).resolve().parent / "telemetry_output"
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


# ===========================================================================
# 1. Zero-Day -- works immediately, no setup
# ===========================================================================

def handle_zeroday_event(event_id, process_name, user_name, ip):
    score = engine.score_windows_event(event_id, process_name, user_name, ip)
    if score is None:
        return
    verdict = engine.get_verdict(score)
    print(f"[zero_day]   {process_name:<30} ({user_name}@{ip}) -> {score:.3f} ({verdict})")
    save_event("zero_day", score, verdict, process_name=process_name, user_name=user_name, ip=ip)


zday = ZeroDayEventCollector(on_event=handle_zeroday_event)
zday.start(poll_interval=2.0)


# ===========================================================================
# 2. CICIDS -- now using scapy for REAL packet/byte counts (fixes the
#    "flow not extracted correctly" issue -- old version hardcoded these to 0)
# ===========================================================================
# NOTE: requires Administrator + Npcap installed (https://npcap.com/#download)

net_collector = ScapyFlowCollector(flow_timeout=2.0)

try:
    net_collector.start()
    print("[run_all] CICIDS scapy sniffer started (real packet/byte counts).")
except Exception as exc:
    print(f"[run_all] CICIDS scapy sniffer FAILED to start: {exc}")
    print("[run_all] Fix: run as Administrator, and install Npcap.")


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
# 3. EMBER -- needs `pip install ember` (or the package used in ember.ipynb)
#    and a real folder to watch for new/modified .exe/.dll files.
# ===========================================================================

def handle_pe_features(pe_features: dict, meta: dict):
    score = engine.score_file(pe_features)
    if score is not None:
        verdict = engine.get_verdict(score)
        fname = Path(meta["file_path"]).name
        print(f"[ember]      {fname:<25} sha256={meta['sha256'][:12]}... -> {score:.3f} ({verdict})")
        save_event("ember", score, verdict, file_path=meta["file_path"], sha256=meta["sha256"])


pe_dir = Path(PE_WATCH_DIR.replace("%USERNAME%", Path.home().name))
if pe_dir.exists():
    pe_collector = PEFileCollector(
        on_new_pe_features=handle_pe_features,
        feature_names=getattr(engine, "_ember_features", None),
    )
    pe_observer = Observer()
    pe_observer.schedule(pe_collector, path=str(pe_dir), recursive=False)
    pe_observer.start()
    print(f"[run_all] EMBER collector watching: {pe_dir}")
else:
    print(f"[run_all] EMBER SKIPPED -- watch folder does not exist: {pe_dir}")
    print("[run_all] Fix: create that folder, or edit PE_WATCH_DIR at the top of this file.")


# ===========================================================================
# 4. HDFS -- needs a real log file path set in HDFS_LOG_PATH above.
# ===========================================================================

def handle_block_text(raw_text: str):
    score = engine.score_log_line(raw_text)
    if score is not None:
        verdict = engine.get_verdict(score)
        print(f"[hdfs]       block scored -> {score:.3f} ({verdict})")
        save_event("hdfs", score, verdict)


hdfs_path = Path(HDFS_LOG_PATH)
if hdfs_path.exists():
    hdfs_collector = HDFSLogCollector(on_block_text=handle_block_text)
    hdfs_collector.start_flush_thread()
    hdfs_observer = Observer()
    hdfs_observer.schedule(hdfs_collector, path=str(hdfs_path.parent), recursive=False)
    hdfs_observer.start()
    print(f"[run_all] HDFS collector watching: {hdfs_path}")
else:
    print(f"[run_all] HDFS SKIPPED -- set HDFS_LOG_PATH to a real file (currently: {HDFS_LOG_PATH})")


# ===========================================================================
# 5. Windows Advanced -- needs Sysmon installed + configured first.
#    Download: https://learn.microsoft.com/sysinternals/downloads/sysmon
#    Install:  sysmon64.exe -accepteula -i  (as Administrator)
#    This logs to "Microsoft-Windows-Sysmon/Operational" -- once that exists,
#    WindowsAPICollector reads it automatically. No path to edit here.
# ===========================================================================

try:
    win_collector = WindowsAPICollector()
    win_collector.start()
    print("[run_all] Windows Advanced collector started (reading Sysmon log).")
    print("[run_all] NOTE: scoring for this model requires wiring get_sequence(pid)")
    print("[run_all]       into score_process_event(api_call_sequence=...) per PID --")
    print("[run_all]       not auto-looped here since it needs a specific PID to watch.")
except Exception as exc:
    print(f"[run_all] Windows Advanced SKIPPED -- {exc}")
    print("[run_all] Install Sysmon first: https://learn.microsoft.com/sysinternals/downloads/sysmon")


# ===========================================================================
# Keep running
# ===========================================================================

print("\n[run_all] All available collectors started. Press Ctrl+C to stop.\n")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[run_all] Stopping...")
    zday.stop()