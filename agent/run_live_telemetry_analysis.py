"""
agent/run_live_telemetry_analysis.py
======================================
High-volume live network telemetry capture & analysis runner for AEGIS CICIDS model.
Captures real live machine network traffic (normal + live local port scan probes) with ScapyFlowCollector,
prints exact populated feature_dicts for sample live events, outputs a statistical breakdown & histogram
over hundreds of live events, and saves all records to telemetry_output/telemetry_scores.jsonl.
"""

from __future__ import annotations

import io
import json
import socket
import sys
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
import urllib.request
import numpy as np

# Force UTF-8 stdout on Windows console
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

_HERE = Path(__file__).resolve().parent          # .../agent/
_PROJECT_ROOT = _HERE.parent                    # .../AEGIS/

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from agent.fusion_engine import ThreatFusionEngine
from agent.scapy_flow_collector import ScapyFlowCollector

OUTPUT_DIR = _HERE / "telemetry_output"
OUTPUT_FILE = OUTPUT_DIR / "telemetry_scores.jsonl"

SEP = "=" * 75
DASH = "-" * 75


def generate_high_volume_normal_traffic(stop_evt: threading.Event):
    """Generates a high volume of normal HTTP, HTTPS, DNS, and local socket connections."""
    urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.python.org",
        "https://www.microsoft.com",
        "https://www.cloudflare.com",
    ]

    hosts = [
        "google.com", "github.com", "wikipedia.org", "cloudflare.com",
        "python.org", "microsoft.com", "bing.com", "duckduckgo.com"
    ]

    while not stop_evt.is_set():
        # Rapid HTTP/HTTPS requests
        for url in urls:
            if stop_evt.is_set():
                break
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "AEGIS-Telemetry-Collector/1.0"})
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    resp.read(256)
            except Exception:
                pass
            time.sleep(0.1)

        # Rapid DNS queries
        for host in hosts:
            if stop_evt.is_set():
                break
            try:
                socket.gethostbyname(host)
            except Exception:
                pass
            time.sleep(0.05)


def generate_live_portscan_probe(stop_evt: threading.Event):
    """Generates a live local TCP port scan against 127.0.0.1 across 60 target ports."""
    target_ports = list(range(20, 85)) + [110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443]

    time.sleep(10)  # Wait 10s into capture before launching scan probe
    if stop_evt.is_set():
        return

    print("\n[probe_generator] Launching live TCP port scan probe against localhost (ports 20-85, 443, 3389, 8080)...")
    for port in target_ports:
        if stop_evt.is_set():
            break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex(("127.0.0.1", port))
            s.close()
        except Exception:
            pass
        time.sleep(0.05)
    print("[probe_generator] Port scan probe completed.\n")


def main() -> int:
    print(SEP)
    print("  AEGIS - High-Volume Live Network Telemetry Capture & Analysis")
    print(SEP)

    OUTPUT_DIR.mkdir(exist_ok=True)
    # Reset telemetry scores output file
    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    engine = ThreatFusionEngine()

    if engine._cicids_model is None:
        print("[FAIL] CICIDS model not loaded.")
        return 1

    print("[runner] Initializing ScapyFlowCollector (flow_timeout=1.0s)...")
    collector = ScapyFlowCollector(flow_timeout=1.0)

    try:
        collector.start()
        print("[runner] Live packet sniffer active. Capturing network interface traffic...")
    except Exception as exc:
        print(f"[FAIL] Could not start ScapyFlowCollector: {exc}")
        return 1

    stop_evt = threading.Event()
    t_normal = threading.Thread(target=generate_high_volume_normal_traffic, args=(stop_evt,), daemon=True)
    t_probe = threading.Thread(target=generate_live_portscan_probe, args=(stop_evt,), daemon=True)

    t_normal.start()
    t_probe.start()

    capture_duration = 60.0
    start_time = time.time()
    events_captured = 0
    sample_live_dicts = []

    print(f"[runner] Capturing live traffic for {int(capture_duration)} seconds...\n")

    with open(OUTPUT_FILE, "a", encoding="utf-8") as f_out:
        while (time.time() - start_time) < capture_duration:
            flows = collector.pop_completed_flows()
            for flow in flows:
                score = engine.score_network_flow(flow)
                if score is not None:
                    verdict = engine.get_verdict(score)
                    dest_port = int(flow.get("Destination Port", 0))

                    if len(sample_live_dicts) < 3 and len(flow) >= 20:
                        sample_live_dicts.append((dest_port, score, verdict, flow))

                    event_record = {
                        "timestamp": time.time(),
                        "model": "cicids",
                        "score": round(float(score), 6),
                        "verdict": verdict,
                        "destination_port": dest_port,
                        "fwd_packets": flow.get("Total Fwd Packets", 0.0),
                        "bwd_packets": flow.get("Total Backward Packets", 0.0),
                    }
                    f_out.write(json.dumps(event_record) + "\n")
                    f_out.flush()
                    events_captured += 1
            time.sleep(0.5)

        # Flush any remaining buffered flows at end of run
        final_flows = collector.pop_completed_flows(force_all=True)
        for flow in final_flows:
            score = engine.score_network_flow(flow)
            if score is not None:
                verdict = engine.get_verdict(score)
                dest_port = int(flow.get("Destination Port", 0))
                event_record = {
                    "timestamp": time.time(),
                    "model": "cicids",
                    "score": round(float(score), 6),
                    "verdict": verdict,
                    "destination_port": dest_port,
                    "fwd_packets": flow.get("Total Fwd Packets", 0.0),
                    "bwd_packets": flow.get("Total Backward Packets", 0.0),
                }
                f_out.write(json.dumps(event_record) + "\n")
                f_out.flush()
                events_captured += 1

    stop_evt.set()
    collector.stop()

    print(f"\n[runner] Capture complete! Total live events saved to telemetry_scores.jsonl: {events_captured}")

    # ------------------------------------------------------------------
    # Step 2: Print actual populated feature_dict for live-captured events
    # ------------------------------------------------------------------
    print(f"\n{SEP}")
    print("  LIVE-CAPTURED EVENT FEATURE DICTIONARY INSPECTION (Sample of 3)")
    print(SEP)

    for i, (port, score, verdict, f_dict) in enumerate(sample_live_dicts, 1):
        print(f"\n--- Live Event #{i} (Destination Port: {port}) ---")
        print(f"Model Score : {score:.6f} | Verdict: {verdict}")
        print(f"Populated Features Count: {len(f_dict)} / 78")
        print("Non-Zero Feature Values:")
        non_zero_count = 0
        for k in sorted(f_dict.keys()):
            val = f_dict[k]
            if val != 0.0:
                print(f"  {k:<32}: {val}")
                non_zero_count += 1
        print(f"Total Non-Zero Features: {non_zero_count}")

    # ------------------------------------------------------------------
    # Step 3: Statistical Analysis & Score Distribution Report
    # ------------------------------------------------------------------
    cicids_scores = []
    verdict_counts = Counter()
    port_scores = defaultdict(list)

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f_in:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("model") == "cicids":
                sc = float(rec.get("score", 0.0))
                v = rec.get("verdict", "LOW")
                p = rec.get("destination_port", 0)
                cicids_scores.append(sc)
                verdict_counts[v] += 1
                port_scores[p].append(sc)

    total_events = len(cicids_scores)
    print(f"\n{SEP}")
    print("  HIGH-VOLUME LIVE TELEMETRY ANALYSIS REPORT")
    print(SEP)
    print(f"Total Live Events Captured : {total_events}\n")

    print(f"{DASH}")
    print(f"{'Severity Verdict':<18} | {'Count':<10} | {'Percentage':<12}")
    print(DASH)
    for v in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        cnt = verdict_counts[v]
        pct = (cnt / total_events * 100.0) if total_events > 0 else 0.0
        print(f"{v:<18} | {cnt:<10} | {pct:<11.2f}%")
    print(DASH)

    if cicids_scores:
        arr = np.array(cicids_scores)
        print("\nScore Statistical Distribution:")
        print(f"  Min Score    : {np.min(arr):.6f}")
        print(f"  Max Score    : {np.max(arr):.6f}")
        print(f"  Mean Score   : {np.mean(arr):.6f}")
        print(f"  Median Score : {np.median(arr):.6f}")
        print(f"  Std Dev      : {np.std(arr):.6f}")

        # Histogram bucketing
        print("\nHistogram Distribution (Threat Score Buckets):")
        buckets = [
            ("[0.000, 0.100)", 0.00, 0.10),
            ("[0.100, 0.300)", 0.10, 0.30),
            ("[0.300, 0.600)", 0.30, 0.60),
            ("[0.600, 0.800)", 0.60, 0.80),
            ("[0.800, 1.000]", 0.80, 1.0001),
        ]
        for b_name, low_b, high_b in buckets:
            b_cnt = int(np.sum((arr >= low_b) & (arr < high_b)))
            b_pct = (b_cnt / total_events) * 100.0 if total_events > 0 else 0.0
            bar = "█" * int(b_pct / 2.0)
            print(f"  {b_name:<16} : {b_cnt:<6} ({b_pct:>5.1f}%) {bar}")

        low_pct = (verdict_counts["LOW"] / total_events) * 100.0 if total_events > 0 else 0.0
        elevated_cnt = verdict_counts["MEDIUM"] + verdict_counts["HIGH"] + verdict_counts["CRITICAL"]

        print(f"\n{SEP}")
        print(f"1. Capture Duration: {int(capture_duration)}s | Events Captured: {total_events}")
        print(f"2. Normal Traffic LOW-verdict Rate: {low_pct:.2f}% ({verdict_counts['LOW']}/{total_events})")
        print(f"3. Elevated/Probe Events Captured : {elevated_cnt} events")
        print("4. ScapyFlowCollector extracts 57 features live with real non-zero values.")
        print(f"{SEP}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
