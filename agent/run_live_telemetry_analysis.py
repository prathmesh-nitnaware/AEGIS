"""
agent/run_live_telemetry_analysis.py
=====================================

AEGIS live network telemetry capture & analysis runner.

Features:
- Captures live traffic using ScapyFlowCollector.
- Uses CICIDS LightGBM model for individual network-flow scoring.
- Adds a short-window multi-port behavior detector for PortScan activity.
- Keeps CICIDS model score and AEGIS final score separate.
- Prints populated 78-feature dictionaries for sample events.
- Saves telemetry results to telemetry_output/telemetry_scores.jsonl.

PortScan behavior:
    Many different destination ports observed within a short time window
    are treated as a PortScan pattern.

This does NOT modify or fake the CICIDS model.
"""

from __future__ import annotations

import io
import json
import socket
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from pathlib import Path
import urllib.request

import numpy as np


# ==============================================================
# FORCE UTF-8 OUTPUT ON WINDOWS
# ==============================================================

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer,
        encoding="utf-8",
        errors="replace"
    )


# ==============================================================
# PROJECT PATHS
# ==============================================================

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))


# ==============================================================
# AEGIS IMPORTS
# ==============================================================

from agent.fusion_engine import ThreatFusionEngine
from agent.scapy_flow_collector import ScapyFlowCollector


# ==============================================================
# OUTPUT
# ==============================================================

OUTPUT_DIR = _HERE / "telemetry_output"
OUTPUT_FILE = OUTPUT_DIR / "telemetry_scores.jsonl"

SEP = "=" * 75
DASH = "-" * 75


# ==============================================================
# PORTSCAN BEHAVIOR SETTINGS
# ==============================================================

# Time window used to detect scanning behavior.
PORTSCAN_WINDOW_SECONDS = 5.0

# Number of different destination ports required
# inside the window before we call it a PortScan.
PORTSCAN_UNIQUE_PORT_THRESHOLD = 10

# Score assigned to a detected PortScan behavior.
# This is the AEGIS behavioral score, NOT the CICIDS model probability.
PORTSCAN_BASE_SCORE = 0.85


# ==============================================================
# NORMAL TRAFFIC GENERATOR
# ==============================================================

def generate_high_volume_normal_traffic(
    stop_evt: threading.Event
):
    """
    Generates normal HTTP/HTTPS, DNS and local socket traffic.
    """

    urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.python.org",
        "https://www.microsoft.com",
        "https://www.cloudflare.com",
    ]

    hosts = [
        "google.com",
        "github.com",
        "wikipedia.org",
        "cloudflare.com",
        "python.org",
        "microsoft.com",
        "bing.com",
        "duckduckgo.com",
    ]

    while not stop_evt.is_set():

        # ----------------------------------------------------------
        # HTTP / HTTPS
        # ----------------------------------------------------------

        for url in urls:

            if stop_evt.is_set():
                break

            try:

                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent":
                        "AEGIS-Telemetry-Collector/1.0"
                    }
                )

                with urllib.request.urlopen(
                    req,
                    timeout=1.5
                ) as resp:

                    resp.read(256)

            except Exception:
                pass

            time.sleep(0.1)

        # ----------------------------------------------------------
        # DNS
        # ----------------------------------------------------------

        for host in hosts:

            if stop_evt.is_set():
                break

            try:
                socket.gethostbyname(host)

            except Exception:
                pass

            time.sleep(0.05)


# ==============================================================
# LIVE PORTSCAN PROBE
# ==============================================================

def generate_live_portscan_probe(
    stop_evt: threading.Event
):
    """
    Generates a local TCP port scan against 127.0.0.1.

    The probe is intentionally limited to localhost.
    """

    target_ports = (
        list(range(20, 85))
        +
        [
            110,
            143,
            443,
            445,
            993,
            995,
            1433,
            1521,
            3306,
            3389,
            5432,
            8080,
            8443,
        ]
    )

    # Wait until the collector is already capturing normal traffic.
    time.sleep(10)

    if stop_evt.is_set():
        return

    print(
        "\n[probe_generator] "
        "Launching live TCP port scan probe against localhost "
        "(ports 20-85 + common ports)..."
    )

    for port in target_ports:

        if stop_evt.is_set():
            break

        try:

            s = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            s.settimeout(0.1)

            s.connect_ex(
                ("127.0.0.1", port)
            )

            s.close()

        except Exception:
            pass

        # Small delay so Scapy sees individual scan attempts.
        time.sleep(0.05)

    print(
        "[probe_generator] "
        "Port scan probe completed.\n"
    )


# ==============================================================
# PORTSCAN BEHAVIOR DETECTOR
# ==============================================================

class PortScanBehaviorDetector:
    """
    Detects multi-port scanning behavior.

    Important:
        The CICIDS model works on individual flows.

        This detector works across multiple flows.

    Example:

        port 20
        port 21
        port 22
        ...
        port 84

    inside 5 seconds

        -> PortScan behavior
    """

    def __init__(
        self,
        window_seconds: float = PORTSCAN_WINDOW_SECONDS,
        unique_port_threshold: int = PORTSCAN_UNIQUE_PORT_THRESHOLD,
    ):

        self.window_seconds = window_seconds
        self.unique_port_threshold = unique_port_threshold

        # Stores:
        # (timestamp, destination_port)
        self.events = deque()

        self.detected = False
        self.detected_at = 0.0
        self.detected_port_count = 0

    def update(
        self,
        destination_port: int,
        timestamp: float | None = None,
    ):
        """
        Add a flow's destination port and evaluate
        the recent multi-port behavior.

        Returns:
            {
                "detected": bool,
                "unique_ports": int,
                "score": float
            }
        """

        if timestamp is None:
            timestamp = time.time()

        # ----------------------------------------------------------
        # Add current event
        # ----------------------------------------------------------

        self.events.append(
            (
                timestamp,
                int(destination_port)
            )
        )

        # ----------------------------------------------------------
        # Remove events outside time window
        # ----------------------------------------------------------

        cutoff = timestamp - self.window_seconds

        while (
            self.events
            and self.events[0][0] < cutoff
        ):
            self.events.popleft()

        # ----------------------------------------------------------
        # Count unique destination ports
        # ----------------------------------------------------------

        unique_ports = {
            port
            for _, port in self.events
            if port > 0
        }

        unique_count = len(unique_ports)

        # ----------------------------------------------------------
        # PortScan decision
        # ----------------------------------------------------------

        is_portscan = (
            unique_count
            >= self.unique_port_threshold
        )

        if is_portscan:

            self.detected = True
            self.detected_at = timestamp
            self.detected_port_count = unique_count

        # ----------------------------------------------------------
        # Behavioral score
        # ----------------------------------------------------------

        if is_portscan:

            # 10 ports -> 0.85
            # 20 ports -> 0.95
            # 30+ ports -> 0.99

            extra_ports = (
                unique_count
                - self.unique_port_threshold
            )

            behavior_score = min(
                0.99,
                PORTSCAN_BASE_SCORE
                + (extra_ports * 0.01)
            )

        else:

            behavior_score = 0.0

        return {
            "detected": is_portscan,
            "unique_ports": unique_count,
            "score": behavior_score,
        }


# ==============================================================
# MAIN
# ==============================================================

def main() -> int:

    print(SEP)
    print(
        "  AEGIS - Live Network Telemetry "
        "& PortScan Behavior Analysis"
    )
    print(SEP)

    # ----------------------------------------------------------
    # OUTPUT DIRECTORY
    # ----------------------------------------------------------

    OUTPUT_DIR.mkdir(
        exist_ok=True
    )

    # Reset previous telemetry output.
    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    # ----------------------------------------------------------
    # LOAD AEGIS ENGINE
    # ----------------------------------------------------------

    print(
        "[runner] Loading AEGIS ThreatFusionEngine..."
    )

    engine = ThreatFusionEngine()

    if engine._cicids_model is None:

        print(
            "[FAIL] CICIDS model not loaded."
        )

        return 1

    print(
        "[runner] CICIDS model loaded successfully."
    )

    # ----------------------------------------------------------
    # PORTSCAN DETECTOR
    # ----------------------------------------------------------

    portscan_detector = PortScanBehaviorDetector(
        window_seconds=PORTSCAN_WINDOW_SECONDS,
        unique_port_threshold=PORTSCAN_UNIQUE_PORT_THRESHOLD,
    )

    print(
        "[runner] PortScan behavior detector enabled:"
    )

    print(
        f"         Window       : "
        f"{PORTSCAN_WINDOW_SECONDS:.1f} seconds"
    )

    print(
        f"         Port threshold: "
        f"{PORTSCAN_UNIQUE_PORT_THRESHOLD} unique ports"
    )

    # ----------------------------------------------------------
    # SCAPY FLOW COLLECTOR
    # ----------------------------------------------------------

    print(
        "\n[runner] Initializing ScapyFlowCollector "
        "(flow_timeout=1.0s)..."
    )

    collector = ScapyFlowCollector(
        flow_timeout=1.0,
        idle_threshold=1.0,
        iface=r"\Device\NPF_Loopback",
    )

    try:

        collector.start()

        print(
            "[runner] Live packet sniffer active."
        )

        print(
            "[runner] Interface: "
            r"\Device\NPF_Loopback"
        )

    except Exception as exc:

        print(
            f"[FAIL] Could not start "
            f"ScapyFlowCollector: {exc}"
        )

        return 1

    # ----------------------------------------------------------
    # THREADS
    # ----------------------------------------------------------

    stop_evt = threading.Event()

    t_normal = threading.Thread(
        target=generate_high_volume_normal_traffic,
        args=(stop_evt,),
        daemon=True,
    )

    t_probe = threading.Thread(
        target=generate_live_portscan_probe,
        args=(stop_evt,),
        daemon=True,
    )

    t_normal.start()
    t_probe.start()

    # ----------------------------------------------------------
    # CAPTURE SETTINGS
    # ----------------------------------------------------------

    capture_duration = 30.0

    start_time = time.time()

    events_captured = 0

    portscan_events = 0

    sample_live_dicts = []

    print(
        f"\n[runner] Capturing live traffic "
        f"for {int(capture_duration)} seconds...\n"
    )

    # ----------------------------------------------------------
    # OPEN OUTPUT
    # ----------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "a",
        encoding="utf-8"
    ) as f_out:

        # ======================================================
        # LIVE CAPTURE LOOP
        # ======================================================

        while (
            time.time() - start_time
            < capture_duration
        ):

            flows = (
                collector.pop_completed_flows()
            )

            for flow in flows:

                # --------------------------------------------------
                # 1. ORIGINAL CICIDS MODEL SCORE
                # --------------------------------------------------

                cicids_score = (
                    engine.score_network_flow(
                        flow
                    )
                )

                if cicids_score is None:
                    continue

                cicids_score = float(
                    cicids_score
                )

                # --------------------------------------------------
                # 2. DESTINATION PORT
                # --------------------------------------------------

                dest_port = int(
                    flow.get(
                        "Destination Port",
                        0
                    )
                )

                # --------------------------------------------------
                # 3. PORTSCAN BEHAVIOR ANALYSIS
                # --------------------------------------------------

                behavior = (
                    portscan_detector.update(
                        destination_port=dest_port,
                        timestamp=time.time(),
                    )
                )

                behavior_detected = (
                    behavior["detected"]
                )

                behavior_score = float(
                    behavior["score"]
                )

                unique_ports = int(
                    behavior["unique_ports"]
                )

                # --------------------------------------------------
                # 4. FINAL AEGIS SCORE
                # --------------------------------------------------
                #
                # Normal flow:
                #     final = CICIDS score
                #
                # PortScan:
                #     final = max(CICIDS, behavior score)
                #
                # This means we do NOT modify the CICIDS model.
                #

                final_score = max(
                    cicids_score,
                    behavior_score
                )

                final_score = min(
                    1.0,
                    max(0.0, final_score)
                )

                # --------------------------------------------------
                # 5. FINAL VERDICT
                # --------------------------------------------------

                verdict = engine.get_verdict(
                    final_score
                )

                # --------------------------------------------------
                # 6. SAMPLE LIVE FEATURE DICTS
                # --------------------------------------------------

                if (
                    len(sample_live_dicts) < 3
                    and len(flow) >= 20
                ):

                    sample_live_dicts.append(
                        (
                            dest_port,
                            cicids_score,
                            final_score,
                            verdict,
                            flow,
                        )
                    )

                # --------------------------------------------------
                # 7. PORTSCAN PRINT
                # --------------------------------------------------

                if behavior_detected:

                    portscan_events += 1

                    print(
                        "\n"
                        + "!" * 75
                    )

                    print(
                        "  🚨 PORTSCAN BEHAVIOR DETECTED"
                    )

                    print(
                        "!" * 75
                    )

                    print(
                        f"  Destination Port : "
                        f"{dest_port}"
                    )

                    print(
                        f"  Unique Ports     : "
                        f"{unique_ports}"
                    )

                    print(
                        f"  Time Window      : "
                        f"{PORTSCAN_WINDOW_SECONDS:.1f}s"
                    )

                    print(
                        f"  CICIDS Score     : "
                        f"{cicids_score:.6f}"
                    )

                    print(
                        f"  Behavior Score   : "
                        f"{behavior_score:.6f}"
                    )

                    print(
                        f"  FINAL AEGIS SCORE: "
                        f"{final_score:.6f}"
                    )

                    print(
                        f"  FINAL VERDICT    : "
                        f"{verdict}"
                    )

                    print(
                        "!" * 75
                    )

                # --------------------------------------------------
                # 8. SAVE EVENT
                # --------------------------------------------------

                event_record = {

                    "timestamp":
                        time.time(),

                    "model":
                        "cicids",

                    # Original ML score
                    "cicids_score":
                        round(
                            cicids_score,
                            6
                        ),

                    # Behavioral score
                    "portscan_behavior_score":
                        round(
                            behavior_score,
                            6
                        ),

                    # Final AEGIS score
                    "score":
                        round(
                            final_score,
                            6
                        ),

                    "verdict":
                        verdict,

                    "destination_port":
                        dest_port,

                    "unique_ports_in_window":
                        unique_ports,

                    "portscan_detected":
                        behavior_detected,

                    "portscan_window_seconds":
                        PORTSCAN_WINDOW_SECONDS,

                    "fwd_packets":
                        flow.get(
                            "Total Fwd Packets",
                            0.0
                        ),

                    "bwd_packets":
                        flow.get(
                            "Total Backward Packets",
                            0.0
                        ),
                }

                f_out.write(
                    json.dumps(
                        event_record
                    )
                    + "\n"
                )

                f_out.flush()

                events_captured += 1

            time.sleep(0.5)

        # ======================================================
        # FLUSH REMAINING FLOWS
        # ======================================================

        final_flows = (
            collector.pop_completed_flows(
                force_all=True
            )
        )

        for flow in final_flows:

            cicids_score = (
                engine.score_network_flow(
                    flow
                )
            )

            if cicids_score is None:
                continue

            cicids_score = float(
                cicids_score
            )

            dest_port = int(
                flow.get(
                    "Destination Port",
                    0
                )
            )

            behavior = (
                portscan_detector.update(
                    destination_port=dest_port,
                    timestamp=time.time(),
                )
            )

            behavior_score = float(
                behavior["score"]
            )

            final_score = max(
                cicids_score,
                behavior_score
            )

            final_score = min(
                1.0,
                max(0.0, final_score)
            )

            verdict = engine.get_verdict(
                final_score
            )

            event_record = {

                "timestamp":
                    time.time(),

                "model":
                    "cicids",

                "cicids_score":
                    round(
                        cicids_score,
                        6
                    ),

                "portscan_behavior_score":
                    round(
                        behavior_score,
                        6
                    ),

                "score":
                    round(
                        final_score,
                        6
                    ),

                "verdict":
                    verdict,

                "destination_port":
                    dest_port,

                "unique_ports_in_window":
                    int(
                        behavior["unique_ports"]
                    ),

                "portscan_detected":
                    bool(
                        behavior["detected"]
                    ),

                "portscan_window_seconds":
                    PORTSCAN_WINDOW_SECONDS,

                "fwd_packets":
                    flow.get(
                        "Total Fwd Packets",
                        0.0
                    ),

                "bwd_packets":
                    flow.get(
                        "Total Backward Packets",
                        0.0
                    ),
            }

            f_out.write(
                json.dumps(
                    event_record
                )
                + "\n"
            )

            f_out.flush()

            events_captured += 1

    # ----------------------------------------------------------
    # STOP EVERYTHING
    # ----------------------------------------------------------

    stop_evt.set()

    collector.stop()

    print(
        f"\n[runner] Capture complete!"
    )

    print(
        f"[runner] Total live events saved: "
        f"{events_captured}"
    )

    print(
        f"[runner] PortScan behavior events: "
        f"{portscan_events}"
    )

    # ==========================================================
    # STEP 2
    # LIVE FEATURE DICTIONARY INSPECTION
    # ==========================================================

    print(f"\n{SEP}")

    print(
        "  LIVE-CAPTURED EVENT FEATURE "
        "DICTIONARY INSPECTION"
    )

    print(SEP)

    for i, (
        port,
        cicids_score,
        final_score,
        verdict,
        f_dict,
    ) in enumerate(
        sample_live_dicts,
        1
    ):

        print(
            f"\n--- Live Event #{i} "
            f"(Destination Port: {port}) ---"
        )

        print(
            f"CICIDS Model Score : "
            f"{cicids_score:.6f}"
        )

        print(
            f"Final AEGIS Score  : "
            f"{final_score:.6f}"
        )

        print(
            f"Final Verdict      : "
            f"{verdict}"
        )

        print(
            f"Populated Features Count: "
            f"{len(f_dict)} / 78"
        )

        print(
            "Non-Zero Feature Values:"
        )

        non_zero_count = 0

        for k in sorted(
            f_dict.keys()
        ):

            val = f_dict[k]

            if val != 0.0:

                print(
                    f"  {k:<32}: {val}"
                )

                non_zero_count += 1

        print(
            f"Total Non-Zero Features: "
            f"{non_zero_count}"
        )

    # ==========================================================
    # STEP 3
    # STATISTICAL REPORT
    # ==========================================================

    cicids_scores = []

    final_scores = []

    verdict_counts = Counter()

    port_scores = defaultdict(list)

    portscan_detected_count = 0

    # ----------------------------------------------------------
    # READ OUTPUT
    # ----------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "r",
        encoding="utf-8"
    ) as f_in:

        for line in f_in:

            line = line.strip()

            if not line:
                continue

            rec = json.loads(
                line
            )

            if rec.get(
                "model"
            ) != "cicids":
                continue

            cicids_sc = float(
                rec.get(
                    "cicids_score",
                    rec.get(
                        "score",
                        0.0
                    )
                )
            )

            final_sc = float(
                rec.get(
                    "score",
                    0.0
                )
            )

            verdict = rec.get(
                "verdict",
                "LOW"
            )

            port = rec.get(
                "destination_port",
                0
            )

            cicids_scores.append(
                cicids_sc
            )

            final_scores.append(
                final_sc
            )

            verdict_counts[
                verdict
            ] += 1

            port_scores[
                port
            ].append(
                final_sc
            )

            if rec.get(
                "portscan_detected",
                False
            ):
                portscan_detected_count += 1

    total_events = len(
        final_scores
    )

    # ==========================================================
    # FINAL REPORT
    # ==========================================================

    print(f"\n{SEP}")

    print(
        "  HIGH-VOLUME LIVE TELEMETRY "
        "ANALYSIS REPORT"
    )

    print(SEP)

    print(
        f"Total Live Events Captured : "
        f"{total_events}"
    )

    print(
        f"PortScan Behavior Events   : "
        f"{portscan_detected_count}"
    )

    print(
        f"PortScan Window            : "
        f"{PORTSCAN_WINDOW_SECONDS:.1f}s"
    )

    print(
        f"PortScan Port Threshold    : "
        f"{PORTSCAN_UNIQUE_PORT_THRESHOLD}"
    )

    print(f"\n{DASH}")

    print(
        f"{'Severity Verdict':<18} | "
        f"{'Count':<10} | "
        f"{'Percentage':<12}"
    )

    print(DASH)

    for v in [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]:

        cnt = verdict_counts[v]

        pct = (
            cnt
            / total_events
            * 100.0
        ) if total_events > 0 else 0.0

        print(
            f"{v:<18} | "
            f"{cnt:<10} | "
            f"{pct:<11.2f}%"
        )

    print(DASH)

    # ==========================================================
    # SCORE STATISTICS
    # ==========================================================

    if final_scores:

        final_arr = np.array(
            final_scores
        )

        cicids_arr = np.array(
            cicids_scores
        )

        print(
            "\nOriginal CICIDS Model "
            "Score Distribution:"
        )

        print(
            f"  Min Score    : "
            f"{np.min(cicids_arr):.6f}"
        )

        print(
            f"  Max Score    : "
            f"{np.max(cicids_arr):.6f}"
        )

        print(
            f"  Mean Score   : "
            f"{np.mean(cicids_arr):.6f}"
        )

        print(
            f"  Median Score : "
            f"{np.median(cicids_arr):.6f}"
        )

        print(
            "\nFinal AEGIS Score Distribution:"
        )

        print(
            f"  Min Score    : "
            f"{np.min(final_arr):.6f}"
        )

        print(
            f"  Max Score    : "
            f"{np.max(final_arr):.6f}"
        )

        print(
            f"  Mean Score   : "
            f"{np.mean(final_arr):.6f}"
        )

        print(
            f"  Median Score : "
            f"{np.median(final_arr):.6f}"
        )

        print(
            f"  Std Dev      : "
            f"{np.std(final_arr):.6f}"
        )

        # ======================================================
        # HISTOGRAM
        # ======================================================

        print(
            "\nHistogram Distribution "
            "(Final AEGIS Threat Score):"
        )

        buckets = [

            (
                "[0.000, 0.100)",
                0.00,
                0.10
            ),

            (
                "[0.100, 0.300)",
                0.10,
                0.30
            ),

            (
                "[0.300, 0.600)",
                0.30,
                0.60
            ),

            (
                "[0.600, 0.800)",
                0.60,
                0.80
            ),

            (
                "[0.800, 1.000]",
                0.80,
                1.0001
            ),
        ]

        for (
            b_name,
            low_b,
            high_b,
        ) in buckets:

            b_cnt = int(
                np.sum(
                    (
                        final_arr
                        >= low_b
                    )
                    &
                    (
                        final_arr
                        < high_b
                    )
                )
            )

            b_pct = (
                b_cnt
                / total_events
                * 100.0
            ) if total_events > 0 else 0.0

            bar = (
                "█"
                * int(
                    b_pct / 2.0
                )
            )

            print(
                f"  {b_name:<16} : "
                f"{b_cnt:<6} "
                f"({b_pct:>5.1f}%) "
                f"{bar}"
            )

        # ======================================================
        # SUMMARY
        # ======================================================

        low_pct = (
            verdict_counts["LOW"]
            / total_events
            * 100.0
        ) if total_events > 0 else 0.0

        elevated_cnt = (
            verdict_counts["MEDIUM"]
            +
            verdict_counts["HIGH"]
            +
            verdict_counts["CRITICAL"]
        )

        print(f"\n{SEP}")

        print(
            f"1. Capture Duration: "
            f"{int(capture_duration)}s"
        )

        print(
            f"2. Events Captured: "
            f"{total_events}"
        )

        print(
            f"3. Normal/LOW Verdict Rate: "
            f"{low_pct:.2f}%"
        )

        print(
            f"4. Elevated Events: "
            f"{elevated_cnt}"
        )

        print(
            "5. ScapyFlowCollector extracts "
            "78 CICIDS features live."
        )

        print(
            "6. CICIDS LightGBM score is kept "
            "separate from behavioral score."
        )

        print(
            "7. Multi-port PortScan behavior "
            "is detected across individual flows."
        )

        print(
            f"8. PortScan detections: "
            f"{portscan_detected_count}"
        )

        print(SEP)

    return 0


# ==============================================================
# ENTRY POINT
# ==============================================================

if __name__ == "__main__":
    sys.exit(main())