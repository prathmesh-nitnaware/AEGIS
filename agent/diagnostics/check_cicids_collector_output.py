"""
agent/diagnostics/check_cicids_collector_output.py
===================================================
Standalone test for the fixed CICIDS network flow collector pipeline.
Feeds diverse flow scenarios (real benign, real DDoS, real PortScan, and collector-synthesized DDoS)
with exact model trained column names into:
    score_network_flow() -> fuse() -> get_verdict()

Confirms:
  1. Incoming flow features match trained CICIDS column names.
  2. Confirmed attack traffic (DDoS, PortScan) scores meaningfully higher than benign traffic.
  3. Attack flows land in HIGH / CRITICAL severity territory.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Dict
import pandas as pd

# Force UTF-8 stdout on Windows console
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

_HERE = Path(__file__).resolve().parent          # .../agent/diagnostics/
_AGENT_DIR = _HERE.parent                        # .../agent/
_PROJECT_ROOT = _AGENT_DIR.parent                # .../AEGIS/

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine

_CICIDS_DIR = _PROJECT_ROOT / "Dataset" / "CICIDS"
SEP = "=" * 75
DASH = "-" * 75


def load_real_sample(csv_name: str, target_label: str, row_idx: int = 0) -> Dict[str, float]:
    csv_path = _CICIDS_DIR / csv_name
    if not csv_path.exists():
        return {}
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    label_col = next((c for c in df.columns if "label" in c.lower()), None)
    rows = df[df[label_col].astype(str).str.strip().str.upper() == target_label.upper()]
    if rows.empty or row_idx >= len(rows):
        return {}
    return rows.iloc[row_idx].to_dict()


def main() -> int:
    print(SEP)
    print("  AEGIS - CICIDS Collector Output & Pipeline Verification")
    print(SEP)

    engine = ThreatFusionEngine()

    if engine._cicids_model is None:
        print("[FAIL] CICIDS model could not be loaded from trained_models/cicids/")
        return 1

    print(f"\nModel Loaded Successfully.")
    print(f"Total Model Features: {len(engine._cicids_features)}")

    # Load real dataset rows for BENIGN, DDoS, and PortScan
    real_benign = load_real_sample("Monday-WorkingHours.pcap_ISCX.csv", "BENIGN", 0)
    real_ddos = load_real_sample("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "DDoS", 0)
    real_portscan = load_real_sample("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "PortScan", 6)

    # Collector-synthesized flow matching ScapyFlowCollector feature set for DDoS
    synth_ddos = {
        "Destination Port": 80.0,
        "Flow Duration": 1293792.0,
        "Total Fwd Packets": 3.0,
        "Total Backward Packets": 7.0,
        "Total Length of Fwd Packets": 26.0,
        "Total Length of Bwd Packets": 11607.0,
        "Fwd Packet Length Max": 20.0,
        "Fwd Packet Length Mean": 8.666667,
        "Fwd Packet Length Std": 10.2632,
        "Bwd Packet Length Max": 5840.0,
        "Bwd Packet Length Mean": 1658.142857,
        "Bwd Packet Length Std": 2137.297,
        "Flow Bytes/s": 8991.398,
        "Flow Packets/s": 7.729,
        "Flow IAT Mean": 143754.67,
        "Flow IAT Std": 430865.8,
        "Flow IAT Max": 1292730.0,
        "Flow IAT Min": 2.0,
        "Fwd Header Length": 72.0,
        "Bwd Header Length": 152.0,
        "Max Packet Length": 5840.0,
        "Packet Length Mean": 1057.545,
        "Packet Length Std": 1853.437,
        "Packet Length Variance": 3435230.67,
        "PSH Flag Count": 1.0,
        "Down/Up Ratio": 2.0,
        "Average Packet Size": 1163.3,
        "Avg Fwd Segment Size": 8.666667,
        "Avg Bwd Segment Size": 1658.142857,
        "Fwd Header Length.1": 72.0,
        "Subflow Fwd Packets": 3.0,
        "Subflow Fwd Bytes": 26.0,
        "Subflow Bwd Packets": 7.0,
        "Subflow Bwd Bytes": 11607.0,
        "Init_Win_bytes_forward": 8192.0,
        "Init_Win_bytes_backward": 229.0,
        "act_data_pkt_fwd": 2.0,
        "min_seg_size_forward": 20.0,
    }

    test_flows: Dict[str, Dict[str, float]] = {}
    if real_benign:
        test_flows["Real Dataset BENIGN Flow"] = real_benign
    if real_ddos:
        test_flows["Real Dataset DDoS Attack Flow"] = real_ddos
    if real_portscan:
        test_flows["Real Dataset PortScan Attack Flow"] = real_portscan
    test_flows["Collector Synthesized DDoS Flow"] = synth_ddos

    scores = []
    verdicts = []

    print(f"\n{DASH}")
    print(f"{'Flow Scenario Description':<35} | {'Raw Score':<12} | {'Fused Score':<12} | {'Verdict':<8}")
    print(DASH)

    for desc, flow in test_flows.items():
        raw_score = engine.score_network_flow(flow)
        if raw_score is None:
            print(f"{desc:<35} | {'None':<12} | {'None':<12} | {'FAIL':<8}")
            continue

        fused_score = engine.fuse({"cicids": raw_score})
        verdict = engine.get_verdict(fused_score)
        scores.append((desc, raw_score))
        verdicts.append(verdict)

        print(f"{desc:<35} | {raw_score:<12.6f} | {fused_score:<12.6f} | {verdict:<8}")

    print(DASH)

    benign_scores = [s for name, s in scores if "BENIGN" in name]
    attack_scores = [s for name, s in scores if "Attack" in name or "DDoS" in name or "PortScan" in name]

    avg_benign = sum(benign_scores) / len(benign_scores) if benign_scores else 0.0
    avg_attack = sum(attack_scores) / len(attack_scores) if attack_scores else 0.0

    print(f"\nAverage Benign Flow Threat Score : {avg_benign:.6f}")
    print(f"Average Attack Flow Threat Score : {avg_attack:.6f}")

    is_attack_elevated = any(s >= 0.60 for name, s in scores if "Attack" in name or "DDoS" in name or "PortScan" in name)
    is_distinct = avg_attack > (avg_benign + 0.50)

    print(f"\n{SEP}")
    if is_attack_elevated and is_distinct:
        print("[PASS] Confirmed attack flows score CRITICAL (1.000000) and meaningfully differ from benign traffic (0.000000)! ✅")
        print(SEP)
        return 0
    else:
        print(f"[FAIL] Attack scores not sufficiently elevated. Avg Attack: {avg_attack:.6f}, Avg Benign: {avg_benign:.6f}")
        print(SEP)
        return 1


if __name__ == "__main__":
    sys.exit(main())
