"""
agent/diagnostics/compare_cicids_ddos_row.py
Inspect exact values of real DDoS, PortScan, and Benign rows from CICIDS dataset CSVs.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
import pandas as pd

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine

_CICIDS_DIR = _PROJECT_ROOT / "Dataset" / "CICIDS"


def inspect_file(engine, csv_name, target_label):
    csv_path = _CICIDS_DIR / csv_name
    if not csv_path.exists():
        print(f"[SKIP] CSV not found: {csv_name}")
        return

    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    label_col = next((c for c in df.columns if "label" in c.lower()), None)
    rows = df[df[label_col].astype(str).str.strip().str.upper() == target_label.upper()]

    if rows.empty:
        print(f"[SKIP] No rows for {target_label} in {csv_name}")
        return

    row = rows.iloc[0].to_dict()
    score = engine.score_network_flow(row)

    print(f"\n==================================================")
    print(f"  Target Label : {target_label} ({csv_name})")
    print(f"  Model Score  : {score:.8f}")
    print(f"==================================================")
    print("Non-Zero Features:")
    for k in engine._cicids_features:
        val = row.get(k, 0.0)
        try:
            fval = float(val)
            if fval != 0.0:
                print(f"  {k:<32}: {fval}")
        except Exception:
            pass


def main():
    engine = ThreatFusionEngine()
    inspect_file(engine, "Monday-WorkingHours.pcap_ISCX.csv", "BENIGN")
    inspect_file(engine, "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "DDoS")
    inspect_file(engine, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "PortScan")
    return 0


if __name__ == "__main__":
    sys.exit(main())
