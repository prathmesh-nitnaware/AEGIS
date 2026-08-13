"""
agent/diagnostics/inspect_cicids_columns.py
=============================================
Read-only inspection script for the CICIDS LightGBM model export.
Loads trained_models/cicids/aegis_lgbm_cicids_model.pkl via joblib,
extracts the "features" list, and prints the total count and ordered column names.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
import joblib

# Force UTF-8 stdout on Windows console
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

_HERE = Path(__file__).resolve().parent          # .../agent/diagnostics/
_AGENT_DIR = _HERE.parent                        # .../agent/
_PROJECT_ROOT = _AGENT_DIR.parent                # .../AEGIS/

MODEL_PATH = _PROJECT_ROOT / "trained_models" / "cicids" / "aegis_lgbm_cicids_model.pkl"


def main() -> int:
    if not MODEL_PATH.exists():
        print(f"[FAIL] Model pkl not found at: {MODEL_PATH}")
        return 1

    export = joblib.load(MODEL_PATH)
    if not isinstance(export, dict):
        print(f"[FAIL] Export pkl is not a dict! Type: {type(export)}")
        return 1

    features = export.get("features", [])
    print("=" * 72)
    print("  AEGIS - CICIDS Model Trained Feature Names Inspection")
    print("=" * 72)
    print(f"Total Trained Feature Count: {len(features)}\n")
    print("Ordered Feature Column Names:")
    for idx, feat in enumerate(features):
        print(f"  [{idx:2d}] {feat!r}")

    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
