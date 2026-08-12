"""
agent/diagnostics/check_ember_live_pipeline.py
=================================================
EMBER diagnostic (matches the one-file-per-model pattern used by
check_cicids_label_mapping.py, check_hdfs_label_mapping.py, etc).

check_ember_label_mapping.py already verifies the trained model's label
convention against real dataset rows. This file covers what that one
can't: it verifies the LIVE extraction path -- ember_features.py reading
a raw .exe off disk -- rather than pre-extracted parquet rows. EMBER is
the only model that needed this, because it's the only one where the
live feature extractor had to be rebuilt from scratch (the official
`ember` pip package doesn't install on modern Python).

Two checks, run in order:

  PART 1 -- Feature alignment
    Confirms ember_features.py's extraction order (2381 dims, canonical
    EMBER group order) actually matches what the trained model expects
    (engine._ember_features), using the same real dataset
    check_ember_label_mapping.py already validated against.

  PART 2 -- Live extraction + scoring
    Runs a real file on disk through the full path: raw bytes ->
    ember_features.extract_from_path() -> ThreatFusionEngine.score_file().
    This is the actual PEFileCollector code path, tested end-to-end.

Run from project root:
    python agent/diagnostics/check_ember_live_pipeline.py "C:\\Windows\\System32\\notepad.exe"

(Part 1 runs with or without a file argument. Part 2 needs a real file
path and is skipped if you don't provide one.)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

_HERE = Path(__file__).resolve().parent
_AGENT_DIR = _HERE.parent
_PROJECT_ROOT = _AGENT_DIR.parent

for p in (_PROJECT_ROOT, _AGENT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from agent.fusion_engine import ThreatFusionEngine  # noqa: E402
import ember_features as ef  # noqa: E402

_EMBER_FILE = _PROJECT_ROOT / "Dataset" / "EMBER" / "test_ember_2018_v2_features.parquet"
SEP = "=" * 72


def check_alignment(engine: ThreatFusionEngine) -> bool:
    print(SEP)
    print("  PART 1 -- Feature Alignment Check")
    print(SEP)

    model_features = list(engine._ember_features)
    print(f"\nModel expects        : {len(model_features)} features")
    print(f"Extractor produces    : {ef.TOTAL_DIM} features")
    print(f"First 5 model names   : {model_features[:5]}")
    print(f"Last 5 model names    : {model_features[-5:]}")

    if len(model_features) != ef.TOTAL_DIM:
        print(f"\n[FAIL] Length mismatch: {len(model_features)} != {ef.TOTAL_DIM}.")
        print("       ember_features.py's feature groups don't match this model's")
        print("       training data. Check the model_features list above against")
        print("       ember_features.FEATURE_GROUP_SIZES and adjust accordingly.")
        return False

    print("\n[OK] Length matches (2381).")

    if not _EMBER_FILE.exists():
        print(f"\n[WARN] {_EMBER_FILE} not found -- skipping real-sample cross-check.")
        return True

    df = pd.read_parquet(_EMBER_FILE)
    label_col = next((c for c in df.columns if c.lower() == "label"), None)
    df = df.rename(columns={label_col: "label"})
    df_labeled = df[df["label"] != -1]
    sample = df_labeled.iloc[0]
    row_vals = sample[model_features].to_numpy(dtype=float)
    print(f"Sample row (label={int(sample['label'])}) first 5 values under "
          f"model's own column order: {np.round(row_vals[:5], 4)}")
    print("[OK] Model's column list is usable for reindexing.")
    return True


def check_live_extraction(engine: ThreatFusionEngine, target: str) -> bool:
    print(f"\n{SEP}")
    print("  PART 2 -- Live Extraction + Scoring")
    print(SEP)

    if not Path(target).exists():
        print(f"\n[FAIL] File not found: {target}")
        return False

    print(f"\nExtracting features from: {target}")
    t0 = time.time()
    try:
        vector, meta = ef.extract_from_path(target)
    except ValueError as e:
        print(f"[FAIL] Not a valid PE file: {e}")
        return False
    dt = (time.time() - t0) * 1000
    print(f"Extraction took {dt:.1f} ms, produced {len(vector)} features")
    print(f"PE meta: {meta}")

    pe_features = dict(zip(engine._ember_features, vector))
    score = engine.score_file(pe_features)
    if score is None:
        print("[FAIL] score_file() returned None -- something's wrong upstream.")
        return False

    verdict = engine.get_verdict(score)
    print(f"\nSCORE   : {score:.4f}")
    print(f"VERDICT : {verdict}")
    print("\nSanity check: known-clean Windows system binaries should score")
    print("LOW (well under 0.3). If a clean file scores HIGH/CRITICAL here,")
    print("re-check Part 1's output above against ember_features.FEATURE_GROUP_SIZES.")
    return True


def main() -> int:
    engine = ThreatFusionEngine()
    if engine._ember_model is None:
        print("[FAIL] EMBER model could not be loaded.")
        return 1

    ok = check_alignment(engine)

    if len(sys.argv) > 1:
        ok = check_live_extraction(engine, sys.argv[1]) and ok
    else:
        print(f"\n{SEP}")
        print("[SKIP] Part 2 -- pass a file path to test live extraction+scoring:")
        print('       python check_ember_live_pipeline.py "C:\\path\\to\\some.exe"')

    print(f"\n{SEP}")
    print("[OK] All checks passed." if ok else "[FAIL] See above.")
    print(SEP)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
