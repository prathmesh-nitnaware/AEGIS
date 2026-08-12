"""
agent/diagnostics/check_windows_label_mapping.py
=================================================
Sanity-check script for the Windows Advanced XGBoost model in _score_windows().

Confirms:
  1. Windows model & artefacts loaded via ThreatFusionEngine.
  2. label_encoder.classes_ contains threat labels ["Attack", "Normal"] (NOT S1-S4).
  3. _windows_labels_valid flag is True (model is included in fuse()).
  4. "Normal" class index correctly resolved for the scoring formula.
  5. Directional scoring: Normal API sequences score LOW, Attack sequences score HIGH.

Run from project root:
    python agent/diagnostics/check_windows_label_mapping.py
"""

from __future__ import annotations

import io
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# Force UTF-8 stdout for Windows console compatibility
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_HERE         = Path(__file__).resolve().parent   # .../agent/diagnostics/
_AGENT_DIR    = _HERE.parent                      # .../agent/
_PROJECT_ROOT = _AGENT_DIR.parent                 # .../AEGIS/

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine  # noqa: E402

DATASET_PATH = (
    _PROJECT_ROOT
    / "Dataset"
    / "ADFA_dataset"
    / "ADFA-WD-SAA_Master"
    / "ADFA-WD-SAA_Master"
    / "Full_Process_Traces"
)

SEP  = "=" * 72
DASH = "-" * 72


def _pass_fail(true_label: str, score: float) -> Tuple[str, str]:
    """
    PASS if:
      - true_label == "Normal" and score < 0.40
      - true_label == "Attack" and score > 0.40
    """
    is_normal = true_label.upper() == "NORMAL"
    if is_normal and score < 0.40:
        return "PASS", f"True Normal -> score {score:.6f} < 0.40"
    elif not is_normal and score >= 0.40:
        return "PASS", f"True Attack -> score {score:.6f} >= 0.40"
    elif is_normal and score >= 0.40:
        return "FAIL", f"True Normal incorrectly scored high: {score:.6f} >= 0.40"
    else:
        return "FAIL", f"True Attack incorrectly scored low: {score:.6f} < 0.40"


MIN_TOKENS = 5  # sequences shorter than this are degenerate (mostly zero-padded)


def _load_ghc_sample(folder: Path, n: int = 3) -> List[List[str]]:
    """Load up to n .GHC files from a session folder and return token lists.

    Files with fewer than MIN_TOKENS tokens are skipped -- a 1-token sequence
    pads to 999 zeros and represents a degenerate/empty process trace that
    the model cannot meaningfully classify.
    """
    ghc_files = list(folder.rglob("*.GHC"))
    random.seed(42)
    random.shuffle(ghc_files)
    samples = []
    for fp in ghc_files:
        if len(samples) >= n:
            break
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore").strip()
            tokens = content.split()
            if len(tokens) >= MIN_TOKENS:
                samples.append(tokens)
        except Exception:
            pass
    return samples


def main() -> int:
    print(SEP)
    print("  AEGIS - Windows Advanced Model Label Mapping Sanity Check")
    print(SEP)

    engine = ThreatFusionEngine()

    # ------------------------------------------------------------------
    # 1. Check model loaded
    # ------------------------------------------------------------------
    if engine._win_model is None:
        print("\n[FAIL] Windows model could not be loaded from trained_models/windows_advanced/!")
        print("       Run: python ml_notebooks/windows_advanced/retrain_windows.py")
        return 1

    print("\n--- Model & Encoder Inspection ---")
    print(f"Model type         : {type(engine._win_model).__name__}")
    print(f"Token vocab size   : {len(engine._win_token_map)}")

    # ------------------------------------------------------------------
    # 2. Inspect label_encoder classes
    # ------------------------------------------------------------------
    le = engine._win_le
    if le is not None and hasattr(le, "classes_"):
        print("\nLabelEncoder classes_:")
        for idx, cls_val in enumerate(le.classes_):
            print(f"  [{idx}] {cls_val!r} (type: {type(cls_val).__name__})")
    else:
        print("\n[WARN] LabelEncoder missing or has no classes_ attribute.")

    # ------------------------------------------------------------------
    # 3. Check _windows_labels_valid flag
    # ------------------------------------------------------------------
    print(f"\n_windows_labels_valid : {engine._windows_labels_valid}")
    if not engine._windows_labels_valid:
        print(
            "  [FAIL] Flag is False -- label_encoder still contains non-threat labels.\n"
            "         Windows sub-score is excluded from fuse().\n"
            "         Run: python ml_notebooks/windows_advanced/retrain_windows.py"
        )
        return 1
    else:
        print("  [OK]  Windows sub-score will be included in fuse().")

    # ------------------------------------------------------------------
    # 4. Resolve "Normal" class index
    # ------------------------------------------------------------------
    normal_idx: Optional[int] = None
    if le is not None and hasattr(le, "classes_"):
        for i, c in enumerate(le.classes_):
            if str(c).lower() == "normal":
                normal_idx = i
                break

    print(f"\nResolved 'Normal' class index: {normal_idx}")
    if normal_idx is None:
        print(
            "  [FAIL] 'Normal' string class NOT found in label_encoder.classes_!\n"
            "         Scoring formula will fall back to 1 - max(proba)."
        )

    # ------------------------------------------------------------------
    # 5. Real dataset directional validation
    # ------------------------------------------------------------------
    if not DATASET_PATH.exists():
        print("\nDataset not found locally -- skipped real-sample validation")
        return 0

    print("\n--- Real Dataset Directional Scoring Validation ---")
    results: List[Dict[str, str]] = []

    sample_requests = [
        (DATASET_PATH / "S1", "Normal", 3),  # S1 = Normal baseline
        (DATASET_PATH / "S2", "Attack", 3),  # S2 = Hydra FTP
        (DATASET_PATH / "S3", "Attack", 3),  # S3 = Hydra SSH
        (DATASET_PATH / "S4", "Attack", 2),  # S4 = Drive-by Download
    ]

    for session_dir, true_label, n in sample_requests:
        if not session_dir.exists():
            print(f"  [SKIP] Session folder not found: {session_dir.name}")
            continue

        samples = _load_ghc_sample(session_dir, n)
        if not samples:
            print(f"  [SKIP] No .GHC files found in {session_dir.name}")
            continue

        for seq_idx, token_seq in enumerate(samples):
            score = engine._score_windows(token_seq)

            if score is None:
                status, reason = "FAIL", "_score_windows() returned None"
            else:
                status, reason = _pass_fail(true_label, score)

            results.append({
                "session": session_dir.name,
                "true_label": true_label,
                "tokens": str(len(token_seq)),
                "score": f"{score:.6f}" if score is not None else "None",
                "status": status,
                "reason": reason,
            })

    # ------------------------------------------------------------------
    # 6. Summary table
    # ------------------------------------------------------------------
    print(f"\n{DASH}")
    print(f"{'Session':<10} | {'True Label':<10} | {'Tokens':<7} | {'Score':<10} | {'Status':<6}")
    print(DASH)

    pass_count = 0
    for r in results:
        print(
            f"{r['session']:<10} | {r['true_label']:<10} | "
            f"{r['tokens']:<7} | {r['score']:<10} | {r['status']:<6}"
        )
        if r["status"] == "PASS":
            pass_count += 1

    print(DASH)
    print(f"Total: {pass_count} / {len(results)} PASS")

    # ------------------------------------------------------------------
    # 7. Verdict paragraph
    # ------------------------------------------------------------------
    print(f"\n{SEP}")
    print("  DIAGNOSTIC VERDICT PARAGRAPH")
    print(SEP)
    if pass_count == len(results) and len(results) > 0:
        normal_idx_str = str(normal_idx) if normal_idx is not None else "N/A"
        print(
            "WINDOWS ADVANCED MODEL LABEL MAPPING VERIFIED CORRECT:\n"
            "The retrained XGBoost model ('windows_advanced_xgboost.pkl') contains a valid "
            f"label_encoder with binary threat labels: ['Attack', 'Normal']. "
            f"The dynamic lookup for string 'Normal' inside _score_windows() resolves to "
            f"index {normal_idx_str}. The _windows_labels_valid flag is True, so the Windows "
            "sub-score is now included in ThreatFusionEngine.fuse(). Real ADFA-WD-SAA samples "
            f"scored correctly: Normal (S1) sessions scored LOW (<0.40) and Attack "
            "sessions (S2/S3/S4) scored HIGH (>=0.40). "
            f"All {pass_count}/{len(results)} directional checks passed."
        )
    else:
        print(
            "WINDOWS MODEL VALIDATION FAILED:\n"
            f"Only {pass_count}/{len(results)} directional checks passed. "
            "Either the model is still using old S1/S2/S3/S4 session labels (re-run "
            "retrain_windows.py), or the scoring direction is inverted (check that "
            "_score_windows() uses '1 - P(Normal)' not 'P(Attack)' directly)."
        )
    print(SEP)

    return 0 if (pass_count == len(results) and len(results) > 0) else 1


if __name__ == "__main__":
    sys.exit(main())
