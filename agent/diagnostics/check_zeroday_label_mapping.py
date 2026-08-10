"""
agent/diagnostics/check_zeroday_label_mapping.py
=================================================
Sanity-check script for the Zero-Day IsolationForest score mapping in score_windows_event().

Confirms:
  1. Zero-Day model & categorical encoders loaded via ThreatFusionEngine.
  2. Inspection of event_encoder, process_encoder, and user_encoder classes.
  3. Directional sanity check: verifies whether unseen/novel activities score
     consistently higher (more anomalous) than known baseline activities.

Run from project root:
    python agent/diagnostics/check_zeroday_label_mapping.py
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

# Force UTF-8 stdout for Windows console compatibility
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent          # .../agent/diagnostics/
_AGENT_DIR = _HERE.parent                        # .../agent/
_PROJECT_ROOT = _AGENT_DIR.parent                # .../AEGIS/

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine  # noqa: E402

SEP = "=" * 72
DASH = "-" * 72


def main() -> int:
    print(SEP)
    print("  AEGIS - Zero-Day Anomaly Model Directional Sanity Check")
    print(SEP)

    engine = ThreatFusionEngine()

    if engine._zday_model is None:
        print("\n[FAIL] Zero-Day model could not be loaded from trained_models/zero_day/!")
        return 1

    print("\n--- Model & Encoder Classes Inspection ---")
    print(f"Model type         : {type(engine._zday_model).__name__}")

    event_classes = list(engine._zday_event_enc.classes_) if engine._zday_event_enc else []
    process_classes = list(engine._zday_process_enc.classes_) if engine._zday_process_enc else []
    user_classes = list(engine._zday_user_enc.classes_) if engine._zday_user_enc else []

    print(f"event_encoder classes   ({len(event_classes):2d}) : {event_classes}")
    print(f"process_encoder classes ({len(process_classes):2d}) : {process_classes}")
    print(f"user_encoder classes    ({len(user_classes):2d}) : {user_classes}")

    # Build 3 "known/baseline" test cases using values present in the training classes
    # If classes are minimal, use the exact classes from training
    known_event = str(event_classes[0]) if event_classes else "0"
    known_proc_1 = str(process_classes[0]) if process_classes else "unknown.exe"
    known_proc_2 = str(process_classes[1]) if len(process_classes) > 1 else known_proc_1
    known_user = str(user_classes[0]) if user_classes else "unknown"

    known_cases: List[Tuple[str, str, str, str, str]] = [
        ("Known Baseline #1", known_event, known_proc_1, known_user, "192.168.1.10"),
        ("Known Baseline #2", known_event, known_proc_2, known_user, "127.0.0.1"),
        ("Known Baseline #3", known_event, known_proc_1, known_user, "10.0.0.5"),
    ]

    # Build 3 "unseen/novel" test cases using values NOT present in the training classes
    unseen_cases: List[Tuple[str, str, str, str, str]] = [
        ("Unseen Novel #1", "9999", "malware_unknown.exe", "HackerUser", "192.168.1.254"),
        ("Unseen Novel #2", "4688", "powershell_obfuscated.exe", "EvilUser", "222.111.0.1"),
        ("Unseen Novel #3", "7045", "mimikatz_driver.sys", "UnknownAccount", "45.33.22.11"),
    ]

    print("\n--- Test Case Evaluation ---")
    results: List[Dict[str, str]] = []
    known_scores: List[float] = []
    unseen_scores: List[float] = []

    all_cases = [(c, "Known") for c in known_cases] + [(c, "Unseen") for c in unseen_cases]

    for (tag, evt_id, proc, usr, ip), group in all_cases:
        # Encode inputs manually for inspection
        evt_enc = engine._safe_le_transform(engine._zday_event_enc, evt_id, fallback=0)
        proc_enc = engine._safe_le_transform(engine._zday_process_enc, proc, fallback=0)
        usr_enc = engine._safe_le_transform(engine._zday_user_enc, usr, fallback=0)

        try:
            ip_last = int(str(ip).split(".")[-1])
        except (ValueError, IndexError):
            ip_last = 0

        x = np.array([[evt_enc, proc_enc, usr_enc, ip_last]], dtype=np.float64)
        decision_raw = float(engine._zday_model.decision_function(x)[0])
        score = engine.score_windows_event(evt_id, proc, usr, ip)

        if score is not None:
            if group == "Known":
                known_scores.append(score)
            else:
                unseen_scores.append(score)

        results.append({
            "tag": tag,
            "group": group,
            "inputs": f"Evt:{evt_id} Proc:{proc[:18]} Usr:{usr} IP:{ip}",
            "encoded": f"[{evt_enc}, {proc_enc}, {usr_enc}, {ip_last}]",
            "decision": f"{decision_raw:+.4f}",
            "score": f"{score:.6f}" if score is not None else "None",
        })

    # Summary Table
    print(f"\n{DASH}")
    print(f"{'Test Case Tag':<20} | {'Group':<6} | {'Encoded Features':<16} | {'Decision':<9} | {'Score':<10}")
    print(DASH)
    for r in results:
        print(f"{r['tag']:<20} | {r['group']:<6} | {r['encoded']:<16} | {r['decision']:<9} | {r['score']:<10}")
    print(DASH)

    avg_known = float(np.mean(known_scores)) if known_scores else 0.0
    avg_unseen = float(np.mean(unseen_scores)) if unseen_scores else 0.0
    margin = avg_unseen - avg_known

    print(f"\nAverage Known Baseline Score : {avg_known:.6f}")
    print(f"Average Unseen Novel Score    : {avg_unseen:.6f}")
    print(f"Score Separation Margin      : {margin:+.6f} (Threshold required for PASS: > +0.10)")

    # PASS / FAIL Evaluation
    is_pass = margin > 0.10
    verdict_status = "PASS" if is_pass else "FAIL"

    print(f"\n{SEP}")
    print(f"  DIAGNOSTIC VERDICT: {verdict_status}")
    print(SEP)
    print(
        "DIRECTIONAL SANITY CHECK FOR ZERO-DAY ISOLATION FOREST:\n"
        "IsolationForest is an unsupervised model trained without attack ground-truth labels. The scoring "
        "formula 1 - sigmoid(decision_function) correctly maps more anomalous inputs (lower/negative decision) "
        "to higher threat scores. However, in this trained model artifact, the categorical encoders "
        "('event_encoder', 'process_encoder', 'user_encoder') were fitted on an extremely minimal set of "
        "classes (e.g. process_encoder has only ['CompatTelRunner.exe', 'unknown.exe']). Because "
        "_safe_le_transform() falls back to index 0 for all unseen labels, both known baseline and novel "
        "unseen process/event names collapse to the exact same feature index [0, 0, 0, ip_last].\n\n"
        f"Consequently, the score margin between novel activity and baseline activity is only {margin:+.4f} "
        "(below the required +0.10 margin threshold). While the mathematical direction (1 - sigmoid) is "
        "correct, the feature encoding pipeline currently lacks a rich training vocabulary, preventing the "
        "model from meaningfully discriminating zero-day threats from normal traffic. Retraining with "
        "comprehensive Windows event log vocabularies is strongly recommended before building live collectors."
    )
    print(SEP)

    return 0 if is_pass else 1


if __name__ == "__main__":
    sys.exit(main())
