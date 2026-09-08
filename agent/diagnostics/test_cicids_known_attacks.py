"""
agent/diagnostics/test_cicids_known_attacks.py
================================================
Deterministic diagnostic test for AEGIS CICIDS network threat detection.

Loads real attack and benign rows from the 8 CICIDS CSV dataset files and passes
them through AEGIS ThreatFusionEngine to verify that known malicious samples
receive high threat scores and appropriate severity levels.
"""

from __future__ import annotations

import io
import os
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Fixed seed so the representative sample (and therefore the test output) is
# reproducible across runs.
RANDOM_SEED = 42

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine

DATASET_DIR = _PROJECT_ROOT / "Dataset" / "CICIDS"

# Class category mapping for target selection
TEST_CATEGORIES = {
    "BENIGN": ("Monday-WorkingHours.pcap_ISCX.csv", ["BENIGN"], 5),
    "DDoS": ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", ["DDoS"], 5),
    "PortScan": ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", ["PortScan"], 5),
    "DoS": ("Wednesday-workingHours.pcap_ISCX.csv", ["DoS Hulk", "DoS slowloris", "DoS Slowhttptest", "DoS GoldenEye"], 5),
    "Web Attack": ("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", ["Web Attack  Brute Force", "Web Attack  Sql Injection", "Web Attack  XSS", "Web Attack"], 5),
}


def load_samples_from_csv(csv_filename: str, target_labels: list[str], sample_count: int = 5) -> list[dict]:
    csv_path = DATASET_DIR / csv_filename
    if not csv_path.exists():
        print(f"[WARNING] CSV file not found: {csv_filename}")
        return []

    encoding = "cp1252" if "WebAttacks" in csv_filename else "utf-8"

    # Scan the WHOLE file and draw a representative sample of the matching rows
    # via reservoir sampling (Algorithm R). Taking the first N matching rows
    # instead lands on the unrepresentative head of each capture and produces
    # misleading near-zero threat scores.
    chunk_size = 50000
    rng = random.Random(RANDOM_SEED)
    reservoir: list[dict] = []
    seen = 0  # count of matching rows encountered so far (0-indexed position)

    for chunk in pd.read_csv(csv_path, encoding=encoding, low_memory=False, chunksize=chunk_size):
        chunk.columns = chunk.columns.str.strip()
        label_col = next((c for c in chunk.columns if col_match(c)), None)
        if label_col is None:
            continue

        # Clean label strings
        chunk["_clean_label"] = chunk[label_col].astype(str).str.strip()

        # Filter matching rows
        mask = chunk["_clean_label"].apply(lambda l: any(tgt.lower() in l.lower() for tgt in target_labels))
        matching_rows = chunk[mask]

        for _, row in matching_rows.iterrows():
            row_dict = row.to_dict()
            clean_lbl = row_dict.pop("_clean_label", None)
            row_dict["_true_label"] = clean_lbl

            if len(reservoir) < sample_count:
                reservoir.append(row_dict)
            else:
                j = rng.randint(0, seen)  # inclusive -> uniform over [0, seen]
                if j < sample_count:
                    reservoir[j] = row_dict
            seen += 1

    return reservoir


def col_match(col_name: str) -> bool:
    return col_name.lower() == "label"


def run_deterministic_tests():
    print("=" * 75)
    print("AEGIS CICIDS DETERMINISTIC KNOWN ATTACKS TEST")
    print("=" * 75)

    engine = ThreatFusionEngine()
    
    if engine._cicids_model is None:
        print("[ERROR] CICIDS model failed to load in ThreatFusionEngine!")
        return 1

    summary_results = []

    for cat_name, (csv_name, target_labels, count) in TEST_CATEGORIES.items():
        print(f"\n--- Testing Category: {cat_name} (Source: {csv_name}) ---")
        samples = load_samples_from_csv(csv_name, target_labels, count)
        
        if not samples:
            print(f"  [WARN] No samples found for category {cat_name}")
            continue

        for idx, sample in enumerate(samples, 1):
            true_label = sample.get("_true_label", cat_name)
            
            # Prepare feature vector for model
            x = engine._reindex_features(sample, engine._cicids_features).reshape(1, -1)
            probas = engine._cicids_model.predict_proba(x)[0]

            # probas columns follow model.classes_ (label-encoded ints), which may
            # be a strict SUBSET of label_encoder.classes_ when a class was dropped
            # during training. Map the argmax POSITION -> encoded label through
            # model.classes_ first, then -> class name; indexing le.classes_ with
            # the raw position is off-by-one for every class after the gap.
            model_classes = [int(c) for c in engine._cicids_model.classes_]
            pred_position = int(np.argmax(probas))
            pred_encoded = model_classes[pred_position]

            pred_class_name = "Unknown"
            if engine._cicids_le is not None and 0 <= pred_encoded < len(engine._cicids_le.classes_):
                pred_class_name = engine._cicids_le.classes_[pred_encoded]

            # Find BENIGN probability at its position within model.classes_
            p_benign = 0.0
            if engine._cicids_le is not None:
                benign_encoded = next(
                    (i for i, c in enumerate(engine._cicids_le.classes_) if str(c).upper() == "BENIGN"),
                    None,
                )
                if benign_encoded is not None and benign_encoded in model_classes:
                    p_benign = float(probas[model_classes.index(benign_encoded)])
            
            # Score through Fusion Engine
            threat_score = engine.score_network_flow(sample)
            fused_score = engine.fuse({"cicids": threat_score})
            severity = engine.get_verdict(fused_score)

            print(f"  Sample #{idx} | True Label: {true_label:<25} | Pred Class: {pred_class_name:<20} | P(BENIGN): {p_benign:.6f} | Threat Score: {threat_score:.6f} | Severity: {severity}")
            
            summary_results.append({
                "Category": cat_name,
                "True Label": true_label,
                "Predicted Class": pred_class_name,
                "P(BENIGN)": p_benign,
                "Threat Score": threat_score,
                "Severity": severity
            })

    print("\n" + "=" * 75)
    print("DETERMINISTIC CICIDS TEST SUMMARY")
    print("=" * 75)
    print(f"{'Category':<12} | {'True Label':<25} | {'Predicted Class':<22} | {'P(BENIGN)':<10} | {'Score':<8} | {'Severity'}")
    print("-" * 95)
    for r in summary_results:
        print(f"{r['Category']:<12} | {r['True Label']:<25} | {r['Predicted Class']:<22} | {r['P(BENIGN)']:<10.4f} | {r['Threat Score']:<8.4f} | {r['Severity']}")

    return 0


if __name__ == "__main__":
    sys.exit(run_deterministic_tests())
