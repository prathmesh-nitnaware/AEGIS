"""
tools/evaluate_all_models.py
============================
Unified Model Accuracy & Evaluation Benchmark for AEGIS Layer 1 Engines.

Evaluates all production models serialized under `trained_models/`:
1. Linux IDS (XGBoost - Syscall Sequences)
2. Windows Advanced v3 (XGBoost - Process Context)
3. CICIDS Network Flow (LightGBM - Network Telemetry)
4. EMBER Static PE Binary (LightGBM - Portable Executable Features)
5. HDFS Log Anomaly (TF-IDF + XGBoost - System Logs)
6. Zero-Day Anomaly Detector (Isolation Forest - Windows Security Events)

Outputs a comprehensive terminal metrics report with:
- Accuracy, Precision, Recall, and F1-Score
- Class breakdown & confusion statistics
- Latency and artifact validation
"""

from __future__ import annotations

import sys
import time
import warnings
from pathlib import Path
from typing import Dict, Any, Tuple

import joblib
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine

warnings.filterwarnings("ignore")


def evaluate_linux_ids() -> Dict[str, Any]:
    print("\n[1/6] Evaluating Linux IDS XGBoost Classifier...")
    from ml_notebooks.linux_ids.train_enhanced_linux_ids import generate_balanced_linux_dataset
    
    model_path = _PROJECT_ROOT / "trained_models" / "linux_ids" / "linux_xgboost_model.pkl"
    le_path = _PROJECT_ROOT / "trained_models" / "linux_ids" / "linux_label_encoder.pkl"
    
    if not model_path.exists() or not le_path.exists():
        return {"status": "MISSING_ARTIFACT", "error": f"Artifact not found at {model_path}"}
        
    model = joblib.load(model_path)
    le = joblib.load(le_path)
    
    # Generate test set (300 samples per class)
    X, y_labels, _ = generate_balanced_linux_dataset(n_samples_per_class=300)
    y_true = le.transform(y_labels)
    
    t0 = time.perf_counter()
    y_pred = model.predict(X)
    lat_ms = (time.perf_counter() - t0) * 1000 / len(X)
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    
    return {
        "status": "PASS",
        "model": "Linux IDS (XGBoost)",
        "classes": len(le.classes_),
        "samples": len(X),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "latency_per_sample_ms": lat_ms,
        "details": f"Classes: {', '.join(le.classes_)}"
    }


def evaluate_windows_v3() -> Dict[str, Any]:
    print("[2/6] Evaluating Windows Advanced v3 XGBoost Classifier...")
    from ml_notebooks.windows_advanced_v3.train_enhanced_v3 import generate_process_dataset
    
    model_path = _PROJECT_ROOT / "trained_models" / "windows_advanced_v3" / "windows_advanced_v3.pkl"
    if not model_path.exists():
        return {"status": "MISSING_ARTIFACT", "error": f"Artifact not found at {model_path}"}
        
    payload = joblib.load(model_path)
    model = payload["model"] if isinstance(payload, dict) and "model" in payload else payload
    
    # Generate evaluation set
    X, y_true = generate_process_dataset(n_samples=3000)
    
    t0 = time.perf_counter()
    y_pred = model.predict(X)
    lat_ms = (time.perf_counter() - t0) * 1000 / len(X)
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    return {
        "status": "PASS",
        "model": "Windows Advanced v3 (XGBoost)",
        "classes": 2,
        "samples": len(X),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "latency_per_sample_ms": lat_ms,
        "details": "Binary classification: 0 (Normal) vs 1 (Attack/PrivEsc)"
    }


def evaluate_cicids() -> Dict[str, Any]:
    print("[3/6] Evaluating CICIDS Network Flow LightGBM Classifier...")
    from ml_notebooks.cicids.train_enhanced_cicids import build_dataset, CLASSES
    
    model_path = _PROJECT_ROOT / "trained_models" / "cicids" / "aegis_lgbm_cicids_model.pkl"
    if not model_path.exists():
        return {"status": "MISSING_ARTIFACT", "error": f"Artifact not found at {model_path}"}
        
    payload = joblib.load(model_path)
    model = payload["model"]
    le = payload["label_encoder"]
    
    X, raw_labels = build_dataset(samples_per_class=200)
    y_true = le.transform(raw_labels)
    
    t0 = time.perf_counter()
    y_pred = model.predict(X)
    lat_ms = (time.perf_counter() - t0) * 1000 / len(X)
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    
    return {
        "status": "PASS",
        "model": "CICIDS Flow (LightGBM)",
        "classes": len(CLASSES),
        "samples": len(X),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "latency_per_sample_ms": lat_ms,
        "details": f"15 Network attack types (DDoS, PortScan, Botnet, Patator)"
    }


def evaluate_ember() -> Dict[str, Any]:
    print("[4/6] Evaluating EMBER Static PE Binary LightGBM Classifier...")
    from ml_notebooks.ember.train_enhanced_ember import generate_benign_ember_sample, generate_malicious_ember_sample
    
    model_path = _PROJECT_ROOT / "trained_models" / "ember" / "aegis_ember_model_full.pkl"
    if not model_path.exists():
        return {"status": "MISSING_ARTIFACT", "error": f"Artifact not found at {model_path}"}
        
    payload = joblib.load(model_path)
    model = payload["model"]
    
    n_samples = 500
    X_list = []
    y_list = []
    for _ in range(n_samples):
        X_list.append(generate_benign_ember_sample())
        y_list.append(0)
    for _ in range(n_samples):
        X_list.append(generate_malicious_ember_sample())
        y_list.append(1)
        
    X = np.array(X_list, dtype=np.float64)
    y_true = np.array(y_list)
    
    t0 = time.perf_counter()
    y_pred = model.predict(X)
    lat_ms = (time.perf_counter() - t0) * 1000 / len(X)
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    return {
        "status": "PASS",
        "model": "EMBER PE Binary (LightGBM)",
        "classes": 2,
        "samples": len(X),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "latency_per_sample_ms": lat_ms,
        "details": "2381-dim PE Header, Byte Histograms, String Encodings"
    }


def evaluate_hdfs() -> Dict[str, Any]:
    print("[5/6] Evaluating HDFS Log Anomaly TF-IDF + XGBoost Classifier...")
    from ml_notebooks.hdfs.train_enhanced_hdfs import NORMAL_TEMPLATES, ANOMALY_TEMPLATES, generate_sample
    
    model_path = _PROJECT_ROOT / "trained_models" / "hdfs" / "hdfs_xgboost_model.pkl"
    vec_path = _PROJECT_ROOT / "trained_models" / "hdfs" / "hdfs_vectorizer.pkl"
    le_path = _PROJECT_ROOT / "trained_models" / "hdfs" / "hdfs_label_encoder.pkl"
    
    if not model_path.exists() or not vec_path.exists() or not le_path.exists():
        return {"status": "MISSING_ARTIFACT", "error": f"Artifacts missing in {model_path.parent}"}
        
    model = joblib.load(model_path)
    vec = joblib.load(vec_path)
    le = joblib.load(le_path)
    
    texts = []
    labels = []
    for _ in range(500):
        tmpl = np.random.choice(NORMAL_TEMPLATES)
        texts.append(generate_sample(tmpl))
        labels.append("Normal")
        
    for _ in range(500):
        tmpl = np.random.choice(ANOMALY_TEMPLATES)
        texts.append(generate_sample(tmpl))
        labels.append("Anomaly")
        
    y_true = le.transform(labels)
    X = vec.transform(texts)
    
    t0 = time.perf_counter()
    y_pred = model.predict(X)
    lat_ms = (time.perf_counter() - t0) * 1000 / len(texts)
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    
    return {
        "status": "PASS",
        "model": "HDFS Logs (TF-IDF + XGBoost)",
        "classes": 2,
        "samples": len(texts),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "latency_per_sample_ms": lat_ms,
        "details": "5000 TF-IDF features (Normal vs Log corruption & wiping)"
    }


def evaluate_zero_day() -> Dict[str, Any]:
    print("[6/6] Evaluating Zero-Day IsolationForest Outlier Detection Engine...")
    
    model_path = _PROJECT_ROOT / "trained_models" / "zero_day" / "aegis_zero_day_model.pkl"
    event_enc_path = _PROJECT_ROOT / "trained_models" / "zero_day" / "event_encoder.pkl"
    proc_enc_path = _PROJECT_ROOT / "trained_models" / "zero_day" / "process_encoder.pkl"
    user_enc_path = _PROJECT_ROOT / "trained_models" / "zero_day" / "user_encoder.pkl"
    
    if not model_path.exists():
        return {"status": "MISSING_ARTIFACT", "error": f"Artifact not found at {model_path}"}
        
    engine = ThreatFusionEngine()
    
    # Benign typical events (should score low threat, score < 0.35)
    benign_cases = [
        ("4624", "explorer.exe", "DOMAIN\\User", "192.168.1.50"),
        ("4688", "svchost.exe", "SYSTEM", "127.0.0.1"),
        ("1", "chrome.exe", "DOMAIN\\User", "10.0.0.15"),
        ("3", "code.exe", "DOMAIN\\User", "10.0.0.22"),
        ("7", "dwm.exe", "SYSTEM", "127.0.0.1"),
    ] * 100  # 500 samples
    
    # Attack / Anomaly / Zero-day events (should score high threat, score > 0.60)
    attack_cases = [
        ("7045", "mimikatz.exe", "SYSTEM", "10.0.0.99"),
        ("4697", "cobaltstrike.beacon.exe", "root", "198.51.100.4"),
        ("1", "cscript.exe", "guest", "203.0.113.88"),
        ("4688", "ransomware_dropper.exe", "[UNKNOWN_OOV]", "185.220.101.5"),
        ("11", "sharpup.exe", "Administrator", "192.168.100.250"),
    ] * 100  # 500 samples
    
    benign_scores = []
    attack_scores = []
    
    t0 = time.perf_counter()
    for eid, proc, user, ip in benign_cases:
        s = engine.score_windows_event(eid, proc, user, ip)
        if s is not None:
            benign_scores.append(s)
            
    for eid, proc, user, ip in attack_cases:
        s = engine.score_windows_event(eid, proc, user, ip)
        if s is not None:
            attack_scores.append(s)
            
    lat_ms = (time.perf_counter() - t0) * 1000 / (len(benign_cases) + len(attack_cases))
    
    # Threshold at 0.50 for binary anomaly separation:
    # Benign expected < 0.50 (label 0), Attack expected >= 0.50 (label 1)
    y_true = [0] * len(benign_scores) + [1] * len(attack_scores)
    y_pred = [0 if s < 0.50 else 1 for s in benign_scores] + [0 if s < 0.50 else 1 for s in attack_scores]
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    mean_benign = float(np.mean(benign_scores)) if benign_scores else 0.0
    mean_attack = float(np.mean(attack_scores)) if attack_scores else 0.0
    
    return {
        "status": "PASS",
        "model": "Zero-Day IsolationForest",
        "classes": 2,
        "samples": len(y_true),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "latency_per_sample_ms": lat_ms,
        "details": f"Unsupervised separation (Mean Benign={mean_benign:.2f}, Mean Attack={mean_attack:.2f})"
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS Layer 1 Unified Model Accuracy & Evaluation Benchmark")
    parser.add_argument("--model", type=str, default="all", choices=["all", "linux", "windows", "cicids", "ember", "hdfs", "zero_day"],
                        help="Specific model to evaluate (default: all)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    eval_map = {
        "linux": evaluate_linux_ids,
        "windows": evaluate_windows_v3,
        "cicids": evaluate_cicids,
        "ember": evaluate_ember,
        "hdfs": evaluate_hdfs,
        "zero_day": evaluate_zero_day
    }
    
    selected_funcs = eval_map.values() if args.model == "all" else [eval_map[args.model]]

    if not args.json:
        print("=" * 80)
        print("             AEGIS LAYER 1 - PRODUCTION MODEL ACCURACY BENCHMARK             ")
        print("=" * 80)
        print(f"Project Root: {_PROJECT_ROOT}")
        print(f"Timestamp:    {time.strftime('%Y-%m-%d %H:%M:%S')}")

    results = []
    for fn in selected_funcs:
        try:
            res = fn()
            results.append(res)
        except Exception as exc:
            results.append({"status": "ERROR", "error": str(exc), "model": fn.__name__})

    if args.json:
        import json
        print(json.dumps(results, indent=2))
        return

    print("\n" + "=" * 90)
    print(f"{'MODEL NAME':<30} | {'TEST ACC':<10} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-SCORE':<10} | {'LATENCY':<10}")
    print("-" * 90)
    
    overall_accs = []
    for r in results:
        if r.get("status") == "PASS":
            acc_str = f"{r['accuracy'] * 100:.2f}%"
            prec_str = f"{r['precision'] * 100:.2f}%"
            rec_str = f"{r['recall'] * 100:.2f}%"
            f1_str = f"{r['f1'] * 100:.2f}%"
            lat_str = f"{r['latency_per_sample_ms']:.3f} ms"
            print(f"{r['model']:<30} | {acc_str:<10} | {prec_str:<10} | {rec_str:<10} | {f1_str:<10} | {lat_str:<10}")
            overall_accs.append(r["accuracy"])
        else:
            print(f"{r.get('model', 'Unknown'):<30} | FAILED ({r.get('status')}): {r.get('error', '')}")

    print("=" * 90)
    if overall_accs:
        mean_acc = (sum(overall_accs) / len(overall_accs)) * 100
        print(f"MEAN LAYER 1 DETECTION ACCURACY: {mean_acc:.2f}%\n")


if __name__ == "__main__":
    main()
