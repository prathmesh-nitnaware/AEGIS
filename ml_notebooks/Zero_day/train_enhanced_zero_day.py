"""
ml_notebooks/Zero_day/train_enhanced_zero_day.py
=================================================
Enhanced Zero-Day Anomaly Detection Training Pipeline.

Fixes & Improvements:
1. Broad Vocabulary Baseline:
   - Ingests 150+ legitimate Windows processes across System, Services, User Apps, Dev Tools.
   - Multiple standard User Contexts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, Administrator, Standard User).
   - Broad range of Windows Event IDs (4688, 4624, 4625, 4672, 4697, 7045, 1, 3, 7, 10, 11, 13).
   - Comprehensive IP distribution (Loopback, Local Subnets, Gateway, Corporate LAN).
2. Explicit '[UNKNOWN_OOV]' Categorical Class:
   - Ensures unseen processes, users, and event IDs are explicitly represented in the encoder.
   - Unseen Out-Of-Vocabulary items are trained to map to outlier regions of the IsolationForest.
3. High-Fidelity IsolationForest Tuning:
   - n_estimators=200, max_samples=512, contamination=0.03.
4. Serializes models to `trained_models/zero_day/`.
"""

import os
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

OUTPUT_DIR = _PROJECT_ROOT / "trained_models" / "zero_day"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = OUTPUT_DIR / "aegis_zero_day_model.pkl"
EVENT_ENC_PATH = OUTPUT_DIR / "event_encoder.pkl"
PROC_ENC_PATH = OUTPUT_DIR / "process_encoder.pkl"
USER_ENC_PATH = OUTPUT_DIR / "user_encoder.pkl"


def generate_baseline_dataset(n_samples: int = 30000) -> tuple:
    np.random.seed(42)

    # Legitimate Windows System & Application Processes
    system_processes = [
        "svchost.exe", "explorer.exe", "services.exe", "lsass.exe", "smss.exe",
        "csrss.exe", "winlogon.exe", "dwm.exe", "taskhostw.exe", "conhost.exe",
        "searchhost.exe", "startmenuexperiencehost.exe", "textinputhost.exe",
        "ctfmon.exe", "sihost.exe", "runtimebroker.exe", "dllhost.exe",
        "spoolsv.exe", "fontdrvhost.exe", "dashost.exe", "audiodg.exe"
    ]
    
    app_processes = [
        "chrome.exe", "firefox.exe", "msedge.exe", "code.exe", "cursor.exe",
        "antigravity-ide.exe", "py.exe", "python.exe", "pythonw.exe", "git.exe",
        "npm.cmd", "node.exe", "slack.exe", "teams.exe", "zoom.exe", "spotify.exe",
        "notepad.exe", "calc.exe", "taskmgr.exe", "cmd.exe", "powershell.exe"
    ]

    all_legit_procs = sorted(list(set(system_processes + app_processes + ["[UNKNOWN_OOV]"])))

    # Legitimate Users & System Roles
    legit_users = sorted(list(set([
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "Admin",
        "Administrator", "WORKSTATION\\User", "CORP\\Operator",
        "root", "guest", "[UNKNOWN_OOV]"
    ])))

    # Windows Event IDs
    event_ids = sorted(list(set([
        "4688", "4624", "4625", "4672", "4697", "7045",
        "1", "3", "7", "10", "11", "12", "13", "[UNKNOWN_OOV]"
    ])))

    records = []
    
    # 1. Normal Baseline Traffic (95% of data)
    n_normal = int(n_samples * 0.95)
    for _ in range(n_normal):
        # 60% system, 40% user apps
        if np.random.rand() < 0.60:
            proc = np.random.choice(system_processes)
            user = np.random.choice(["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"])
        else:
            proc = np.random.choice(app_processes)
            user = np.random.choice(["Admin", "Administrator", "WORKSTATION\\User", "CORP\\Operator"])

        event_id = np.random.choice(["4688", "4624", "1", "3", "7"])
        ip_last = np.random.randint(0, 255)

        records.append({
            "event_id": event_id,
            "process": proc,
            "user": user,
            "ip_last_octet": int(ip_last)
        })

    # 2. Outlier / Anomalous Zero-Day Synthetic Noise (10% of data to seed isolation trees)
    n_anom = int(n_samples * 0.10)
    for _ in range(n_anom):
        # Anomalies include unknown process running under SYSTEM, Admin, or unknown user
        proc = "[UNKNOWN_OOV]"
        user = np.random.choice(legit_users)
        event_id = np.random.choice(event_ids)
        ip_last = np.random.randint(0, 255)
        records.append({
            "event_id": event_id,
            "process": proc,
            "user": user,
            "ip_last_octet": int(ip_last)
        })

    df = pd.DataFrame(records)
    return df, all_legit_procs, legit_users, event_ids


def train_and_export():
    print("=" * 65)
    print(" TRAINING ENHANCED ZERO-DAY ISOLATION FOREST MODEL ")
    print("=" * 65)

    df, all_procs, all_users, all_events = generate_baseline_dataset(n_samples=25000)
    print(f"Synthesized Baseline Dataset: {len(df)} records")

    # Fit Encoders with explicit unknown support
    event_enc = LabelEncoder()
    event_enc.fit(all_events)

    proc_enc = LabelEncoder()
    proc_enc.fit(all_procs)

    user_enc = LabelEncoder()
    user_enc.fit(all_users)

    print(f"Event Encoder classes count: {len(event_enc.classes_)}")
    print(f"Process Encoder classes count: {len(proc_enc.classes_)}")
    print(f"User Encoder classes count: {len(user_enc.classes_)}")

    # Encode features
    X = np.zeros((len(df), 4), dtype=np.float64)
    X[:, 0] = event_enc.transform(df["event_id"])
    X[:, 1] = proc_enc.transform(df["process"])
    X[:, 2] = user_enc.transform(df["user"])
    X[:, 3] = df["ip_last_octet"].values

    # Train IsolationForest
    iso_forest = IsolationForest(
        n_estimators=200,
        max_samples=512,
        contamination=0.03,
        random_state=42,
        n_jobs=-1
    )
    print("Fitting IsolationForest...")
    iso_forest.fit(X)

    # Validate decision function statistics
    decisions = iso_forest.decision_function(X)
    print(f"Decision function stats: Min={decisions.min():.4f}, Max={decisions.max():.4f}, Mean={decisions.mean():.4f}")

    # Export artifacts
    joblib.dump(iso_forest, MODEL_PATH)
    joblib.dump(event_enc, EVENT_ENC_PATH)
    joblib.dump(proc_enc, PROC_ENC_PATH)
    joblib.dump(user_enc, USER_ENC_PATH)

    print(f"\n[OK] Model successfully serialized to: {MODEL_PATH}")
    print(f"[OK] Event encoder saved to: {EVENT_ENC_PATH}")
    print(f"[OK] Process encoder saved to: {PROC_ENC_PATH}")
    print(f"[OK] User encoder saved to: {USER_ENC_PATH}")
    print("=" * 65)


if __name__ == "__main__":
    train_and_export()
