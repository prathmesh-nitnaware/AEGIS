"""
ml_notebooks/windows_advanced_v3/train_enhanced_v3.py
=====================================================
Enhanced Windows Advanced v3 XGBoost Process Context Classifier.

Features (9 dimensions):
  0: cmd_len (float)
  1: enc_flag (0.0 or 1.0 - encoded command)
  2: script_flag (0.0 or 1.0 - PowerShell / cmd / cscript)
  3: anomaly_v3 (0.0 or 1.0 - parent-child anomaly)
  4: il_val (1.0 to 4.0 - integrity level: 1=low, 2=medium, 3=high, 4=system)
  5: net_count (float - count of outbound connections)
  6: masq_ind (0.0 or 1.0 - masquerading indicator)
  7: role_logon (0.0 or 1.0)
  8: role_admin (0.0 or 1.0)

Classes:
  0: Normal
  1: Attack
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier
import joblib

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

OUTPUT_DIR = _PROJECT_ROOT / "trained_models" / "windows_advanced_v3"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = OUTPUT_DIR / "windows_advanced_v3.pkl"

FEATURE_NAMES = [
    "command_line_length",
    "encoded_command_flag",
    "scripting_indicator",
    "parent_child_anomaly_v3",
    "integrity_level_numeric",
    "network_conn_count",
    "masquerading_indicator",
    "process_role_logon",
    "process_role_admin"
]


def generate_process_dataset(n_samples: int = 20000) -> tuple:
    np.random.seed(42)

    X_list = []
    y_list = []

    # 1. Normal Process Contexts (70% of dataset)
    n_normal = int(n_samples * 0.70)
    for _ in range(n_normal):
        archetype = np.random.choice(["system_service", "explorer_child", "developer_tool", "cli_normal"])
        
        if archetype == "system_service":
            # svchost, dwm, services
            cmd_len = np.random.randint(20, 150)
            enc_flag = 0.0
            script_flag = 0.0
            anomaly = 0.0
            il = 4.0  # System
            net_count = np.random.choice([0.0, 1.0, 2.0], p=[0.7, 0.2, 0.1])
            masq = 0.0
            role_logon = 1.0 if np.random.rand() < 0.3 else 0.0
            role_admin = 0.0
        elif archetype == "explorer_child":
            # chrome, calc, notepad, word
            cmd_len = np.random.randint(10, 300)
            enc_flag = 0.0
            script_flag = 0.0
            anomaly = 0.0
            il = np.random.choice([2.0, 3.0], p=[0.8, 0.2])  # Medium / High
            net_count = np.random.randint(0, 15)
            masq = 0.0
            role_logon = 0.0
            role_admin = 0.0
        elif archetype == "developer_tool":
            # code, python, npm, git
            cmd_len = np.random.randint(30, 800)
            enc_flag = 0.0
            script_flag = 1.0 if np.random.rand() < 0.2 else 0.0
            anomaly = 0.0
            il = 2.0  # Medium
            net_count = np.random.randint(0, 10)
            masq = 0.0
            role_logon = 0.0
            role_admin = 0.0
        else:
            # cmd / powershell running normal scripts
            cmd_len = np.random.randint(15, 200)
            enc_flag = 0.0
            script_flag = 1.0
            anomaly = 0.0
            il = 2.0
            net_count = 0.0
            masq = 0.0
            role_logon = 0.0
            role_admin = 1.0

        vec = [cmd_len, enc_flag, script_flag, anomaly, il, net_count, masq, role_logon, role_admin]
        X_list.append(vec)
        y_list.append(0)  # Normal

    # 2. Attack Process Contexts (30% of dataset)
    n_attack = n_samples - n_normal
    for _ in range(n_attack):
        attack_type = np.random.choice([
            "encoded_powershell", "vssadmin_ransomware", "mimikatz_dump",
            "masqueraded_binary", "suspicious_parent_spawn", "reverse_shell"
        ])

        if attack_type == "encoded_powershell":
            cmd_len = np.random.randint(1200, 15000)
            enc_flag = 1.0
            script_flag = 1.0
            anomaly = 1.0
            il = np.random.choice([2.0, 3.0, 4.0])
            net_count = np.random.randint(1, 20)
            masq = 0.0
            role_logon = 0.0
            role_admin = 1.0
        elif attack_type == "vssadmin_ransomware":
            cmd_len = np.random.randint(80, 400)
            enc_flag = 0.0
            script_flag = 1.0
            anomaly = 1.0
            il = 3.0  # High privilege
            net_count = 0.0
            masq = 0.0
            role_logon = 0.0
            role_admin = 1.0
        elif attack_type == "mimikatz_dump":
            cmd_len = np.random.randint(60, 300)
            enc_flag = 0.0
            script_flag = 0.0
            anomaly = 1.0
            il = 4.0  # System
            net_count = np.random.randint(0, 5)
            masq = 0.0
            role_logon = 0.0
            role_admin = 1.0
        elif attack_type == "masqueraded_binary":
            cmd_len = np.random.randint(50, 500)
            enc_flag = 0.0
            script_flag = 0.0
            anomaly = 1.0
            il = 2.0
            net_count = np.random.randint(1, 10)
            masq = 1.0  # Masquerading in non-system dir
            role_logon = 0.0
            role_admin = 0.0
        elif attack_type == "suspicious_parent_spawn":
            # Word or Excel spawning cmd/powershell
            cmd_len = np.random.randint(100, 1000)
            enc_flag = np.random.choice([0.0, 1.0])
            script_flag = 1.0
            anomaly = 1.0
            il = 2.0
            net_count = np.random.randint(1, 8)
            masq = 0.0
            role_logon = 0.0
            role_admin = 0.0
        else:
            # Reverse shell / C2 beacon
            cmd_len = np.random.randint(100, 2500)
            enc_flag = np.random.choice([0.0, 1.0])
            script_flag = 1.0
            anomaly = 1.0
            il = np.random.choice([2.0, 3.0])
            net_count = np.random.randint(2, 50)
            masq = 0.0
            role_logon = 0.0
            role_admin = 1.0

        vec = [cmd_len, enc_flag, script_flag, anomaly, il, net_count, masq, role_logon, role_admin]
        X_list.append(vec)
        y_list.append(1)  # Attack

    X = np.array(X_list, dtype=np.float64)
    y = np.array(y_list, dtype=np.int64)
    return X, y


def train_and_export():
    print("=" * 65)
    print(" TRAINING ROBUST WINDOWS ADVANCED V3 XGBOOST MODEL ")
    print("=" * 65)

    X, y = generate_process_dataset(n_samples=25000)
    print(f"Generated Dataset: {X.shape[0]} samples, {X.shape[1]} features")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    xgb = XGBClassifier(
        n_estimators=160,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    print("Fitting XGBClassifier...")
    xgb.fit(X_train, y_train)

    y_pred = xgb.predict(X_test)
    y_probs = xgb.predict_proba(X_test)[:, 1]
    acc = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy on Test Set: {acc * 100:.2f}%\n")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    payload = {
        "model": xgb,
        "threshold": 0.90,
        "features": FEATURE_NAMES,
        "feature_names": FEATURE_NAMES,
        "feature_count": 9,
        "feature_version": "v3",
        "model_version": "windows_advanced_v3",
        "probability_type": "raw_xgboost_probability",
        "random_seed": 42,
        "model_hyperparameters": {
            "n_estimators": 160,
            "max_depth": 5,
            "learning_rate": 0.08,
            "subsample": 0.85,
            "colsample_bytree": 0.85,
        },
        "training_date": "2026-09-14",
    }

    joblib.dump(payload, MODEL_PATH)
    print(f"[OK] Windows Advanced v3 payload serialized to: {MODEL_PATH}")
    print("=" * 65)


if __name__ == "__main__":
    train_and_export()
