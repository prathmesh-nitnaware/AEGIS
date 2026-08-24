import json
import os
import sys
import pickle
from pathlib import Path
from datetime import datetime, timezone
import numpy as np
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc, confusion_matrix
)
try:
    import xgboost as xgb
except ImportError:
    xgb = None

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from agent.windows_process_context import (
    WindowsProcessContextAggregator,
    ProcessContextState,
    WindowsAdvancedV3FeatureExtractor
)

# Path configuration
_TEMP_DIR = Path("C:/Users/Admin/.gemini/antigravity-ide/brain/f40c5c1b-dc84-4324-a42b-8703f26c8191/scratch/otrf_temp")
_MODEL_DIR = Path("d:/AEGIS/trained_models/windows_advanced_v3")
_MODEL_DIR.mkdir(parents=True, exist_ok=True)

def parse_guid_or_pid(val):
    if not val:
        return None
    if isinstance(val, str) and val.startswith("0x"):
        try:
            return int(val, 16)
        except ValueError:
            return val
    try:
        return int(val)
    except ValueError:
        return val

def label_process(state: ProcessContextState) -> str:
    image_name = Path(state.image).name.lower() if state.image else ""
    cmd_lower = state.command_line.lower() if state.command_line else ""
    parent_name = Path(state.parent_image).name.lower() if state.parent_image else ""
    parent_cmd_lower = state.parent_command_line.lower() if state.parent_command_line else ""
    
    # Behavior-based attacker indicator keywords
    attack_keywords = [
        "monkey.png", "bitmap", "bypass", "hidden", "sharpview", "seatbelt",
        "psexec", "sdelete", "advfirewall firewall", "sdclt.exe", "schtasks",
        "mimikatz", "sekurlsa", "get-objectacl", "lsass"
    ]
    
    if any(k in cmd_lower for k in attack_keywords):
        return "Attack"
        
    if parent_name in ("powershell.exe", "pwsh.exe", "cmd.exe", "psexec64.exe"):
        if any(k in parent_cmd_lower for k in attack_keywords):
            return "Attack"
            
    if "psexec" in image_name or "sdelete" in image_name:
        return "Attack"

    return "Normal"

def load_data():
    aggregator = WindowsProcessContextAggregator(max_processes=100000)
    all_events = []
    
    files = [f for f in os.listdir(_TEMP_DIR) if f.startswith("apt29_evals") and f.endswith(".json")]
    
    for filename in files:
        filepath = _TEMP_DIR / filename
        day_label = "day1" if "day1" in filename else "day2"
        print(f"Ingesting {filename} as {day_label}...")
        
        with open(filepath, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f):
                try:
                    data = json.loads(line)
                    ev_id = data.get("EventID") or data.get("event_id")
                    if ev_id is None:
                        ev_id = data.get("System", {}).get("EventID")
                    if ev_id is None:
                        continue
                        
                    ev_id = int(ev_id)
                    time_created = data.get("TimeCreated") or data.get("@timestamp")
                    
                    if ev_id == 1:
                        agg_event = {
                            "event_id": 1,
                            "process_guid": data.get("ProcessGuid"),
                            "pid": parse_guid_or_pid(data.get("ProcessId")),
                            "image": data.get("Image", ""),
                            "command_line": data.get("CommandLine", ""),
                            "user": data.get("User", ""),
                            "integrity_level": data.get("IntegrityLevel", ""),
                            "parent_process_guid": data.get("ParentProcessGuid"),
                            "parent_pid": parse_guid_or_pid(data.get("ParentProcessId")),
                            "parent_image": data.get("ParentImage", ""),
                            "parent_command_line": data.get("ParentCommandLine", ""),
                            "time": time_created,
                            "campaign": day_label
                        }
                        all_events.append(agg_event)
                        
                    elif ev_id == 4688:
                        new_pid = parse_guid_or_pid(data.get("NewProcessId"))
                        parent_pid = parse_guid_or_pid(data.get("ProcessId"))
                        label = data.get("MandatoryLabel", "")
                        il = "Medium"
                        if "S-1-16-16384" in label:
                            il = "System"
                        elif "S-1-16-12288" in label:
                            il = "High"
                        elif "S-1-16-4096" in label:
                            il = "Low"
                            
                        agg_event = {
                            "event_id": 1,
                            "process_guid": data.get("ProcessGuid") or f"GUID_4688_{new_pid}_{time_created}",
                            "pid": new_pid,
                            "image": data.get("NewProcessName", ""),
                            "command_line": data.get("CommandLine", ""),
                            "user": data.get("SubjectUserName", ""),
                            "integrity_level": il,
                            "parent_process_guid": None,
                            "parent_pid": parent_pid,
                            "parent_image": data.get("ParentProcessName", ""),
                            "parent_command_line": "",
                            "time": time_created,
                            "campaign": day_label
                        }
                        all_events.append(agg_event)
                        
                    elif ev_id == 3:
                        agg_event = {
                            "event_id": 3,
                            "process_guid": data.get("ProcessGuid"),
                            "pid": parse_guid_or_pid(data.get("ProcessId")),
                            "destination_ip": data.get("DestinationIp", ""),
                            "destination_port": parse_guid_or_pid(data.get("DestinationPort")),
                            "time": time_created,
                            "campaign": day_label
                        }
                        all_events.append(agg_event)
                        
                    elif ev_id == 5156:
                        pid = parse_guid_or_pid(data.get("ProcessID"))
                        agg_event = {
                            "event_id": 3,
                            "process_guid": f"GUID_4688_{pid}_{time_created}",
                            "pid": pid,
                            "destination_ip": data.get("DestAddress", ""),
                            "destination_port": parse_guid_or_pid(data.get("DestPort")),
                            "time": time_created,
                            "campaign": day_label
                        }
                        all_events.append(agg_event)
                except Exception:
                    pass

    print(f"Total events ingested: {len(all_events)}")
    all_events.sort(key=lambda x: x["time"])
    
    # Replay events
    for ev in all_events:
        aggregator.process_event(ev)
        
    print(f"Processes reconstructed in aggregator: {len(aggregator.processes)}")
    
    X = []
    y = []
    groups = []
    metadata = []
    
    for guid, state in aggregator.processes.items():
        campaign = getattr(state, "campaign", "day1")
        for ev in all_events:
            if ev["event_id"] == 1 and ev["process_guid"] == guid:
                campaign = ev["campaign"]
                break
                
        lbl_str = label_process(state)
        lbl_val = 1 if lbl_str == "Attack" else 0
        
        # USE THE CANONICAL V3 EXTRACTOR HERE
        feats = WindowsAdvancedV3FeatureExtractor.extract_features(state)
        
        X.append(feats)
        y.append(lbl_val)
        groups.append(campaign)
        metadata.append({
            "guid": guid,
            "image": state.image,
            "command_line": state.command_line,
            "campaign": campaign
        })
        
    return np.array(X), np.array(y), np.array(groups), metadata

def evaluate_thresholds(X, y, groups, clf, clf_label):
    print(f"\n=================== {clf_label} Threshold Evaluation (OOF) ===================")
    gkf = GroupKFold(n_splits=2)
    
    # Get out-of-fold probability predictions
    oof_probs = np.zeros(len(y))
    for train_idx, test_idx in gkf.split(X, y, groups):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        
        clf.fit(X_train, y_train)
        oof_probs[test_idx] = clf.predict_proba(X_test)[:, 1]
        
    print(f"{'Threshold':<10} | {'TN':<5} | {'FP':<5} | {'FN':<5} | {'TP':<5} | {'FPR':<8} | {'Recall':<8} | {'Precision':<10} | {'F1':<8}")
    print("-" * 75)
    for th in [0.50, 0.60, 0.70, 0.80, 0.85, 0.90, 0.95, 0.99]:
        preds = (oof_probs >= th).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, preds).ravel()
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        print(f"{th:<10.2f} | {tn:<5} | {fp:<5} | {fn:<5} | {tp:<5} | {fpr:<8.2%} | {recall:<8.2%} | {precision:<10.2%} | {f1:<8.4f}")

def main():
    X, y, groups, metadata = load_data()
    print(f"\nFeatures shape: {X.shape}")
    print(f"Label distribution: {dict(Counter(y))}")
    print(f"Groups distribution: {dict(Counter(groups))}")
    
    # Base XGBoost estimator configuration matching V2
    scale_weight = np.sum(y == 0) / np.sum(y == 1) if np.sum(y == 1) > 0 else 1.0
    
    xgb_clf = None
    if xgb:
        xgb_clf = xgb.XGBClassifier(
            n_estimators=100, max_depth=4, scale_pos_weight=scale_weight,
            use_label_encoder=False, eval_metric="logloss", random_state=42
        )
        evaluate_thresholds(X, y, groups, xgb_clf, "XGBoost V3")
        
    rf_clf = RandomForestClassifier(n_estimators=100, max_depth=4, class_weight="balanced", random_state=42)
    evaluate_thresholds(X, y, groups, rf_clf, "Random Forest V3")
    
    if xgb_clf is None:
        print("XGBoost not available. Exiting.")
        return
        
    print("\nTraining final XGBoost model on full dataset...")
    xgb_clf.fit(X, y)
    
    # Save the V3 model and metadata payload
    model_path = _MODEL_DIR / "windows_advanced_v3.pkl"
    print(f"Saving final model payload to {model_path}...")
    
    payload = {
        "model": xgb_clf,
        "model_version": "windows_advanced_v3",
        "feature_version": "v3",
        "feature_names": WindowsAdvancedV3FeatureExtractor.FEATURE_NAMES,
        "feature_count": len(WindowsAdvancedV3FeatureExtractor.FEATURE_NAMES),
        "class_mapping": {0: "Normal", 1: "Attack"},
        "threshold": 0.90,
        "probability_type": "raw_xgboost_probability",
        "training_dataset_identifier": "OTRF APT29 Day1 & Day2",
        "evaluation_methodology": "GroupKFold by campaign day",
        "random_seed": 42,
        "model_hyperparameters": {
            "n_estimators": 100,
            "max_depth": 4,
            "scale_pos_weight": scale_weight,
            "eval_metric": "logloss",
            "random_state": 42
        },
        "training_date": "2026-08-24"
    }
    
    with open(model_path, "wb") as f:
        pickle.dump(payload, f)
        
    print("V3 Model Serialization completed successfully!")

if __name__ == "__main__":
    main()
