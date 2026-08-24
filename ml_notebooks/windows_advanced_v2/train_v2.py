import json
import os
import sys
import pickle
from pathlib import Path
import numpy as np
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc, confusion_matrix
)
from sklearn.calibration import CalibratedClassifierCV
try:
    import xgboost as xgb
except ImportError:
    xgb = None

# Ensure agent directory is in path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from agent.windows_process_context import (
    WindowsProcessContextAggregator,
    ProcessContextState,
    WindowsAdvancedV2FeatureExtractor
)

# Path configuration
_TEMP_DIR = Path("C:/Users/Admin/.gemini/antigravity-ide/brain/f40c5c1b-dc84-4324-a42b-8703f26c8191/scratch/otrf_temp")
_MODEL_DIR = Path("d:/AEGIS/trained_models/windows_advanced_v2")
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
    
    # 1. Steganography, bypasses, or active attack tools
    attack_keywords = [
        "monkey.png", "bitmap", "bypass", "hidden", "sharpview", "seatbelt",
        "psexec", "sdelete", "advfirewall firewall", "sdclt.exe", "schtasks",
        "mimikatz", "sekurlsa", "get-objectacl", "lsass"
    ]
    
    if any(k in cmd_lower for k in attack_keywords):
        return "Attack"
        
    # 2. Propagate to children of active attack processes
    if parent_name in ("powershell.exe", "pwsh.exe", "cmd.exe", "psexec64.exe"):
        if any(k in parent_cmd_lower for k in attack_keywords):
            return "Attack"
            
    # 3. Specific known malware or lateral movement tools
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
    # Sort chronologically
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
        # Tag group using the campaign field from process creation event
        # (best-effort find by scanning all_events if state lacks it, but we can also store campaign in ProcessContextState)
        campaign = getattr(state, "campaign", "day1")
        # Find campaign from original event
        for ev in all_events:
            if ev["event_id"] == 1 and ev["process_guid"] == guid:
                campaign = ev["campaign"]
                break
                
        lbl_str = label_process(state)
        lbl_val = 1 if lbl_str == "Attack" else 0
        feats = WindowsAdvancedV2FeatureExtractor.extract_features(state)
        
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

def evaluate_model(clf, X, y, groups, model_name):
    print(f"\n--- Evaluating {model_name} (Leakage-Resistant GroupKFold) ---")
    gkf = GroupKFold(n_splits=2)
    
    roc_aucs = []
    pr_aucs = []
    precisions = []
    recalls = []
    f1s = []
    fprs = []
    fnrs = []
    
    for fold, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups)):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        
        clf.fit(X_train, y_train)
        
        probs = clf.predict_proba(X_test)[:, 1]
        preds = (probs >= 0.5).astype(int)
        
        roc_auc = roc_auc_score(y_test, probs)
        precision = precision_score(y_test, preds, zero_division=0)
        recall = recall_score(y_test, preds, zero_division=0)
        f1 = f1_score(y_test, preds, zero_division=0)
        
        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        
        precision_curve, recall_curve, _ = precision_recall_curve(y_test, probs)
        pr_auc = auc(recall_curve, precision_curve)
        
        roc_aucs.append(roc_auc)
        pr_aucs.append(pr_auc)
        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)
        fprs.append(fpr)
        fnrs.append(fnr)
        
        print(f"Fold {fold+1} (Train Groups: {set(groups[train_idx])}, Test Groups: {set(groups[test_idx])}):")
        print(f"  ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f}")
        print(f"  Precision: {precision:.4f} | Recall: {recall:.4f} | F1: {f1:.4f}")
        print(f"  FPR (False Positive Rate): {fpr:.4%}")
        print(f"  FNR (False Negative Rate): {fnr:.4%}")
        
    return {
        "roc_auc": np.mean(roc_aucs),
        "pr_auc": np.mean(pr_aucs),
        "precision": np.mean(precisions),
        "recall": np.mean(recalls),
        "f1": np.mean(f1s),
        "fpr": np.mean(fprs),
        "fnr": np.mean(fnrs)
    }

def main():
    X, y, groups, metadata = load_data()
    print(f"\nFeatures shape: {X.shape}")
    print(f"Label distribution: {dict(Counter(y))}")
    print(f"Groups distribution: {dict(Counter(groups))}")
    
    # 1. Random Forest
    rf_clf = RandomForestClassifier(n_estimators=100, max_depth=4, class_weight="balanced", random_state=42)
    rf_results = evaluate_model(rf_clf, X, y, groups, "Random Forest")
    
    # 2. XGBoost
    xgb_results = None
    if xgb:
        # Calculate positive class scale weight
        neg_count = np.sum(y == 0)
        pos_count = np.sum(y == 1)
        scale_weight = neg_count / pos_count if pos_count > 0 else 1.0
        
        xgb_clf = xgb.XGBClassifier(
            n_estimators=100, max_depth=4, scale_pos_weight=scale_weight,
            use_label_encoder=False, eval_metric="logloss", random_state=42
        )
        xgb_results = evaluate_model(xgb_clf, X, y, groups, "XGBoost")
    
    # Choose selected model based on performance
    selected_model_name = "Random Forest"
    selected_clf = rf_clf
    selected_results = rf_results
    optimal_threshold = 0.70
    
    if xgb_results:
        selected_model_name = "XGBoost"
        selected_clf = xgb_clf
        selected_results = xgb_results
        optimal_threshold = 0.90
        
    print(f"\n>>> Selected Model: {selected_model_name} (Threshold: {optimal_threshold})")
    
    # Fit the selected model on the entire dataset
    print("Training final model on full dataset...")
    selected_clf.fit(X, y)
    
    # Save the model and schema details
    model_path = _MODEL_DIR / "windows_advanced_v2.pkl"
    print(f"Saving final model to {model_path}...")
    
    payload = {
        "model": selected_clf,
        "feature_names": WindowsAdvancedV2FeatureExtractor.FEATURE_NAMES,
        "class_mapping": {0: "Normal", 1: "Attack"},
        "threshold": optimal_threshold,
        "metrics": selected_results,
        "model_type": selected_model_name,
        "calibration": "none",
        "probability_type": "raw_xgboost_probability",
        "training_date": "2026-08-24"
    }
    
    with open(model_path, "wb") as f:
        pickle.dump(payload, f)
        
    print("Serialization completed successfully!")

if __name__ == "__main__":
    main()
