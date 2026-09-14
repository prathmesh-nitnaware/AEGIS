"""
ml_notebooks/cicids/train_enhanced_cicids.py
============================================
Enhanced Robust Training Pipeline for CICIDS Network Flow Model (Model 3).
"""

import os
import random
from pathlib import Path
import joblib
import numpy as np
import lightgbm as lgb
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = PROJECT_ROOT / "trained_models" / "cicids"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CICIDS_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean',
    'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

CLASSES = [
    'BENIGN',
    'Bot',
    'DDoS',
    'DoS GoldenEye',
    'DoS Hulk',
    'DoS Slowhttptest',
    'DoS slowloris',
    'FTP-Patator',
    'Heartbleed',
    'Infiltration',
    'PortScan',
    'SSH-Patator',
    'Web Attack - Brute Force',
    'Web Attack - Sql Injection',
    'Web Attack - XSS'
]

def generate_flow_sample(cls_name: str) -> dict:
    f = {k: 0.0 for k in CICIDS_FEATURES}
    
    if cls_name == 'BENIGN':
        ptype = random.choice(["http", "https", "dns", "generic"])
        if ptype == "dns":
            f['Destination Port'] = 53.0
            f['Flow Duration'] = float(random.randint(100, 20000))
            f['Total Fwd Packets'] = float(random.randint(1, 3))
            f['Total Backward Packets'] = float(random.randint(1, 3))
            f['Total Length of Fwd Packets'] = float(random.randint(30, 200))
            f['Total Length of Bwd Packets'] = float(random.randint(50, 500))
            f['Flow IAT Mean'] = float(random.randint(100, 5000))
            f['Average Packet Size'] = float(random.randint(40, 150))
        elif ptype == "https":
            f['Destination Port'] = 443.0
            f['Flow Duration'] = float(random.randint(10000, 5000000))
            f['Total Fwd Packets'] = float(random.randint(5, 50))
            f['Total Backward Packets'] = float(random.randint(5, 60))
            f['Total Length of Fwd Packets'] = float(random.randint(500, 25000))
            f['Total Length of Bwd Packets'] = float(random.randint(1000, 100000))
            f['Fwd Packet Length Mean'] = float(random.randint(80, 1200))
            f['Bwd Packet Length Mean'] = float(random.randint(100, 1400))
            f['Flow IAT Mean'] = float(random.randint(1000, 20000))
            f['ACK Flag Count'] = float(random.randint(5, 60))
            f['SYN Flag Count'] = 1.0
            f['FIN Flag Count'] = 1.0
        elif ptype == "http":
            f['Destination Port'] = 80.0
            f['Flow Duration'] = float(random.randint(5000, 2000000))
            f['Total Fwd Packets'] = float(random.randint(3, 30))
            f['Total Backward Packets'] = float(random.randint(3, 40))
            f['Total Length of Fwd Packets'] = float(random.randint(200, 10000))
            f['Total Length of Bwd Packets'] = float(random.randint(500, 50000))
            f['ACK Flag Count'] = float(random.randint(3, 30))
        else:
            f['Destination Port'] = float(random.choice([22, 3389, 8080, random.randint(1024, 65535)]))
            f['Flow Duration'] = float(random.randint(500, 1000000))
            f['Total Fwd Packets'] = float(random.randint(1, 20))
            f['Total Backward Packets'] = float(random.randint(0, 20))
            f['Total Length of Fwd Packets'] = float(random.randint(50, 10000))
            f['Total Length of Bwd Packets'] = float(random.randint(0, 20000))
            f['ACK Flag Count'] = float(random.randint(0, 20))
            
    elif cls_name == 'PortScan':
        f['Destination Port'] = float(random.randint(1, 65535))
        f['Flow Duration'] = float(random.randint(5, 1000))
        f['Total Fwd Packets'] = float(random.randint(1, 2))
        f['Total Backward Packets'] = 0.0
        f['Total Length of Fwd Packets'] = 0.0
        f['Total Length of Bwd Packets'] = 0.0
        f['SYN Flag Count'] = float(random.randint(1, 4))
        f['ACK Flag Count'] = 0.0
        f['Fwd Packets/s'] = float(random.uniform(500.0, 50000.0))
        f['Flow Packets/s'] = f['Fwd Packets/s']
        f['Average Packet Size'] = 0.0
        
    elif cls_name == 'DDoS':
        f['Destination Port'] = float(random.choice([80, 443]))
        f['Flow Duration'] = float(random.randint(100, 10000))
        f['Total Fwd Packets'] = float(random.randint(100, 3000))
        f['Total Backward Packets'] = 0.0
        f['Total Length of Fwd Packets'] = 0.0
        f['SYN Flag Count'] = float(random.randint(100, 3000))
        f['Flow Packets/s'] = float(random.uniform(50000.0, 1000000.0))
        f['Fwd Packets/s'] = f['Flow Packets/s']
        f['ACK Flag Count'] = 0.0
        
    elif cls_name == 'DoS Hulk':
        f['Destination Port'] = 80.0
        f['Flow Duration'] = float(random.randint(5000, 200000))
        f['Total Fwd Packets'] = float(random.randint(50, 1500))
        f['Flow Packets/s'] = float(random.uniform(2000.0, 100000.0))
        f['Fwd Packet Length Mean'] = float(random.randint(300, 800))
        f['PSH Flag Count'] = float(random.randint(20, 500))
        
    elif cls_name == 'DoS GoldenEye':
        f['Destination Port'] = 80.0
        f['Flow Duration'] = float(random.randint(20000, 500000))
        f['Total Fwd Packets'] = float(random.randint(30, 800))
        f['Flow Packets/s'] = float(random.uniform(500.0, 20000.0))
        f['Bwd Packet Length Mean'] = float(random.randint(100, 500))
        
    elif cls_name == 'DoS slowloris':
        f['Destination Port'] = 80.0
        f['Flow Duration'] = float(random.randint(2000000, 120000000))
        f['Total Fwd Packets'] = float(random.randint(5, 50))
        f['Flow IAT Mean'] = float(random.uniform(500000.0, 5000000.0))
        f['Flow Packets/s'] = float(random.uniform(0.001, 0.1))
        
    elif cls_name == 'DoS Slowhttptest':
        f['Destination Port'] = 80.0
        f['Flow Duration'] = float(random.randint(1000000, 60000000))
        f['Total Fwd Packets'] = float(random.randint(10, 80))
        f['Flow IAT Mean'] = float(random.uniform(200000.0, 2000000.0))
        f['Flow Packets/s'] = float(random.uniform(0.01, 0.5))
        
    elif cls_name == 'FTP-Patator':
        f['Destination Port'] = 21.0
        f['Flow Duration'] = float(random.randint(1000, 100000))
        f['Total Fwd Packets'] = float(random.randint(4, 50))
        f['Total Backward Packets'] = float(random.randint(4, 50))
        f['PSH Flag Count'] = float(random.randint(2, 10))
        f['RST Flag Count'] = float(random.randint(1, 10))
        
    elif cls_name == 'SSH-Patator':
        f['Destination Port'] = 22.0
        f['Flow Duration'] = float(random.randint(1000, 100000))
        f['Total Fwd Packets'] = float(random.randint(10, 100))
        f['Total Backward Packets'] = float(random.randint(10, 100))
        f['Total Length of Fwd Packets'] = float(random.randint(1000, 15000))
        f['Total Length of Bwd Packets'] = float(random.randint(1000, 15000))
        f['PSH Flag Count'] = float(random.randint(5, 30))
        f['RST Flag Count'] = float(random.randint(2, 20))
        f['ACK Flag Count'] = float(random.randint(10, 150))
        f['Flow IAT Mean'] = float(random.uniform(10.0, 500.0))
        
    elif cls_name == 'Heartbleed':
        f['Destination Port'] = 443.0
        f['Total Fwd Packets'] = float(random.randint(1, 3))
        f['Total Backward Packets'] = float(random.randint(10, 50))
        f['Total Length of Bwd Packets'] = float(random.randint(30000, 65535))
        f['Bwd Packet Length Max'] = float(random.randint(16384, 65535))
        
    elif cls_name == 'Bot':
        f['Destination Port'] = float(random.choice([6667, 8080, 4444, 1337]))
        f['Flow Duration'] = float(random.randint(50000, 10000000))
        f['Fwd IAT Mean'] = float(random.uniform(10000.0, 100000.0))
        f['Fwd IAT Std'] = float(random.uniform(0.1, 50.0))
        f['Total Fwd Packets'] = float(random.randint(5, 100))
        
    elif cls_name == 'Infiltration':
        f['Destination Port'] = float(random.choice([4444, 5555, 8888, 9999]))
        f['Flow Duration'] = float(random.randint(100000, 50000000))
        f['Total Length of Fwd Packets'] = float(random.randint(500000, 50000000))
        f['Total Length of Bwd Packets'] = float(random.randint(100, 10000))
        
    elif cls_name == 'Web Attack - Brute Force':
        f['Destination Port'] = float(random.choice([80, 443, 8080]))
        f['Flow Duration'] = float(random.randint(2000, 50000))
        f['Fwd Packet Length Mean'] = float(random.randint(350, 600))
        f['PSH Flag Count'] = float(random.randint(3, 12))
        
    elif cls_name == 'Web Attack - Sql Injection':
        f['Destination Port'] = float(random.choice([80, 443, 8080]))
        f['Flow Duration'] = float(random.randint(1000, 20000))
        f['Fwd Packet Length Mean'] = float(random.randint(800, 2500))
        f['Fwd Packet Length Max'] = float(random.randint(2500, 8000))
        f['PSH Flag Count'] = float(random.randint(1, 5))
        
    elif cls_name == 'Web Attack - XSS':
        f['Destination Port'] = float(random.choice([80, 443, 8080]))
        f['Flow Duration'] = float(random.randint(1000, 20000))
        f['Fwd Packet Length Mean'] = float(random.randint(600, 1200))
        f['Fwd Packet Length Max'] = float(random.randint(1200, 3000))
        f['PSH Flag Count'] = float(random.randint(1, 5))
        
    return f

def build_dataset(samples_per_class=3000):
    X_rows = []
    y_labels = []

    for cls in CLASSES:
        n_samples = samples_per_class * 2 if cls == 'BENIGN' else samples_per_class
        for _ in range(n_samples):
            sample = generate_flow_sample(cls)
            row = [sample[feat] for feat in CICIDS_FEATURES]
            
            # Sparse flow resilience: Apply to BOTH Benign and Attack
            if random.random() < 0.25:
                # Keep active features
                active_keys = [k for k, v in sample.items() if v > 0]
                if len(active_keys) > 3:
                    subset_keys = random.sample(active_keys, random.randint(2, len(active_keys)))
                    sparse_row = [sample[feat] if feat in subset_keys else 0.0 for feat in CICIDS_FEATURES]
                    X_rows.append(sparse_row)
                    y_labels.append(cls)
            
            X_rows.append(row)
            y_labels.append(cls)

    return np.array(X_rows, dtype=np.float64), y_labels

def main():
    print("=" * 65)
    print(" TRAINING ENHANCED CICIDS NETWORK FLOW MODEL (MODEL 3) ")
    print("=" * 65)

    X, raw_labels = build_dataset(samples_per_class=3000)
    print(f"Generated Dataset: {X.shape[0]} samples, {X.shape[1]} features")

    le = LabelEncoder()
    le.fit(CLASSES)
    y = le.transform(raw_labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = lgb.LGBMClassifier(
        n_estimators=300,
        num_leaves=63,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        objective="multiclass",
        num_class=len(CLASSES),
        verbose=-1
    )

    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy on Test Set: {acc * 100:.2f}%\n")

    export_dict = {
        "model": clf,
        "label_encoder": le,
        "features": CICIDS_FEATURES,
        "version": "aegis-cicids-v2-hardened",
        "metadata": {
            "accuracy": float(acc),
            "num_features": len(CICIDS_FEATURES),
            "classes": list(le.classes_),
            "framework": "lightgbm",
            "sparse_resilient": True
        }
    }

    joblib.dump(export_dict, OUTPUT_DIR / "aegis_lgbm_cicids_model.pkl")
    print(f"[OK] Saved hardened CICIDS model to: {OUTPUT_DIR / 'aegis_lgbm_cicids_model.pkl'}")

if __name__ == "__main__":
    main()
