"""
ml_notebooks/hdfs/train_enhanced_hdfs.py
========================================
Enhanced Robust Training Pipeline for HDFS Log Anomaly Detection Model (Model 5).
"""

import os
import random
from pathlib import Path
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import xgboost as xgb

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = PROJECT_ROOT / "trained_models" / "hdfs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

NORMAL_TEMPLATES = [
    "081109 203518 143 INFO dfs.DataNode$DataXceiver: Receiving block blk_{blk} src: /{ip1}:{port1} dest: /{ip2}:{port2}",
    "081109 203519 143 INFO dfs.DataNode$PacketResponder: PacketResponder {blk} for block blk_{blk} terminating",
    "081109 203519 145 INFO dfs.DataNode$DataXceiver: Received block blk_{blk} of size {size} from /{ip1}",
    "081109 203519 147 INFO dfs.DataNode$BlockReceiver: Verification succeeded for blk_{blk}",
    "081109 203520 23 INFO dfs.FSNamesystem: BLOCK* NameSystem.allocateBlock: /user/hadoop/data_{fid}.csv. blk_{blk}",
    "081109 203520 25 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: {ip1}:{port1} is added to blk_{blk} size {size}",
    "081109 203521 143 INFO dfs.DataNode$DataXceiver: Serving block blk_{blk} to /{ip1}:{port1}",
    "081109 203522 34 INFO dfs.DataBlockScanner: Verification of block blk_{blk} succeeded",
    "081109 203523 12 INFO dfs.DataNode$DataTransfer: Successfully transferred blk_{blk} to /{ip2}:{port2}",
    "081109 203524 45 INFO dfs.DataNode$BlockReceiver: Finalized block blk_{blk} of size {size}",
    "081109 203525 19 INFO dfs.FSNamesystem: BLOCK* ask {ip1}:{port1} to replicate blk_{blk} to datanode(s) {ip2}:{port2}",
    "081109 203526 29 INFO dfs.DataNode: Block blk_{blk} successfully replicated to destination",
]

ANOMALY_TEMPLATES = [
    "081109 203601 143 ERROR dfs.DataNode$DataXceiver: Receiving block blk_{blk} src: /{ip1}:{port1} dest: /{ip2}:{port2} caught java.io.IOException: Connection reset by peer",
    "081109 203602 143 WARN dfs.DataNode$BlockReceiver: Exception in receiveBlock for block blk_{blk} java.net.SocketTimeoutException: 60000 millis timeout while waiting for channel",
    "081109 203603 23 ERROR dfs.FSNamesystem: BLOCK* NameSystem.delete: blk_{blk} is invalid and marked for deletion",
    "081109 203604 147 ERROR dfs.DataNode$BlockReceiver: Block blk_{blk} is corrupted, checksum verification failed: expected {chk1} got {chk2}",
    "081109 203605 143 ERROR dfs.DataNode: java.io.IOException: DiskOutOfSpaceException: No space left on device /data/hdfs/datanode",
    "081109 203606 143 FATAL dfs.DataNode: Unexpected termination of DataNode thread on node {ip1}: OutOfMemoryError",
    "081109 203607 145 WARN dfs.DataNode$DataTransfer: Failed to transfer blk_{blk} to /{ip2}:{port2} got java.io.EOFException",
    "081109 203608 19 ERROR dfs.FSNamesystem: Lost heartbeat from DataNode {ip1}:{port1}, marking node dead",
    "081109 203609 29 ERROR dfs.DataNode: Block blk_{blk} replication failed: ConnectionRefusedException to {ip2}",
    "081109 203610 33 FATAL dfs.DataNode: FileSystem corruption detected while scanning blk_{blk}. Halting service",
    "081109 203611 143 ERROR dfs.DataNode: Block blk_{blk} replica size mismatch: expected {size} got 0",
    "081109 203612 143 WARN dfs.DataNode: DatanodeRegistration failed for {ip1}: InvalidRegistrationException",
    "081109 203613 99 FATAL dfs.FSNamesystem: System audit logs wiped and deleted by root administrator",
    "081109 203614 99 ERROR dfs.AuditLogger: Unauthorized log wiping and log clearing activity detected",
    "081109 203615 99 FATAL dfs.FSNamesystem: Ransomware activity detected: mass deletion of block files blk_{blk}",
]

def generate_ip():
    return f"10.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def generate_sample(template):
    blk = random.randint(1000000000, 9999999999)
    return template.format(
        blk=blk,
        ip1=generate_ip(),
        ip2=generate_ip(),
        port1=random.randint(1024, 65535),
        port2=random.randint(1024, 65535),
        size=random.randint(1024, 67108864),
        fid=random.randint(1, 99999),
        chk1=random.randint(100000, 999999),
        chk2=random.randint(100000, 999999)
    )

def build_dataset(n_normal=15000, n_anomaly=15000):
    texts = []
    labels = []

    for _ in range(n_normal // 2):
        texts.append(generate_sample(random.choice(NORMAL_TEMPLATES)))
        labels.append("Normal")

    for _ in range(n_normal // 2):
        num_lines = random.randint(2, 6)
        session_lines = [generate_sample(random.choice(NORMAL_TEMPLATES)) for _ in range(num_lines)]
        texts.append("\n".join(session_lines))
        labels.append("Normal")

    for _ in range(n_anomaly // 2):
        texts.append(generate_sample(random.choice(ANOMALY_TEMPLATES)))
        labels.append("Anomaly")

    for _ in range(n_anomaly // 2):
        num_lines = random.randint(2, 6)
        session_lines = [generate_sample(random.choice(NORMAL_TEMPLATES)) for _ in range(num_lines - 1)]
        session_lines.append(generate_sample(random.choice(ANOMALY_TEMPLATES)))
        random.shuffle(session_lines)
        texts.append("\n".join(session_lines))
        labels.append("Anomaly")

    return texts, labels

def main():
    print("=" * 65)
    print(" TRAINING ENHANCED HDFS LOG ANOMALY DETECTION MODEL (MODEL 5) ")
    print("=" * 65)

    texts, raw_labels = build_dataset(n_normal=15000, n_anomaly=15000)
    print(f"Generated Dataset: {len(texts)} samples")

    vectorizer = TfidfVectorizer(
        max_features=5000,
        stop_words="english",
        lowercase=True,
        ngram_range=(1, 2),
        token_pattern=r"(?u)\b\w+\b"
    )
    X = vectorizer.fit_transform(texts)

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(raw_labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        eval_metric="logloss"
    )

    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc * 100:.2f}%")

    joblib.dump(clf, OUTPUT_DIR / "hdfs_xgboost_model.pkl")
    joblib.dump(vectorizer, OUTPUT_DIR / "hdfs_vectorizer.pkl")
    joblib.dump(label_encoder, OUTPUT_DIR / "hdfs_label_encoder.pkl")
    print(f"[OK] HDFS saved to {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
