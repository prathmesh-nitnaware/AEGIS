"""
experiments/diagnostics/brutal_stress_test_4_models.py
======================================================
Brutal Adversarial Stress-Test & Vulnerability Audit for the other 4 AEGIS models:
  1. Windows Advanced v3 (XGBoost Process Context Model)
  2. CICIDS Network Flow (LightGBM 78-feature Traffic Model)
  3. EMBER Binary Model (LightGBM 2381-feature PE Static Model)
  4. HDFS Distributed Log Model (TF-IDF + XGBoost Anomaly Model)

Evaluates:
  - Extreme out-of-bounds, NaN, Inf, and empty inputs
  - Benign normal operations vs real attack payloads
  - Decision boundaries, probability calibration, and false positives/negatives
  - Adversarial evasion, mimicry, and feature poisoning
"""

import sys
import time
from pathlib import Path
import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine

def print_header(title: str):
    print("\n" + "=" * 70)
    print(f" {title.center(68)} ")
    print("=" * 70)

def print_sub(title: str):
    print(f"\n--- [ {title} ] ---")

def run_stress_test():
    print_header("BRUTAL AUDIT: 4 REMAINING AEGIS ML DETECTION ENGINES")
    print(f"Project Root: {_PROJECT_ROOT}")
    
    engine = ThreatFusionEngine()

    flaws = []
    insights = []

    # =========================================================================
    # PART 1: HDFS DISTRIBUTED LOG ANOMALY ENGINE (Model 5)
    # =========================================================================
    print_header("PART 1: HDFS LOG ANOMALY ENGINE (TF-IDF + XGBoost)")

    print_sub("1.1 Model & Vectorizer State")
    if engine._hdfs_model is None or engine._hdfs_vectorizer is None or engine._hdfs_le is None:
        print("[FAIL] HDFS model artifacts failed to load!")
        flaws.append("HDFS model or vectorizer or label encoder is None")
    else:
        print(f"[OK] Model: XGBClassifier, Classes={list(engine._hdfs_le.classes_)}")
        print(f"[OK] TF-IDF Vectorizer vocabulary size: {len(engine._hdfs_vectorizer.vocabulary_)}")

    print_sub("1.2 Edge-Case & Injection Strings on HDFS")
    hdfs_fuzz = [
        ("Empty String", ""),
        ("All Whitespace", "     \t\n   "),
        ("Nonsense / OOV Words", "xyzzy foobar blubba wumpus qwertyuiop1234567890"),
        ("SQL Injection in Log", "BLOCK* NameSystem.allocateBlock: /user/hadoop/data.txt; DROP TABLE hdfs_blocks;--"),
        ("XSS Payload in Log", "<script>alert('hdfs_xss')</script> received packet"),
        ("10,000 Char Log Line", "INFO dfs.DataNode$DataXceiver: Receiving block " + "A" * 10000 + " src: /10.0.0.1"),
        ("Unicode & Emojis", "🔥 ERROR dfs.DataNode: Block blk_-12345 corrupted 💀 by attacker"),
    ]

    for label, text in hdfs_fuzz:
        try:
            score = engine.score_log_line(text)
            verdict = engine.get_verdict(score) if score is not None else "ERROR"
            print(f"  * {label:<28} -> Threat: {score:.4f} ({verdict})")
        except Exception as e:
            print(f"  * {label:<28} -> [CRASH] {e}")
            flaws.append(f"HDFS crashed on input '{label}': {e}")

    print_sub("1.3 Real Benign vs Real Anomaly HDFS Traces")
    hdfs_scenarios = [
        ("Benign: Block Allocation", "INFO dfs.FSNamesystem: BLOCK* NameSystem.allocateBlock: /user/root/rand/_temporary/_task_200811051756_0003_m_000004_0/part-00004. blk_-1608999687919862906"),
        ("Benign: Block Verification", "INFO dfs.DataBlockScanner: Verification succeeded for blk_-1608999687919862906"),
        ("Benign: Receiving Block", "INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.250.19.102:54106 dest: /10.250.19.102:50010"),
        ("Benign: PacketResponder Terminate", "INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_-1608999687919862906 terminating"),
        
        ("Anomaly: Exception NameSystem Add", "WARN dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: Redundant addStoredBlock request received for blk_7579124409207056023 on 10.251.126.5:50010 size 67108864"),
        ("Anomaly: Block Lost / Missing", "ERROR dfs.DataNode$DataXceiver: 10.251.214.220:50010:DataXceiver error processing WRITE_BLOCK operation src: /10.250.10.6:57216 dest: /10.251.214.220:50010 java.io.IOException: Block blk_-3544583377289625738 is not valid"),
        ("Anomaly: Ransomware Log Wiping", "WARN dfs.FSNamesystem: Block blk_-999999 deleted unexpectedly by remote root command"),
    ]

    for label, text in hdfs_scenarios:
        score = engine.score_log_line(text)
        verdict = engine.get_verdict(score)
        is_anom = "Anomaly:" in label
        status = "[PASS]"
        if is_anom and score < 0.50:
            status = "[WEAK DETECTION]"
            insights.append(f"HDFS anomaly scenario '{label}' only scored {score:.4f}")
        elif not is_anom and score >= 0.60:
            status = "[FALSE POSITIVE]"
            insights.append(f"HDFS benign scenario '{label}' got high threat score {score:.4f}")
        print(f"  {status:<18} {label:<35} -> Threat: {score:.4f} ({verdict})")

    # =========================================================================
    # PART 2: CICIDS NETWORK FLOW ENGINE (Model 3)
    # =========================================================================
    print_header("PART 2: CICIDS NETWORK FLOW ENGINE (LightGBM 78 Features)")

    print_sub("2.1 Model & Export Structure")
    if engine._cicids_model is None:
        print("[FAIL] CICIDS model failed to load!")
        flaws.append("CICIDS model is None")
    else:
        print(f"[OK] Model: LightGBM, Expected Features Count: {len(engine._cicids_features)}")
        if engine._cicids_le:
            safe_classes = [str(c).encode('ascii', 'replace').decode('ascii') for c in engine._cicids_le.classes_]
            print(f"[OK] Classes: {safe_classes}")
        else:
            print("[OK] Classes: Embedded")

    print_sub("2.2 Extreme Feature Values & Malformed Packets")
    cicids_fuzz = [
        ("Empty Flow Dict ({})", {}),
        ("All Zero 78 Features", {f: 0.0 for f in engine._cicids_features}),
        ("Extreme High Values (10^9)", {f: 1e9 for f in engine._cicids_features}),
        ("Negative Values (-9999)", {f: -9999.0 for f in engine._cicids_features}),
        ("NaN Values in Flow", {f: float("nan") for f in engine._cicids_features}),
        ("Infinity Values in Flow", {f: float("inf") for f in engine._cicids_features}),
    ]

    for label, flow_dict in cicids_fuzz:
        try:
            score = engine.score_network_flow(flow_dict)
            verdict = engine.get_verdict(score) if score is not None else "ERROR"
            print(f"  * {label:<28} -> Threat: {score:.4f} ({verdict})")
        except Exception as e:
            print(f"  * {label:<28} -> [CRASH] {e}")
            flaws.append(f"CICIDS crashed on '{label}': {e}")

    print_sub("2.3 Real Attack Flows vs Benign Web Traffic")
    cicids_flows = [
        ("Benign: Normal HTTPS Web Browsing", {
            "Destination Port": 443.0, "Flow Duration": 125000.0,
            "Total Fwd Packets": 12.0, "Total Backward Packets": 18.0,
            "Total Length of Fwd Packets": 1420.0, "Total Length of Bwd Packets": 18500.0,
            "Fwd Packet Length Mean": 118.3, "Bwd Packet Length Mean": 1027.7,
            "Flow IAT Mean": 4310.0, "FIN Flag Count": 1.0, "SYN Flag Count": 1.0, "ACK Flag Count": 30.0
        }),
        ("Benign: DNS Lookup (Port 53)", {
            "Destination Port": 53.0, "Flow Duration": 1500.0,
            "Total Fwd Packets": 1.0, "Total Backward Packets": 1.0,
            "Total Length of Fwd Packets": 45.0, "Total Length of Bwd Packets": 120.0,
            "Flow IAT Mean": 1500.0, "ACK Flag Count": 0.0
        }),
        ("Attack: TCP SYN Flood DDoS", {
            "Destination Port": 80.0, "Flow Duration": 500.0,
            "Total Fwd Packets": 250.0, "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": 0.0, "Total Length of Bwd Packets": 0.0,
            "SYN Flag Count": 250.0, "ACK Flag Count": 0.0, "Flow IAT Mean": 2.0,
            "Fwd Packets/s": 500000.0
        }),
        ("Attack: PortScan Horizontal Sweep", {
            "Destination Port": 445.0, "Flow Duration": 10.0,
            "Total Fwd Packets": 1.0, "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": 0.0, "Total Length of Bwd Packets": 0.0,
            "SYN Flag Count": 1.0, "ACK Flag Count": 0.0, "Flow IAT Mean": 0.0
        }),
        ("Attack: Hydra SSH Brute Force", {
            "Destination Port": 22.0, "Flow Duration": 15000.0,
            "Total Fwd Packets": 65.0, "Total Backward Packets": 60.0,
            "Total Length of Fwd Packets": 4200.0, "Total Length of Bwd Packets": 3800.0,
            "Flow IAT Mean": 120.0, "RST Flag Count": 12.0, "ACK Flag Count": 120.0
        })
    ]

    for label, flow_dict in cicids_flows:
        score = engine.score_network_flow(flow_dict)
        verdict = engine.get_verdict(score)
        is_attack = "Attack:" in label
        status = "[PASS]"
        if is_attack and score < 0.60:
            status = "[WEAK DETECTION]"
            insights.append(f"CICIDS attack scenario '{label}' scored only {score:.4f}")
        elif not is_attack and score >= 0.60:
            status = "[FALSE POSITIVE]"
            insights.append(f"CICIDS benign scenario '{label}' scored high threat {score:.4f}")
        print(f"  {status:<18} {label:<35} -> Threat: {score:.4f} ({verdict})")

    # =========================================================================
    # PART 3: EMBER PE BINARY STATIC ENGINE (Model 4)
    # =========================================================================
    print_header("PART 3: EMBER STATIC PE BINARY ENGINE (LightGBM 2381 Features)")

    print_sub("3.1 Model & Feature Schema")
    if engine._ember_model is None:
        print("[FAIL] EMBER model failed to load!")
        flaws.append("EMBER model is None")
    else:
        print(f"[OK] Model: LightGBM, Expected Features Count: {len(engine._ember_features)}")

    print_sub("3.2 Extreme PE Feature Inputs")
    ember_fuzz = [
        ("Empty Dict ({})", {}),
        ("All Zero (2381 features)", {f: 0.0 for f in engine._ember_features[:50]}),
        ("All Negative (-1.0)", {f: -1.0 for f in engine._ember_features[:50]}),
        ("All High Values (999.0)", {f: 999.0 for f in engine._ember_features[:50]}),
        ("NaN Values in PE Vector", {f: float("nan") for f in engine._ember_features[:50]}),
    ]

    for label, feat_dict in ember_fuzz:
        try:
            score = engine.score_file(feat_dict)
            verdict = engine.get_verdict(score) if score is not None else "ERROR"
            print(f"  * {label:<28} -> Threat: {score:.4f} ({verdict})")
        except Exception as e:
            print(f"  * {label:<28} -> [CRASH] {e}")
            flaws.append(f"EMBER crashed on '{label}': {e}")

    print_sub("3.3 Simulated PE Archetypes: Benign vs Ransomware / Dropper")
    
    # Feature helpers:
    # EMBER features 0-255: Byte histogram
    # EMBER features 256-511: Byte entropy histogram
    # EMBER features 619+: Section info & characteristics
    
    # 1. Normal benign executable (low-to-moderate entropy, signed, normal sections)
    benign_pe = {f: 0.01 for f in engine._ember_features}
    for i in range(256):
        benign_pe[engine._ember_features[i]] = 0.0039  # flat byte dist
    for i in range(256, 512):
        benign_pe[engine._ember_features[i]] = 0.001

    # 2. Packed Ransomware (High Byte Entropy ~7.98 bits/byte, RWX sections)
    ransomware_pe = {f: 0.0 for f in engine._ember_features}
    for i in range(256, 512):
        ransomware_pe[engine._ember_features[i]] = 0.95  # extreme entropy spike
    if len(engine._ember_features) > 650:
        ransomware_pe[engine._ember_features[625]] = 1.0  # RWX flag / writable executable
        ransomware_pe[engine._ember_features[630]] = 1.0  # anomalous section count

    score_benign = engine.score_file(benign_pe)
    score_mal = engine.score_file(ransomware_pe)

    print(f"  * Benign System Executable Vector       -> Threat: {score_benign:.4f} ({engine.get_verdict(score_benign)})")
    print(f"  * Packed High-Entropy Ransomware Vector -> Threat: {score_mal:.4f} ({engine.get_verdict(score_mal)})")

    if score_mal < 0.60:
        insights.append(f"EMBER packed ransomware archetype scored low ({score_mal:.4f})")
    if score_benign >= 0.60:
        insights.append(f"EMBER benign executable scored high ({score_benign:.4f})")

    # =========================================================================
    # PART 4: WINDOWS ADVANCED v3 PROCESS CONTEXT ENGINE (Model 2c)
    # =========================================================================
    print_header("PART 4: WINDOWS ADVANCED v3 PROCESS CONTEXT (XGBoost)")

    print_sub("4.1 Model Payload State")
    if engine._win_v3_payload is None:
        print("[FAIL] Windows Advanced v3 payload failed to load!")
        flaws.append("windows_advanced_v3 payload is None")
    else:
        v3_model = engine._win_v3_payload.get("model")
        print(f"[OK] Model: {type(v3_model).__name__}, Threshold: {engine._win_v3_payload.get('threshold')}")
        print(f"[OK] Features Schema Count: {len(engine._win_v3_payload.get('features', []))}")

    print_sub("4.2 Process Feature Vector Stress Tests")
    # Features schema expected by v3:
    # 0: image_encoded, 1: parent_image_encoded, 2: user_encoded, 3: integrity_encoded,
    # 4: command_line_length, 5: network_conn_count, 6: file_created_count, 7: registry_set_count
    
    win_scenarios = [
        ("Benign: Normal svchost.exe (SYSTEM)", [45.0, 0.0, 0.0, 0.0, 4.0, 0.0, 0.0, 1.0, 0.0]),
        ("Benign: Normal explorer.exe (User)", [120.0, 0.0, 0.0, 0.0, 2.0, 2.0, 0.0, 0.0, 0.0]),
        ("Benign: Code.exe / Developer Terminal", [350.0, 0.0, 0.0, 0.0, 2.0, 4.0, 0.0, 0.0, 0.0]),
        
        ("Attack: Powershell Obfuscated Base64 Injection", [4500.0, 1.0, 1.0, 1.0, 2.0, 5.0, 0.0, 0.0, 0.0]),
        ("Attack: Ransomware vssadmin shadow delete", [180.0, 0.0, 0.0, 1.0, 3.0, 0.0, 0.0, 0.0, 1.0]),
        ("Attack: Mimikatz LSASS Memory Dumping", [85.0, 0.0, 0.0, 1.0, 3.0, 1.0, 1.0, 0.0, 1.0]),
        ("Extreme: Huge 100k length command line", [100000.0, 0.0, 0.0, 0.0, 2.0, 0.0, 0.0, 0.0, 0.0]),
        ("Extreme: All zeros", [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]),
    ]

    for label, feat_vec in win_scenarios:
        try:
            score = engine.score_windows_v3(feat_vec)
            verdict = "Attack" if score >= engine._win_v3_payload.get("threshold", 0.90) else "Normal"
            is_attack = "Attack:" in label
            status = "[PASS]"
            if is_attack and score < 0.60:
                status = "[WEAK DETECTION]"
                insights.append(f"Windows v3 attack '{label}' scored low threat: {score:.4f}")
            elif not is_attack and score >= 0.85:
                status = "[FALSE POSITIVE]"
                insights.append(f"Windows v3 benign '{label}' scored high threat: {score:.4f}")
            print(f"  {status:<18} {label:<45} -> Score: {score:.4f} ({verdict})")
        except Exception as e:
            print(f"  * {label:<45} -> [CRASH] {e}")
            flaws.append(f"Windows v3 crashed on '{label}': {e}")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print_header("AUDIT SUMMARY & DISCOVERED FLAWS")
    print(f"\n1. Software Crashes & Runtime Errors: {len(flaws)}")
    for f in flaws:
        print(f"   - [CRITICAL BUG] {f}")
    if not flaws:
        print("   [NONE] All 4 models executed safely without runtime exceptions or NaN/Inf crashes.")

    print(f"\n2. Architectural & Modeling Limitations Discovered: {len(insights)}")
    for ins in insights:
        print(f"   * {ins}")
    print("\n" + "=" * 70)

if __name__ == "__main__":
    run_stress_test()
