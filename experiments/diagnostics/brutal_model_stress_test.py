"""
experiments/diagnostics/brutal_model_stress_test.py
===================================================
Brutal, adversarial stress test and boundary analysis suite for:
  1. AEGIS Zero-Day IsolationForest Anomaly Engine
  2. AEGIS Linux IDS XGBoost Syscall Multi-Class Engine

Probes:
  - Extreme Out-Of-Vocabulary (OOV) inputs & injection strings
  - IPv6, CIDR, and malformed network inputs
  - Benign allowlist robustness and spoofing/evasion analysis
  - Syscall sequence padding, truncation & mimicry dilution attacks
  - Out-of-bounds, negative, and synthetic syscall numbers
  - False positive rates on standard Linux developer & sysadmin workflows
  - Full class probability distributions & decision boundaries
"""
import sys
import time
import traceback
from pathlib import Path
import numpy as np

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine

def print_header(title: str):
    print("\n" + "=" * 70)
    print(f" {title.center(68)} ")
    print("=" * 70)

def print_sub(title: str):
    print(f"\n--- [ {title} ] ---")

def run_stress_tests():
    print_header("AEGIS BRUTAL MODEL STRESS-TEST & VULNERABILITY AUDIT")
    print(f"Project Root: {_PROJECT_ROOT}")
    print(f"Testing Engines: Zero-Day IsolationForest & Linux IDS XGBoost\n")

    engine = ThreatFusionEngine()

    flaws_found = []
    insights = []

    # =========================================================================
    # PART 1: ZERO-DAY ISOLATION FOREST MODEL AUDIT
    # =========================================================================
    print_header("PART 1: ZERO-DAY ISOLATION FOREST (Model 6)")

    # 1.1 Model & Artifact Sanity
    print_sub("1.1 Artifact State & Encoders")
    if engine._zday_model is None:
        print("[FAIL] Zero-Day model failed to load!")
        flaws_found.append("Zero-Day model is None")
        return
    
    print(f"[OK] IsolationForest Model: n_estimators={engine._zday_model.n_estimators}, contamination={engine._zday_model.contamination}")
    print(f"[OK] Event Encoder classes count: {len(engine._zday_event_enc.classes_)}")
    print(f"[OK] Process Encoder classes count: {len(engine._zday_process_enc.classes_)}")
    print(f"[OK] User Encoder classes count: {len(engine._zday_user_enc.classes_)}")

    # 1.2 Extreme Fuzzing & Malformed Inputs
    print_sub("1.2 Extreme Malformed, Injection & Overflow Inputs")
    fuzz_payloads = [
        ("Empty Strings", "", "", "", ""),
        ("SQL Injection", "4688' OR '1'='1", "cmd.exe; DROP TABLE telemetry;--", "admin'--", "10.0.0.1"),
        ("XSS Payload", "<script>alert('xss')</script>", "<img src=x onerror=alert(1)>", "root", "192.168.1.1"),
        ("Buffer Overflow 5000 chars", "4688", "A" * 5000 + ".exe", "USER_" + "B" * 2000, "10.0.0.1"),
        ("Unicode & Emojis", "4688", "💀_ransomware_🔥.exe", "üser_ñame_漢字", "192.168.1.50"),
        ("Null Bytes & Control Chars", "4688\x00\r\n", "malware.exe\x00.pdf", "root\x00admin", "127.0.0.1"),
        ("Negative & Hex Event IDs", "-1", "0xdeadbeef.exe", "0x00", "0.0.0.0"),
        ("IPv6 Address", "4688", "powershell.exe", "SYSTEM", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        ("IPv6 Loopback", "4688", "svchost.exe", "SYSTEM", "::1"),
        ("Domain Hostname as IP", "4688", "beacon.exe", "Admin", "c2-server.darkweb.onion"),
        ("CIDR Notation", "4688", "scan.exe", "Admin", "10.0.0.0/24"),
    ]

    fuzz_crash = 0
    for label, eid, proc, user, ip in fuzz_payloads:
        try:
            score = engine.score_windows_event(eid, proc, user, ip)
            verdict = engine.get_verdict(score) if score is not None else "ERROR"
            print(f"  * {label:<28} -> Score: {score:.4f} ({verdict}) [OK]")
        except Exception as e:
            print(f"  * {label:<28} -> [CRASH] {e}")
            fuzz_crash += 1
            flaws_found.append(f"Zero-Day crashed on fuzz payload: {label} ({e})")
    
    if fuzz_crash == 0:
        print("[PASS] Zero-Day model handled all extreme fuzzing without unhandled exceptions.")

    # 1.3 Allowlist Analysis & Spoofing Evasion
    print_sub("1.3 Allowlist Evasion & Process Masquerading Analysis")
    allowlist_tests = [
        ("svchost.exe (Local)", "4688", "svchost.exe", "SYSTEM", "127.0.0.1"),
        ("svchost.exe (Remote IP)", "4688", "svchost.exe", "SYSTEM", "185.220.101.5"),
        ("powershell.exe (Local)", "4688", "powershell.exe", "Admin", "0.0.0.0"),
        ("powershell.exe (Remote IP)", "4688", "powershell.exe", "Admin", "45.33.32.156"),
        ("mimikatz.exe (Local)", "4688", "mimikatz.exe", "SYSTEM", "127.0.0.1"),
        ("mimikatz.exe (Remote IP)", "4688", "mimikatz.exe", "SYSTEM", "185.220.101.5"),
        ("svchost.exe disguised malware", "4688", "svchost.exe", "evil_user", "127.0.0.1"),
    ]

    for label, eid, proc, user, ip in allowlist_tests:
        score = engine.score_windows_event(eid, proc, user, ip)
        verdict = engine.get_verdict(score)
        print(f"  * {label:<32} -> Score: {score:.4f} ({verdict})")
        if "disguised malware" in label and score <= 0.15:
            insights.append("FLAW/INSIGHT: Zero-Day allowlist matches purely on process_name + loopback IP; malicious process named 'svchost.exe' on 127.0.0.1 gets suppressed to 0.15 regardless of evil username.")

    # 1.4 Anomaly Score Distribution & Calibration
    print_sub("1.4 Distribution & Boundary Analysis (1,000 Synthetic Events)")
    scores_normal = []
    scores_unknown = []
    
    np.random.seed(42)
    known_procs = list(engine._zday_process_enc.classes_[:10])
    known_users = list(engine._zday_user_enc.classes_[:5])
    known_events = list(engine._zday_event_enc.classes_[:5])

    for _ in range(500):
        e = np.random.choice(known_events)
        p = np.random.choice(known_procs)
        u = np.random.choice(known_users)
        ip = f"192.168.1.{np.random.randint(1, 254)}"
        s = engine.score_windows_event(e, p, u, ip)
        if s is not None:
            scores_normal.append(s)

    for _ in range(500):
        e = f"EVT_{np.random.randint(10000, 99999)}"
        p = f"malware_{np.random.randint(1000, 9999)}.exe"
        u = f"attacker_{np.random.randint(100, 999)}"
        ip = f"185.220.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}"
        s = engine.score_windows_event(e, p, u, ip)
        if s is not None:
            scores_unknown.append(s)

    print(f"Known In-Vocabulary Distribution (N={len(scores_normal)}):")
    print(f"  Mean: {np.mean(scores_normal):.4f} | Median: {np.median(scores_normal):.4f} | Min: {np.min(scores_normal):.4f} | Max: {np.max(scores_normal):.4f} | Std: {np.std(scores_normal):.4f}")
    
    print(f"Out-Of-Vocabulary Anomaly Distribution (N={len(scores_unknown)}):")
    print(f"  Mean: {np.mean(scores_unknown):.4f} | Median: {np.median(scores_unknown):.4f} | Min: {np.min(scores_unknown):.4f} | Max: {np.max(scores_unknown):.4f} | Std: {np.std(scores_unknown):.4f}")

    if np.mean(scores_unknown) <= np.mean(scores_normal):
        flaws_found.append("Zero-Day model does not assign higher average anomaly scores to Out-Of-Vocabulary (OOV) inputs compared to in-vocabulary inputs!")
    else:
        print(f"[OK] OOV anomaly separation delta: +{np.mean(scores_unknown) - np.mean(scores_normal):.4f}")

    # =========================================================================
    # PART 2: LINUX IDS XGBOOST MULTI-CLASS MODEL AUDIT
    # =========================================================================
    print_header("PART 2: LINUX IDS XGBOOST (Model 1)")

    # 2.1 Model & Label Encoder State
    print_sub("2.1 Model & Class Breakdown")
    if engine._linux_model is None or engine._linux_le is None:
        print("[FAIL] Linux model or label encoder failed to load!")
        flaws_found.append("Linux model/LE is None")
        return

    classes = list(engine._linux_le.classes_)
    print(f"[OK] XGBClassifier loaded: n_classes={len(classes)}")
    for i, c in enumerate(classes):
        print(f"     Class {i}: '{c}'")

    # 2.2 Sequence Length Extremes & Padding Boundaries
    print_sub("2.2 Sequence Length & Padding Boundary Tests")
    seq_tests = [
        ("Empty Sequence (len=0)", []),
        ("Single Syscall (len=1: read=0)", [0]),
        ("Single Syscall (len=1: execve=59)", [59]),
        ("Short Syscall Seq (len=10)", [59, 12, 9, 10, 11, 2, 0, 1, 3, 231]),
        ("Sub-threshold (len=499)", [0, 1, 2, 3] * 124 + [59, 105, 101]),
        ("Exact Threshold (len=500)", [0, 1, 2, 3] * 125),
        ("Super-threshold (len=501)", [0, 1, 2, 3] * 125 + [59]),
        ("Huge Buffer (len=5000)", [0, 1, 2, 3, 4, 5, 59, 101, 105, 231] * 500),
        ("All Zeros (len=500)", [0] * 500),
        ("All Execve=59 (len=500)", [59] * 500),
        ("All Ptrace=101 (len=500)", [101] * 500),
        ("All Negative -1 (len=500)", [-1] * 500),
        ("All High Out-Of-Bounds 9999 (len=500)", [9999] * 500),
    ]

    for label, seq in seq_tests:
        try:
            score = engine.score_process_event(syscall_sequence=seq)
            x_pad = engine._pad_truncate(seq, 500).reshape(1, -1)
            raw_probs = engine._linux_model.predict_proba(x_pad)[0]
            top_class = classes[int(np.argmax(raw_probs))]
            top_prob = float(np.max(raw_probs))
            verdict = engine.get_verdict(score)
            print(f"  * {label:<38} -> Score: {score:.4f} ({verdict:<8}) | TopClass: {top_class:<16} ({top_prob:.3f})")
        except Exception as e:
            print(f"  * {label:<38} -> [CRASH] {e}")
            flaws_found.append(f"Linux model crashed on sequence test: {label} ({e})")

    # 2.3 Real-World Workflows vs Attack Signatures
    print_sub("2.3 Real-World Workflows vs Attack Signatures Evaluation")
    
    # Common Linux benign workflows:
    workflows = {
        "Benign: Bash Shell Interaction": [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 16, 21, 22, 24, 32, 33, 72, 78, 80, 202] * 20,
        "Benign: Python Script Run": [59, 12, 9, 21, 2, 5, 3, 9, 10, 11, 2, 0, 3, 12, 2, 0, 3, 231] * 25,
        "Benign: Nginx Web Server Loop": [202, 45, 46, 44, 47, 43, 48, 0, 1, 3, 41, 42, 49, 50] * 35,
        "Benign: Apt-Get Install": [59, 12, 9, 2, 5, 0, 1, 3, 83, 84, 87, 88, 90, 92, 4, 6, 78, 231] * 25,
        
        # Real Attack Sequences:
        "Attack: Hydra SSH Brute Force": [41, 42, 44, 45, 48, 41, 42, 44, 45, 48, 41, 42, 44, 45, 48] * 30,
        "Attack: Java Meterpreter": [59, 10, 9, 11, 157, 158, 41, 42, 44, 45, 101, 105, 62] * 35,
        "Attack: Root Privilege Escalation": [105, 106, 126, 157, 59, 101, 165, 166, 82, 87, 90, 92] * 40,
        "Attack: Web Shell Execution": [59, 33, 33, 33, 41, 42, 0, 1, 59, 105, 62] * 40,
    }

    benign_scores = []
    attack_scores = []

    for name, seq in workflows.items():
        score = engine.score_process_event(syscall_sequence=seq)
        x_pad = engine._pad_truncate(seq, 500).reshape(1, -1)
        raw_probs = engine._linux_model.predict_proba(x_pad)[0]
        top_class = classes[int(np.argmax(raw_probs))]
        top_prob = float(np.max(raw_probs))
        verdict = engine.get_verdict(score)
        
        is_attack = "Attack:" in name
        if is_attack:
            attack_scores.append(score)
        else:
            benign_scores.append(score)

        status_tag = "[PASS]"
        if is_attack and score < 0.60:
            status_tag = "[WEAK DETECTION]"
            insights.append(f"Attack scenario '{name}' only scored {score:.4f} (under 0.60 HIGH threshold)")
        elif not is_attack and score >= 0.80:
            status_tag = "[FALSE POSITIVE]"
            insights.append(f"Benign workflow '{name}' scored {score:.4f} (FALSE POSITIVE >= 0.80)")

        print(f"  {status_tag:<18} {name:<35} -> Threat: {score:.4f} ({verdict:<8}) | Class: {top_class} ({top_prob:.3f})")

    # 2.4 Adversarial Evasion: Mimicry / Dilution Attack
    print_sub("2.4 Adversarial Mimicry & Dilution Testing")
    # Take an obvious attack sequence (Meterpreter) and dilute it with 450 benign read/write/stat calls
    pure_attack = [59, 101, 105, 41, 42, 44, 45] * 70  # ~490 calls
    score_pure = engine.score_process_event(syscall_sequence=pure_attack)

    # Place attack at beginning, middle, and end of 500-syscall window
    dilute_front = ([59, 101, 105, 41, 42] * 10) + ([0, 1, 3, 4] * 112) # 50 attack + 448 benign
    dilute_middle = ([0, 1, 3, 4] * 56) + ([59, 101, 105, 41, 42] * 10) + ([0, 1, 3, 4] * 56) # 224 benign + 50 attack + 224 benign
    dilute_end = ([0, 1, 3, 4] * 112) + ([59, 101, 105, 41, 42] * 10) # 448 benign + 50 attack
    dilute_truncated = ([0, 1, 3, 4] * 125) + ([59, 101, 105, 41, 42] * 10) # 500 benign + 50 attack (gets truncated!)

    score_front = engine.score_process_event(syscall_sequence=dilute_front)
    score_mid = engine.score_process_event(syscall_sequence=dilute_middle)
    score_end = engine.score_process_event(syscall_sequence=dilute_end)
    score_trunc = engine.score_process_event(syscall_sequence=dilute_truncated)

    print(f"  * Pure Attack Signature Score           : {score_pure:.4f} ({engine.get_verdict(score_pure)})")
    print(f"  * Attack at Window START (Diluted 90%)   : {score_front:.4f} ({engine.get_verdict(score_front)})")
    print(f"  * Attack at Window MIDDLE (Diluted 90%)  : {score_mid:.4f} ({engine.get_verdict(score_mid)})")
    print(f"  * Attack at Window END (Diluted 90%)     : {score_end:.4f} ({engine.get_verdict(score_end)})")
    print(f"  * Attack beyond 500 (Truncated from tail): {score_trunc:.4f} ({engine.get_verdict(score_trunc)})")

    if score_trunc < 0.30:
        insights.append("FLAW/INSIGHT: Fixed 500-length truncation means any attack syscall occurring after 500 events in a single buffer is completely truncated and scored as 0 (evasion via syscall stuffing).")

    # =========================================================================
    # SUMMARY REPORT
    # =========================================================================
    print_header("SUMMARY OF AUDIT FINDINGS & VULNERABILITIES")
    
    print("\n1. Critical Software Bugs/Crashes:")
    if not flaws_found:
        print("   [NONE] Zero software crashes, unhandled exceptions, or serialization failures found.")
    else:
        for f in flaws_found:
            print(f"   - [CRITICAL] {f}")

    print("\n2. Model Security Insights & Architectural Limitations:")
    for ins in insights:
        print(f"   * {ins}")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    run_stress_tests()
