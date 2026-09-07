"""
tools/model_behavior_audit.py
==============================
AEGIS Model Behavioral Determinism & Zero-Score Audit

READ-ONLY diagnostic tool. Does NOT modify any model artifact, threshold,
weight, or production inference code.
"""
from __future__ import annotations

import json
import math
import statistics
import sys
import traceback
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

_ROOT = Path(r"d:\AEGIS")
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "agent"))

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from agent.fusion_engine import ThreatFusionEngine
    from agent.windows_process_context import (
        ProcessContextState,
        WindowsAdvancedV2FeatureExtractor,
        WindowsAdvancedV3FeatureExtractor,
        WindowsAdvancedV3CandidateFeatureExtractor,
    )

import logging
logging.disable(logging.CRITICAL)

REPS = 100

def run_n(fn, *args, **kwargs):
    scores = []
    excs = []
    for _ in range(REPS):
        try:
            r = fn(*args, **kwargs)
            scores.append(r)
        except Exception as e:
            scores.append(None)
            excs.append(str(e))
    numeric = [s for s in scores if s is not None and not math.isnan(float(s))]
    zeros = [s for s in scores if s == 0.0]
    nones = [s for s in scores if s is None]
    unique = set(round(s, 12) for s in numeric) if numeric else set()
    return dict(n=REPS, min=min(numeric) if numeric else None,
                max=max(numeric) if numeric else None,
                mean=statistics.mean(numeric) if numeric else None,
                stdev=statistics.stdev(numeric) if len(numeric) > 1 else 0.0,
                n_unique=len(unique), unique=sorted(unique),
                n_zero=len(zeros), n_none=len(nones),
                n_exc=len(excs), excs=list(set(excs))[:2],
                deterministic=len(unique)<=1 and len(nones)==0)

engine = ThreatFusionEngine()
print("ENGINE INITIALISED")

def fmt(label, r):
    det = "DET" if r["deterministic"] else "NON-DET"
    if r["min"] is not None:
        return f"[{det}] {label}: min={r['min']:.8f} max={r['max']:.8f} mean={r['mean']:.8f} stdev={r['stdev']:.2e} unique={r['n_unique']} zeros={r['n_zero']} nones={r['n_none']}"
    else:
        return f"[OFFLINE/NONE] {label}: nones={r['n_none']} excs={r['n_exc']}"

def make_state(image, parent="explorer.exe", cmd="cmd.exe /c whoami", integrity="Medium", nets=None):
    s = ProcessContextState(guid="{t}", pid=1, image=image, parent_image=parent, command_line=cmd, integrity_level=integrity)
    if nets:
        for n in nets: s.network_destinations.add(n)
    return s

print("\n=== PHASE 2/5: LINUX IDS ===")
linux_cases = {
    "empty": [],
    "short_benign": [3, 0, 5, 2, 8],
    "normal_typical": [0, 59, 2, 3, 11, 231] * 80 + [0] * 20,
    "all_zeros_500": [0] * 500,
    "all_execve": [59] * 500,
    "overlong_600": list(range(1, 601)),
    "high_oov": [9999, 8888, 7777] * 166 + [1],
}
for name, seq in linux_cases.items():
    r = run_n(engine.score_process_event, syscall_sequence=seq)
    print(fmt(f"linux::{name}", r))

print("\n=== PHASE 2/6: HDFS ===")
hdfs_cases = {
    "normal": "081109 204011 143 INFO dfs.DataNode$PacketResponder: PacketResponder 0 for block blk_38865049274842714 terminating",
    "anomaly": "081109 204127 13 ERROR dfs.DataNode$DataXceiver: writeBlock blk_-6670958622368987959 received exception java.io.IOException: Broken pipe",
    "empty": "",
    "short": "ERROR",
    "garbage": "!@#$%^&*()",
    "repeated_blk": "blk " * 100,
}
for name, text in hdfs_cases.items():
    r = run_n(engine.score_log_line, text)
    print(fmt(f"hdfs::{name}", r))

print("\n=== PHASE 2/4: ZERO-DAY ===")
zday_cases = {
    "benign_svchost_loopback": ("4624", "svchost.exe", "SYSTEM", "127.0.0.1"),
    "benign_explorer_00": ("4624", "explorer.exe", "Admin", "0.0.0.0"),
    "suspicious_cmd_ext": ("4688", "cmd.exe", "Admin", "192.168.1.100"),
    "unknown_event": ("9999", "cmd.exe", "Admin", "10.0.0.1"),
    "unknown_process": ("4688", "hacker_tool.exe", "root", "172.16.0.5"),
    "unknown_user": ("4688", "powershell.exe", "UNKNOWN_USR", "10.0.0.1"),
    "benign_proc_ext_ip": ("4688", "svchost.exe", "SYSTEM", "8.8.8.8"),
    "unknown_proc_loopback": ("4688", "hacker_tool.exe", "root", "127.0.0.1"),
    "malformed_ip": ("4688", "cmd.exe", "Admin", "not-an-ip"),
    "all_empty": ("", "", "", ""),
    "all_oov": ("FAKE_ID", "FAKE.EXE", "FAKE_USER", "999.999.999.999"),
}
for name, (ev, pr, us, ip) in zday_cases.items():
    r = run_n(engine.score_windows_event, ev, pr, us, ip)
    print(fmt(f"zero_day::{name}", r))

print("\n=== PHASE 2/7: WINDOWS V2 ===")
v2_cases = {
    "benign_cmd": make_state("C:\\Windows\\System32\\cmd.exe"),
    "benign_svchost": make_state("C:\\Windows\\System32\\svchost.exe"),
    "ps_encoded": make_state("powershell.exe", cmd="powershell -enc AAAA="),
    "excel_spawns_ps": make_state("powershell.exe", parent="excel.exe"),
    "high_integrity_ps": make_state("powershell.exe", integrity="High"),
    "all_zero": make_state("C:\\Windows\\System32\\svchost.exe", parent="", cmd="", integrity=""),
    "with_network": make_state("powershell.exe", nets=["8.8.8.8:443"]),
}
for name, state in v2_cases.items():
    feats = WindowsAdvancedV2FeatureExtractor.extract_features(state)
    r = run_n(engine.score_windows_v2, feats)
    print(fmt(f"v2::{name} feats={[round(f,3) for f in feats]}", r))

print("\n=== PHASE 2/7: WINDOWS V3 BASELINE ===")
v3_cases = {
    "benign_cmd": make_state("C:\\Windows\\System32\\cmd.exe"),
    "userinit_winlogon": make_state("C:\\Windows\\System32\\userinit.exe", parent="C:\\Windows\\System32\\winlogon.exe"),
    "sdclt_from_ps": make_state("C:\\Windows\\System32\\sdclt.exe", parent="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    "masq_svchost": make_state("C:\\Users\\Admin\\AppData\\Local\\Temp\\svchost.exe"),
    "wmiprvse_cmd": make_state("cmd.exe", parent="C:\\Windows\\System32\\wbem\\wmiprvse.exe"),
    "high_integrity_enc_ps": make_state("powershell.exe", integrity="High", cmd="powershell.exe -enc AAAA=="),
}
for name, state in v3_cases.items():
    feats = WindowsAdvancedV3FeatureExtractor.extract_features(state)
    r = run_n(engine.score_windows_v3, feats)
    print(fmt(f"v3::{name} feats={[round(f,3) for f in feats]}", r))

print("\n=== PHASE 2/7: WINDOWS V3 CANDIDATE ===")
cand_cases = {
    "net1_benign_view": make_state("C:\\Windows\\System32\\net1.exe", parent="C:\\Windows\\System32\\net.exe", cmd="net1 view"),
    "net1_malicious_add": make_state("C:\\Windows\\System32\\net1.exe", parent="C:\\Windows\\System32\\net.exe", cmd="net1 user /add admin pass"),
    "net1_domain": make_state("C:\\Windows\\System32\\net1.exe", parent="C:\\Windows\\System32\\net.exe", cmd="net1 group /domain"),
    "benign_cmd": make_state("C:\\Windows\\System32\\cmd.exe"),
    "ps_bypass_enc": make_state("powershell.exe", cmd="powershell -bypass -nop -enc AAAA=="),
    "empty_cmd": make_state("cmd.exe", cmd=""),
    "very_long_cmd": make_state("cmd.exe", cmd="A" * 50000),
}
for name, state in cand_cases.items():
    feats = WindowsAdvancedV3CandidateFeatureExtractor.extract_features(state)
    r = run_n(engine.score_windows_v3_candidate, feats)
    print(fmt(f"cand::{name} feats={[round(f,3) for f in feats]}", r))

print("\n=== PHASE 4: ZERO-DAY DEEP TRACE ===")
def zday_trace(ev, proc, user, ip, label):
    ev_enc = engine._safe_le_transform(engine._zday_event_enc, str(ev), 0)
    pr_enc = engine._safe_le_transform(engine._zday_process_enc, str(proc), 0)
    us_enc = engine._safe_le_transform(engine._zday_user_enc, str(user), 0)
    try: ip_oct = int(str(ip).split(".")[-1])
    except: ip_oct = 0
    x = np.array([[ev_enc, pr_enc, us_enc, ip_oct]], dtype=np.float64)
    dec = float(engine._zday_model.decision_function(x)[0])
    sig = engine._sigmoid(dec)
    raw = 1.0 - sig
    benign_ps = {
        "svchost.exe","explorer.exe","conhost.exe","taskhostw.exe","dwm.exe",
        "csrss.exe","services.exe","lsass.exe","smss.exe","searchhost.exe",
        "startmenuexperiencehost.exe","textinputhost.exe","ctfmon.exe",
        "chrome.exe","cursor.exe","code.exe","py.exe","python.exe","cmd.exe",
        "powershell.exe","antigravity-ide.exe"
    }
    allowlisted = str(proc).lower() in benign_ps and ip in ("0.0.0.0", "127.0.0.1")
    final = float(np.clip(min(raw, 0.15) if allowlisted else raw, 0, 1))
    print(f"  {label}")
    print(f"    raw input: ({ev}, {proc}, {user}, {ip})")
    print(f"    encoded: [{ev_enc}, {pr_enc}, {us_enc}, {ip_oct}] | decision: {dec:.6f} | sigmoid: {sig:.6f} | 1-sigmoid: {raw:.6f} | allowlisted: {allowlisted} | final: {final:.6f}")

for ev, pr, us, ip, lbl in [
    ("4624", "svchost.exe", "SYSTEM", "127.0.0.1", "Benign svchost loopback (allowlisted)"),
    ("4624", "explorer.exe", "Admin", "0.0.0.0", "Benign explorer 0.0.0.0 (allowlisted)"),
    ("4688", "cmd.exe", "Admin", "192.168.1.100", "Suspicious cmd external (NOT allowlisted)"),
    ("9999", "cmd.exe", "Admin", "10.0.0.1", "Unknown ev_id OOV->0"),
    ("4688", "hacker_tool.exe", "root", "172.16.0.5", "Unknown process OOV->0"),
    ("4688", "svchost.exe", "SYSTEM", "8.8.8.8", "Benign proc + EXTERNAL IP (NOT allowlisted)"),
    ("4688", "cmd.exe", "Admin", "not-an-ip", "Malformed IP octet->0"),
    ("", "", "", "", "All empty OOV->0"),
]:
    zday_trace(ev, pr, us, ip, lbl)

print("\n=== PHASE 5: LINUX IDS STAGE TRACE ===")
def linux_trace(seq, label):
    padded = engine._pad_truncate(seq, 500)
    x = padded.reshape(1, -1)
    with warnings.catch_warnings(): warnings.simplefilter("ignore")
    proba = engine._linux_model.predict_proba(x)[0]
    normal_idx = next((i for i, c in enumerate(engine._linux_le.classes_) if str(c).lower() == "normal"), None)
    if normal_idx is not None:
        score = 1.0 - float(proba[normal_idx])
        p_normal = float(proba[normal_idx])
    else:
        score = 1.0 - float(np.max(proba))
        p_normal = float(np.max(proba))
    print(f"  {label}: padded_shape={padded.shape} P(Normal)[{normal_idx}]={p_normal:.8f} score={score:.8f}")

for seq, lbl in [
    ([], "empty"),
    ([3, 0, 5, 2, 8], "short benign"),
    ([0] * 500, "all zeros"),
    ([59] * 500, "all execve"),
    ([0, 59, 2, 3, 11, 231] * 80 + [0] * 20, "normal typical"),
    ([9999] * 500, "high OOV"),
]:
    linux_trace(seq, lbl)

print("\n=== PHASE 6: HDFS STAGE TRACE ===")
def hdfs_trace(text, label):
    sparse = engine._hdfs_vectorizer.transform([text])
    dense = sparse.toarray()[0]
    with warnings.catch_warnings(): warnings.simplefilter("ignore")
    proba = engine._hdfs_model.predict_proba(sparse)[0]
    anomaly_idx = next((i for i, c in enumerate(engine._hdfs_le.classes_) if str(c).lower() == "anomaly"), None)
    score = float(proba[anomaly_idx]) if anomaly_idx is not None else float(np.max(proba))
    print(f"  {label}: nnz={np.count_nonzero(dense)} proba={[round(p, 6) for p in proba]} class_order={list(engine._hdfs_le.classes_)} anomaly_idx={anomaly_idx} score={score:.8f}")

for text, lbl in [
    ("081109 204011 143 INFO dfs.DataNode$PacketResponder: PacketResponder 0 for block blk_38865049274842714 terminating", "normal"),
    ("081109 204127 13 ERROR dfs.DataNode$DataXceiver: writeBlock blk_-6670958622368987959 received exception java.io.IOException: Broken pipe", "anomaly"),
    ("", "empty"),
    ("ERROR", "single word"),
]:
    hdfs_trace(text, lbl)

print("\n=== PHASE 8: FUSION MATH AUDIT ===")
def fuse_check(label, d):
    res = engine.fuse(d)
    print(f"  {label}: input={d} -> fuse={res:.8f}")

fuse_check("3 active equal", {"linux": 0.8, "hdfs": 0.2, "zero_day": 0.4})
fuse_check("1 active only", {"linux": 0.75})
fuse_check("None skipped", {"linux": 0.8, "hdfs": None})
fuse_check("zero included", {"linux": 0.0, "hdfs": 0.5})
fuse_check("shadow key (v3)", {"windows_advanced_v3": 0.99})
fuse_check("all None -> 0", {"linux": None, "hdfs": None, "zero_day": None})
fuse_check("shadow+active", {"linux": 0.5, "windows_advanced_v2": 0.9})
fuse_check("quarantined windows", {"linux": 0.5, "windows": 0.9})

print("\n=== PHASE 9: TELEMETRY & ROUNDING AUDIT ===")
print("save_event() JSONL rounding vs API payload conversion:")
for v in [0.004, 0.0004, 0.00004, 0.0, 1e-5, 5e-4, 0.00005]:
    rounded = round(v, 4)
    api_val = float(v)
    issue = " <ROUNDING ZERO IN JSONL>" if v > 0 and rounded == 0.0 else ""
    print(f"  score={v:.2e} -> JSONL={rounded} API_threat_score={api_val:.2e}{issue}")
print("None handling:")
print(f"  save_event(model, None, ...): JSONL score=None | API payload threat_score={float(0.0)} <NONE->0.0 CONVERSION>")

print("\n=== PHASE 7: V3 CANDIDATE SATURATION ANALYSIS ===")
benign_scores, mal_scores = [], []
for i in range(10):
    s_b = make_state("C:\\Windows\\System32\\cmd.exe", cmd=f"cmd.exe /c dir > output_{i}.txt")
    f_b = WindowsAdvancedV3CandidateFeatureExtractor.extract_features(s_b)
    sb = engine.score_windows_v3_candidate(f_b)
    benign_scores.append(sb)
    s_m = make_state("C:\\Windows\\System32\\net1.exe", parent="C:\\Windows\\System32\\net.exe", cmd="net1 user /add admin pass")
    f_m = WindowsAdvancedV3CandidateFeatureExtractor.extract_features(s_m)
    sm = engine.score_windows_v3_candidate(f_m)
    mal_scores.append(sm)

print(f"  Benign 10 samples: min={min(benign_scores):.6f} max={max(benign_scores):.6f} mean={statistics.mean(benign_scores):.6f}")
print(f"  Malicious 10 samples: min={min(mal_scores):.6f} max={max(mal_scores):.6f} mean={statistics.mean(mal_scores):.6f}")

print("\n=== AUDIT RUN COMPLETED ===")
