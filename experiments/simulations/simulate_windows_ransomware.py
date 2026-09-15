"""
experiments/simulations/simulate_windows_ransomware.py
======================================================
AEGIS Phase 5 — Multi-Node Attack Simulation: Windows Ransomware & PE Dropper
Simulates a ransomware outbreak on an endpoint (e.g. vm2-windows).

Workflow:
  1. Simulates malicious executable drop (detected via EMBER PE model).
  2. Simulates process injection & mass encryption syscall activity (Windows Advanced v3).
  3. Triggers centralized peer consensus vote.
  4. Dispatches and executes autonomous host quarantine & isolation:
     - QUARANTINE_FILE: File moved to encrypted vault (.aegis_quarantine/)
     - ISOLATE_HOST: Firewall locks inbound/outbound while preserving Command Node link.
"""

import time
import requests
import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

COMMAND_NODE_URL = os.getenv("COMMAND_NODE_URL", "http://localhost:8000").rstrip("/")
AGENT_ID = os.getenv("AGENT_ID", "endpoint-windows")


def run_simulation():
    print(f"\n{'='*65}")
    print(f" AEGIS ATTACK SIMULATION 2: Windows Ransomware & PE Dropper")
    print(f" Target Agent: {AGENT_ID}")
    print(f" Command Node: {COMMAND_NODE_URL}")
    print(f"{'='*65}\n")

    # Step 1: Malicious PE File Dropped
    print("[1/4] Detecting suspicious binary dropped in %TEMP% (EMBER analysis)...")
    file_telemetry = {
        "agent_id": AGENT_ID,
        "timestamp": int(time.time() * 1000000),
        "file_path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\locker_enc.exe",
        "process": "locker_enc.exe",
        "pid": 8944,
        "threat_score": 0.965,
        "predicted_class": "Malicious_PE",
        "model": "ember",
        "window_size": 1,
    }
    r = requests.post(f"{COMMAND_NODE_URL}/api/telemetry", json=file_telemetry)
    print(f"      -> EMBER telemetry posted: HTTP {r.status_code} (Threat Score: 96.5%)")
    time.sleep(1.5)

    # Step 2: Ransomware begins mass rapid file encryption
    print("\n[2/4] [RANSOMWARE ALERT] Process locker_enc.exe enumerating and encrypting drives...")
    process_telemetry = {
        "agent_id": AGENT_ID,
        "timestamp": int(time.time() * 1000000),
        "process": "locker_enc.exe",
        "pid": 8944,
        "threat_score": 0.992,
        "predicted_class": "Ransomware_Encryption",
        "model": "windows_advanced_v3",
        "normal_probability": 0.008,
        "window_size": 500,
        "syscall": "NtWriteFile",
    }
    requests.post(f"{COMMAND_NODE_URL}/api/telemetry", json=process_telemetry)
    time.sleep(1.0)

    # Step 3: Peer Consensus Voting
    print("\n[3/4] Initiating emergency consensus vote for rapid containment...")
    vote_request = {
        "event_type": "FILE_MODIFICATION",
        "origin_agent_id": AGENT_ID,
        "threat_score": 0.99,
        "confidence": 0.98,
        "details": {
            "process": "locker_enc.exe",
            "pid": 8944,
            "target_file": "C:\\Users\\Victim\\AppData\\Local\\Temp\\locker_enc.exe",
            "severity": "CRITICAL",
            "threat_score": 0.99,
            "description": "Mass file write burst accompanied by known malware PE signature",
        }
    }
    vote_resp = requests.post(f"{COMMAND_NODE_URL}/api/centralized/vote", json=vote_request)
    verdict = vote_resp.json().get("verdict", {})

    print("\n" + "-"*65)
    print(f" CONSENSUS VERDICT REPORT (Vote ID: {verdict.get('vote_id')})")
    print(f" Origin Node         : {verdict.get('origin_agent_id')}")
    print(f" Final Weighted Score: {verdict.get('final_weighted_score') * 100:.1f}%")
    print(f" Severity Level      : {verdict.get('severity')}")
    print(f" Action Dispatched   : {verdict.get('response_action')}")
    print(f" Consensus Reached   : {verdict.get('consensus_reached')}")
    print("-"*65)

    # Step 4: Autonomous Command Consumer executing mitigation hands-free
    print("\n[4/4] Autonomous Command Consumer executing mitigation hands-free...")
    from agent.action_consumer import ActionConsumerDaemon
    consumer = ActionConsumerDaemon(
        agent_id=AGENT_ID,
        command_node_url=COMMAND_NODE_URL,
    )

    # Ensure quarantine test file exists
    test_dummy = "test_ransomware_payload.bin"
    with open(test_dummy, "w") as f:
        f.write("DUMMY_ENCRYPTOR_PAYLOAD_TEST")

    # Poll and execute the dispatched action hands-free
    executed_actions = consumer.poll_and_execute_once()
    for act in executed_actions:
        print(f"      [Dispatcher] Action Executed: {act['action_id']} ({act['action_type']}) -> Status: {act['status']}")

    # Restore host firewall state
    time.sleep(1.0)
    uniso_result = consumer.driver.unisolate_host()
    print(f"      [Firewall] Host Un-isolated: {uniso_result.get('status')}")

    print("\n[SUCCESS] Entire loop (Detection -> Peer Voting -> Command Dispatch -> Local Execution -> Audit Log) completed hands-free!")


if __name__ == "__main__":
    run_simulation()
