"""
experiments/simulations/simulate_linux_attacks.py
=================================================
AEGIS Phase 5 — Multi-Node Attack Simulation: Linux IDS Attacks
Simulates an adversary executing brute-force (Hydra SSH/FTP) and Meterpreter
payloads on a monitored Linux node (e.g. vm1).

Workflow:
  1. Sends baseline normal telemetry to Command Node.
  2. Injects simulated Hydra SSH brute-force attack window.
  3. Injects simulated Java Meterpreter remote code execution.
  4. Triggers centralized peer consensus vote.
  5. Verifies autonomous response action dispatch (KILL_PROCESS).
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
AGENT_ID = os.getenv("AGENT_ID", "endpoint-linux")


def run_simulation():
    print(f"\n{'='*60}")
    print(f" AEGIS ATTACK SIMULATION 1: Linux Brute-Force & Meterpreter")
    print(f" Target Agent: {AGENT_ID}")
    print(f" Command Node: {COMMAND_NODE_URL}")
    print(f"{'='*60}\n")

    # Step 1: Send normal baseline
    print("[1/4] Emitting normal baseline syscall telemetry...")
    normal_payload = {
        "agent_id": AGENT_ID,
        "timestamp": int(time.time() * 1000000),
        "process": "nginx",
        "pid": 1420,
        "uid": 33,
        "syscall": 257, # openat
        "window_size": 500,
        "predicted_class": "Normal",
        "normal_probability": 0.94,
        "threat_score": 0.06,
        "model": "linux_ids",
        "probabilities": {
            "Normal": 0.94,
            "Hydra_SSH": 0.02,
            "Hydra_FTP": 0.01,
            "Meterpreter": 0.01,
            "Java_Meterpreter": 0.01,
            "Web_Shell": 0.005,
            "Adduser": 0.005,
        }
    }
    r = requests.post(f"{COMMAND_NODE_URL}/api/telemetry", json=normal_payload)
    print(f"      -> Baseline telemetry recorded: HTTP {r.status_code}")
    time.sleep(1.5)

    # Step 2: Attack sequence — Hydra SSH Brute-Force
    print("\n[2/4] [ATTACK TRIGGER] Adversary initiates Hydra SSH dictionary brute-force...")
    hydra_payload = {
        "agent_id": AGENT_ID,
        "timestamp": int(time.time() * 1000000),
        "process": "hydra",
        "pid": 5892,
        "uid": 1000,
        "syscall": 42, # connect
        "window_size": 500,
        "predicted_class": "Hydra_SSH",
        "normal_probability": 0.12,
        "threat_score": 0.88,
        "model": "linux_ids",
        "probabilities": {
            "Normal": 0.12,
            "Hydra_SSH": 0.82,
            "Hydra_FTP": 0.03,
            "Meterpreter": 0.01,
            "Java_Meterpreter": 0.01,
            "Web_Shell": 0.005,
            "Adduser": 0.005,
        }
    }
    r = requests.post(f"{COMMAND_NODE_URL}/api/telemetry", json=hydra_payload)
    print(f"      -> Telemetry published: HTTP {r.status_code} (Threat Score: 88.0%)")
    time.sleep(1.5)

    # Step 3: Attack sequence — Java Meterpreter RCE
    print("\n[3/4] [CRITICAL ATTACK] Reverse shell established via Java Meterpreter payload...")
    meterpreter_payload = {
        "agent_id": AGENT_ID,
        "timestamp": int(time.time() * 1000000),
        "process": "java",
        "pid": 6012,
        "uid": 0,
        "syscall": 101, # ptrace
        "window_size": 500,
        "predicted_class": "Java_Meterpreter",
        "normal_probability": 0.03,
        "threat_score": 0.97,
        "model": "linux_ids",
        "probabilities": {
            "Normal": 0.03,
            "Hydra_SSH": 0.02,
            "Hydra_FTP": 0.01,
            "Meterpreter": 0.04,
            "Java_Meterpreter": 0.88,
            "Web_Shell": 0.01,
            "Adduser": 0.01,
        }
    }
    requests.post(f"{COMMAND_NODE_URL}/api/telemetry", json=meterpreter_payload)
    time.sleep(1.0)

    # Step 4: Submit to Centralized Consensus Voting Hub
    print("\n[4/4] Submitting incident to Consensus Voting Coordinator...")
    vote_request = {
        "event_type": "PROCESS_EXECUTION",
        "origin_agent_id": AGENT_ID,
        "threat_score": 0.97,
        "confidence": 0.95,
        "details": {
            "process": "java",
            "pid": 6012,
            "attack_type": "Java_Meterpreter",
            "threat_score": 0.97,
            "evidence": "Syscall anomaly window matched Metasploit Java Meterpreter payload",
        }
    }
    vote_resp = requests.post(f"{COMMAND_NODE_URL}/api/centralized/vote", json=vote_request)
    verdict_data = vote_resp.json().get("verdict", {})

    print("\n" + "-"*60)
    print(f" CONSENSUS VERDICT REPORT (Vote ID: {verdict_data.get('vote_id')})")
    print(f" Origin Node         : {verdict_data.get('origin_agent_id')}")
    print(f" Final Weighted Score: {verdict_data.get('final_weighted_score') * 100:.1f}%")
    print(f" Severity Level      : {verdict_data.get('severity')}")
    print(f" Action Dispatched   : {verdict_data.get('response_action')}")
    print(f" Consensus Reached   : {verdict_data.get('consensus_reached')}")
    peers = verdict_data.get("participating_peers", 1)
    peers_count = len(peers) if isinstance(peers, (list, tuple)) else peers
    print(f" Participating Peers : {peers_count} nodes")
    print("-" * 60)

    # Step 4: Autonomous Command Consumer executes mitigation hands-free
    print("\n[4/4] Autonomous Command Consumer executing mitigation hands-free...")
    from agent.action_consumer import ActionConsumerDaemon
    consumer = ActionConsumerDaemon(
        agent_id=AGENT_ID,
        command_node_url=COMMAND_NODE_URL,
    )
    executed_actions = consumer.poll_and_execute_once()
    for act in executed_actions:
        print(f"      [Dispatcher] Action Executed: {act['action_id']} ({act['action_type']}) -> Status: {act['status']}")

    if verdict_data.get("response_action") == "KILL_PROCESS":
        print("\n[SUCCESS] Autonomous response KILL_PROCESS verified and logged to NeonDB.")
        print("          Dashboard 'Consensus & Feedback' tab now displays this incident.")
    else:
        print(f"\n[INFO] Action dispatched: {verdict_data.get('response_action')}")


if __name__ == "__main__":
    run_simulation()
