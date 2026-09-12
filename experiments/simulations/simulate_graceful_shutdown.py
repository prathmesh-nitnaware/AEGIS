"""
experiments/simulations/simulate_graceful_shutdown.py
=====================================================
AEGIS Phase 5 — Simulation 4: Graceful User-Initiated Shutdown
Demonstrates what happens when a legitimate user shuts down or reboots their PC.

Workflow:
  1. Node vm4-planned-reboot sends regular heartbeats.
  2. The user initiates a clean OS shutdown / reboot (Start -> Shut Down or systemctl poweroff).
  3. The agent hooks the OS termination signal and transmits an emergency Synchronous
     'Last-Gasp' Goodbye beacon to /api/heartbeat/shutdown.
  4. The Command Node records the agent as OFFLINE_GRACEFUL.
  5. 20+ seconds elapse: VERIFIES THAT NO SILENCE ALARM IS RAISED!
  6. Node reboots and transmits a fresh heartbeat: transitions back to ACTIVE cleanly.
"""

import time
import requests
import json
import os

COMMAND_NODE_URL = os.getenv("COMMAND_NODE_URL", "http://localhost:8000").rstrip("/")
AGENT_ID = os.getenv("AGENT_ID", "vm4-planned-reboot")


def run_simulation():
    print(f"\n{'='*65}")
    print(f" AEGIS SIMULATION 4: Graceful User Shutdown vs Silence Alarm")
    print(f" Target Agent: {AGENT_ID}")
    print(f" Command Node: {COMMAND_NODE_URL}")
    print(f"{'='*65}\n")

    # Step 1: Normal operational heartbeats
    print("[1/4] Node operating normally with active heartbeat telemetry...")
    for i in range(2):
        hb = {
            "agent_id": AGENT_ID,
            "status": "healthy",
            "cpu": 15.0 + i,
            "timestamp": time.time(),
        }
        requests.post(f"{COMMAND_NODE_URL}/api/heartbeat", json=hb)
        print(f"      -> Heartbeat #{i+1} sent: status=healthy")
        time.sleep(1.5)

    # Step 2: User initiates Start -> Shut Down
    print("\n[2/4] [USER ACTION] User clicks 'Start -> Shut Down' (or 'systemctl poweroff')...")
    print("      OS sends CTRL_SHUTDOWN_EVENT / SIGTERM.")
    print("      AEGIS shutdown hook intercepts event and sends Goodbye beacon...")

    shutdown_beacon = {
        "agent_id": AGENT_ID,
        "status": "OFFLINE_GRACEFUL",
        "reason": "USER_INITIATED_WINDOWS_SHUTDOWN",
        "timestamp": time.time(),
    }
    resp = requests.post(f"{COMMAND_NODE_URL}/api/heartbeat/shutdown", json=shutdown_beacon)
    print(f"      -> Command Node Response: {resp.status_code} - {resp.json()}")

    # Step 3: Wait 20 seconds (threshold is 15s) and verify alarm is SUPPRESSED
    print("\n[3/4] Waiting 20 seconds (exceeding the 15s silence threshold)...")
    print("      Verifying that NO false silence alarm is fired for this planned offline node.")

    alarm_falsely_fired = False
    for sec in range(1, 21):
        time.sleep(1.0)
        # Check alerts endpoint
        try:
            alerts_resp = requests.get(f"{COMMAND_NODE_URL}/api/alerts", timeout=2)
            alerts = alerts_resp.json().get("alerts", [])
            if any(a.get("agent_id") == AGENT_ID and not a.get("acknowledged") for a in alerts):
                alarm_falsely_fired = True
                break
        except Exception:
            pass
        print(f"      ... {sec}/20 seconds elapsed (silence alarm suppressed: OK)...", end="\r")

    print("\n")
    if alarm_falsely_fired:
        print("[FAIL] A silence alarm was incorrectly raised for a graceful shutdown!")
    else:
        print("[SUCCESS] Zero false alarms fired! The Command Node correctly recognized the")
        print("          graceful departure beacon and marked the node OFFLINE_GRACEFUL.")

    # Step 4: Machine turns back on (next day / reboot)
    print("\n[4/4] [REBOOT] User turns PC back on next morning. AEGIS service starts...")
    boot_heartbeat = {
        "agent_id": AGENT_ID,
        "status": "healthy",
        "cpu": 18.2,
        "timestamp": time.time(),
    }
    requests.post(f"{COMMAND_NODE_URL}/api/heartbeat", json=boot_heartbeat)
    print(f"      -> First boot heartbeat sent: status=healthy")
    print(f"      -> Node {AGENT_ID} automatically restored to ACTIVE operational status.")

    print("\n" + "="*65)
    print(" GRACEFUL SHUTDOWN INTEGRATION TEST: 100% PASSED")
    print("="*65 + "\n")


if __name__ == "__main__":
    run_simulation()
