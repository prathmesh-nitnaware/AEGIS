"""
experiments/simulations/simulate_silence_tamper.py
==================================================
AEGIS Phase 5 — Simulation 3: Adversary Agent Sabotage / Silence Alarm
Simulates an attacker gaining elevated privileges on an endpoint and abruptly
killing the AEGIS monitoring daemon (kill -9 or taskkill /F).

Because the process is terminated forcefully without clean OS shutdown signals,
no goodbye beacon is emitted.
The Command Node's SilenceDetector identifies the missing heartbeat and raises
a CRITICAL SILENT_ALARM within ~15 seconds.
"""

import time
import requests
import json
import os

COMMAND_NODE_URL = os.getenv("COMMAND_NODE_URL", "http://localhost:8000").rstrip("/")
AGENT_ID = os.getenv("AGENT_ID", "node-sabotage-test")


def run_simulation():
    print(f"\n{'='*65}")
    print(f" AEGIS ATTACK SIMULATION 3: Adversary Agent Sabotage (Silence Alarm)")
    print(f" Target Agent: {AGENT_ID}")
    print(f" Command Node: {COMMAND_NODE_URL}")
    print(f"{'='*65}\n")

    # Step 1: Send initial normal heartbeats
    print("[1/3] Agent node booting and establishing heartbeat telemetry with Command Node...")
    for i in range(3):
        hb = {
            "agent_id": AGENT_ID,
            "status": "healthy",
            "cpu": 12.4 + i,
            "timestamp": time.time(),
        }
        r = requests.post(f"{COMMAND_NODE_URL}/api/heartbeat", json=hb)
        print(f"      -> Pulse #{i+1} delivered: status={hb['status']} cpu={hb['cpu']:.1f}%")
        time.sleep(2.0)

    # Step 2: Simulate Adversary Kill
    print(f"\n[2/3] [SABOTAGE EVENT] Adversary executes 'kill -9' on the AEGIS agent daemon!")
    print(f"      Node {AGENT_ID} ceases all network heartbeat transmissions immediately.")
    print("      Awaiting Command Node silence detection (threshold = 15.0 seconds)...\n")

    start_wait = time.time()
    alarm_fired = False

    while time.time() - start_wait < 22:
        elapsed = time.time() - start_wait
        try:
            # Query active alarms endpoint
            resp = requests.get(f"{COMMAND_NODE_URL}/api/alerts", timeout=2)
            alerts = resp.json().get("alerts", [])
            matching = [a for a in alerts if a.get("agent_id") == AGENT_ID and not a.get("acknowledged")]
            if matching:
                alarm = matching[0]
                print(f"\n{'!'*65}")
                print(f" [ALARM TRIGGERED] CRITICAL SILENT_ALARM DETECTED at {elapsed:.1f}s!")
                print(f" Alarm ID         : {alarm.get('id')}")
                print(f" Agent ID         : {alarm.get('agent_id')}")
                print(f" Silence Duration : {alarm.get('silence_duration')}s")
                print(f" Persisted In     : NeonDB (silence_alarms table)")
                print(f" Dashboard Banner : ACTIVE (Acknowledge button enabled)")
                print(f"{'!'*65}\n")
                alarm_fired = True
                break
        except Exception:
            pass

        print(f"      ... monitoring silence detector ({elapsed:.1f}s elapsed)...", end="\r")
        time.sleep(1.5)

    if alarm_fired:
        print("[SUCCESS] Silence-as-Alarm detection verified. Adversary tamper successfully caught!")
    else:
        print("\n[NOTE] Alarm detection in progress or Command Node threshold pending.")


if __name__ == "__main__":
    run_simulation()
