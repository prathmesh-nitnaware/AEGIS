"""
agent/heartbeat_runner.py
==========================
Runs HeartbeatEmitter on an agent machine and ships each pulse to the
Command Node (backend/telemetry_api.py) over plain HTTP POST.

This plugs into HeartbeatEmitter's existing send_fn seam - no changes to
heartbeat.py needed, that's exactly what it was built for.

To simulate "attacker kills the agent" for the demo: Ctrl+C this process
(or `kill <pid>`) and watch the Command Node / dashboard raise the silent
alarm within ~15-17 seconds.

Run:
    python -m agent.heartbeat_runner

Dependencies:
    pip install requests psutil
"""

import time

import requests

from agent.heartbeat import HeartbeatEmitter

# ---------------------------------------------------------------------------
# Config - edit these two per machine before running
# ---------------------------------------------------------------------------
# unique per machine: vm1, vm2, vm3, vm4
AGENT_ID = "vm1"
# set to the Command Node's actual LAN IP
COMMAND_NODE_URL = "http://172.16.239.134:8000"
# seconds - matches SilenceDetector's expectation
HEARTBEAT_INTERVAL = 5.0


def http_send(payload: dict) -> None:
    """send_fn passed into HeartbeatEmitter - fire-and-forget over HTTP."""
    try:
        requests.post(f"{COMMAND_NODE_URL}/api/heartbeat",
                      json=payload, timeout=2)
    except requests.RequestException as exc:
        # Don't let a network hiccup take down the emitter loop - just skip
        # this pulse, the next one goes out on schedule.
        print(f"[{AGENT_ID}] heartbeat send failed: {exc}")


def main():
    emitter = HeartbeatEmitter(
        agent_id=AGENT_ID,
        interval=HEARTBEAT_INTERVAL,
        send_fn=http_send,
    )
    emitter.start()
    print(f"[{AGENT_ID}] heartbeat runner started -> {COMMAND_NODE_URL}/api/heartbeat")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{AGENT_ID}] shutting down...")
        emitter.stop()


if __name__ == "__main__":
    main()
