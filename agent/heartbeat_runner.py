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

import os
import signal
import sys
import time
import requests

from agent.heartbeat import HeartbeatEmitter

# ---------------------------------------------------------------------------
# Config - edit these or pass env vars AGENT_ID and COMMAND_NODE_URL
# ---------------------------------------------------------------------------
AGENT_ID = os.getenv("AGENT_ID", "vm1")
COMMAND_NODE_URL = os.getenv("COMMAND_NODE_URL", "http://localhost:8000").rstrip("/")
HEARTBEAT_INTERVAL = float(os.getenv("HEARTBEAT_INTERVAL", "5.0"))


def http_send(payload: dict) -> None:
    """send_fn passed into HeartbeatEmitter - fire-and-forget over HTTP."""
    try:
        requests.post(f"{COMMAND_NODE_URL}/api/heartbeat", json=payload, timeout=2)
    except requests.RequestException as exc:
        print(f"[{AGENT_ID}] heartbeat send failed: {exc}")


def send_shutdown_beacon(reason: str = "user_initiated_shutdown") -> bool:
    """
    Emergency Synchronous 'Last-Gasp' Goodbye beacon.
    Sent when the OS is shutting down or the user cleanly stops the service.
    Informs Command Node to suppress silence alarms for this machine.
    """
    payload = {
        "agent_id": AGENT_ID,
        "status": "OFFLINE_GRACEFUL",
        "reason": reason,
        "timestamp": time.time(),
    }
    print(f"\n[{AGENT_ID}] Sending graceful shutdown beacon to Command Node ({reason})...")
    try:
        resp = requests.post(f"{COMMAND_NODE_URL}/api/heartbeat/shutdown", json=payload, timeout=3)
        if resp.status_code == 200:
            print(f"[{AGENT_ID}] Graceful departure acknowledged by Command Node. Silence alarms suppressed.")
            return True
    except Exception as exc:
        print(f"[{AGENT_ID}] Could not deliver shutdown beacon: {exc}")
    return False


def setup_os_shutdown_hooks(emitter: HeartbeatEmitter):
    """
    Registers cross-platform OS shutdown interceptors:
      - Windows: win32api.SetConsoleCtrlHandler traps CTRL_SHUTDOWN_EVENT,
        CTRL_LOGOFF_EVENT, and CTRL_CLOSE_EVENT during OS power-off / reboot.
      - Linux: signal.SIGTERM and signal.SIGINT trap systemd / init shutdown.
    """
    def on_terminate(signum_or_event, frame=None):
        reason = f"signal_{signum_or_event}"
        if isinstance(signum_or_event, int):
            if signum_or_event == 6:
                reason = "WINDOWS_OS_SHUTDOWN"
            elif signum_or_event == 5:
                reason = "WINDOWS_USER_LOGOFF"
            elif signum_or_event == 2:
                reason = "CONSOLE_WINDOW_CLOSED"
            elif signum_or_event == signal.SIGTERM:
                reason = "SYSTEMD_SIGTERM"
            elif signum_or_event == signal.SIGINT:
                reason = "USER_KEYBOARD_INTERRUPT"

        print(f"\n[{AGENT_ID}] Intercepted OS shutdown event: {reason}")
        emitter.stop()
        send_shutdown_beacon(reason=reason)
        sys.exit(0)

    # 1. Standard POSIX / Python signals (handles Linux systemd shutdown)
    try:
        signal.signal(signal.SIGTERM, on_terminate)
        signal.signal(signal.SIGINT, on_terminate)
    except Exception:
        pass

    # 2. Windows-specific console & OS shutdown handler
    if sys.platform == "win32":
        try:
            import win32api

            def win_handler(ctrl_type):
                # 6 = CTRL_SHUTDOWN_EVENT, 5 = CTRL_LOGOFF_EVENT, 2 = CTRL_CLOSE_EVENT
                if ctrl_type in (2, 5, 6):
                    on_terminate(ctrl_type)
                    return True
                return False

            win32api.SetConsoleCtrlHandler(win_handler, True)
            print(f"[{AGENT_ID}] Windows OS shutdown hook registered (win32api SetConsoleCtrlHandler).")
        except ImportError:
            print(f"[{AGENT_ID}] win32api not available - relying on standard signals.")


def main():
    emitter = HeartbeatEmitter(
        agent_id=AGENT_ID,
        interval=HEARTBEAT_INTERVAL,
        send_fn=http_send,
    )
    setup_os_shutdown_hooks(emitter)
    emitter.start()

    from agent.action_consumer import ActionConsumerDaemon
    consumer = ActionConsumerDaemon(
        agent_id=AGENT_ID,
        command_node_url=COMMAND_NODE_URL,
        poll_interval=2.0,
    )
    consumer.start()

    print(f"[{AGENT_ID}] Heartbeat runner started -> {COMMAND_NODE_URL}/api/heartbeat")
    print(f"[{AGENT_ID}] Autonomous Action Consumer active -> {COMMAND_NODE_URL}/api/agents/{AGENT_ID}/actions/pending")
    print(f"[{AGENT_ID}] Note: A clean Ctrl+C or OS shutdown sends a graceful departure beacon.")
    print(f"[{AGENT_ID}]       A forceful kill (kill -9 or taskkill /F) simulates adversary tampering.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{AGENT_ID}] Keyboard interrupt received...")
        emitter.stop()
        consumer.stop()
        send_shutdown_beacon("user_keyboard_interrupt")


if __name__ == "__main__":
    main()
