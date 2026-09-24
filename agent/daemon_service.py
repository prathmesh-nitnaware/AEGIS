"""
agent/daemon_service.py
=======================
AEGIS Cross-Platform Agent Daemon & Service Controller.
Manages the unified agent lifecycle:
  1. Heartbeat & Graceful Shutdown Beacon
  2. Autonomous Action Consumer & Remediation Driver
  3. P2P ZeroMQ / UDP Wire Mesh Consensus Node
  4. OS-Aware Live Telemetry Collectors

CLI Commands:
  python -m agent.daemon_service start
  python -m agent.daemon_service stop
  python -m agent.daemon_service status
  python -m agent.daemon_service doctor
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from agent.config import AegisAgentConfig, get_default_config_path
from agent.heartbeat import HeartbeatEmitter
from agent.action_consumer import ActionConsumerDaemon
from agent.p2p_mesh import P2PMeshNode


def get_pid_file_path() -> Path:
    """Returns platform-specific PID file location."""
    if platform.system().lower() == "windows":
        prog_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(prog_data) / "AEGIS" / "agent.pid"
    else:
        # Try /run/aegis-agent.pid or /tmp fallback
        run_dir = Path("/run/aegis")
        if run_dir.exists() and os.access(str(run_dir), os.W_OK):
            return run_dir / "agent.pid"
        return Path("/tmp/aegis-agent.pid")


class AegisAgentDaemon:
    """Unified background service daemon for the AEGIS EDR Agent."""

    def __init__(self, config: Optional[AegisAgentConfig] = None):
        self.config = config or AegisAgentConfig.load()
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._p2p_node: Optional[P2PMeshNode] = None
        self._emitter: Optional[HeartbeatEmitter] = None
        self._action_consumer: Optional[ActionConsumerDaemon] = None
        self._pid_file = get_pid_file_path()

    def _send_heartbeat_payload(self, payload: dict):
        """HTTP transport shipping heartbeat to Command Node."""
        try:
            url = f"{self.config.command_node_url.rstrip('/')}/api/heartbeat"
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2.5)
        except Exception:
            pass

    def run(self):
        """Starts all agent subsystems and blocks until shutdown signal."""
        self._write_pid()
        self._setup_signal_handlers()

        print("=" * 65)
        print("  AEGIS EDR AGENT DAEMON")
        print(f"  Node ID:          {self.config.agent_id}")
        print(f"  Command Node:     {self.config.command_node_url}")
        print(f"  Platform:         {platform.system()} {platform.release()} ({platform.machine()})")
        print(f"  P2P Mesh Port:    {self.config.p2p_bind_port} (Enabled: {self.config.p2p_enabled})")
        print(f"  Quarantine Vault: {self.config.quarantine_dir}")
        print("=" * 65)

        # 1. Start P2P Wire Mesh Node
        if self.config.p2p_enabled:
            try:
                self._p2p_node = P2PMeshNode(
                    agent_id=self.config.agent_id,
                    bind_port=self.config.p2p_bind_port,
                )
                self._p2p_node.start()
                for peer in self.config.p2p_peers:
                    if ":" in peer:
                        h, p = peer.split(":", 1)
                        self._p2p_node.register_peer(peer_id=f"peer-{h}", host=h, port=int(p))
                print(f"[Daemon] P2P Wire Mesh listening on port {self.config.p2p_bind_port}")
            except Exception as exc:
                print(f"[Daemon] Warning: P2P Mesh initialization failed: {exc}")

        # 2. Start Heartbeat Emitter
        self._emitter = HeartbeatEmitter(
            agent_id=self.config.agent_id,
            interval=self.config.heartbeat_interval,
            send_fn=self._send_heartbeat_payload,
        )
        self._emitter.start()
        print(f"[Daemon] Heartbeat emitter started (interval: {self.config.heartbeat_interval}s)")

        # 3. Start Action Consumer Worker Thread
        if self.config.enable_active_response:
            try:
                self._action_consumer = ActionConsumerDaemon(
                    agent_id=self.config.agent_id,
                    command_node_url=self.config.command_node_url,
                    poll_interval=2.5,
                )
                self._action_consumer.start()
                print("[Daemon] Action consumer worker active (listening for mitigation directives)")
            except Exception as exc:
                print(f"[Daemon] Warning: Action consumer start failed: {exc}")

        # 4. Main Event Loop
        try:
            while not self._stop_event.is_set():
                time.sleep(0.5)
        except (KeyboardInterrupt, SystemExit):
            print("\n[Daemon] Shutdown interrupt received.")
        finally:
            self.stop()

    def stop(self):
        """Gracefully halts all agent subsystems and notifies Command Node."""
        print("[Daemon] Initiating graceful agent shutdown...")
        self._stop_event.set()

        # Stop action consumer
        if self._action_consumer:
            try:
                self._action_consumer.stop()
            except Exception:
                pass

        # Stop heartbeat emitter
        if self._emitter:
            try:
                self._emitter.stop()
            except Exception:
                pass

        # Send graceful shutdown beacon to Command Node so no False Alarm is raised
        try:
            url = f"{self.config.command_node_url.rstrip('/')}/api/heartbeat/shutdown"
            payload = {
                "agent_id": self.config.agent_id,
                "status": "OFFLINE_GRACEFUL",
                "reason": "Planned agent daemon shutdown",
                "timestamp": time.time(),
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2.5)
            print("[Daemon] Graceful shutdown beacon transmitted to Command Node.")
        except Exception as exc:
            print(f"[Daemon] Warning: Failed to send shutdown beacon: {exc}")

        # Stop P2P node
        if self._p2p_node:
            try:
                self._p2p_node.stop()
            except Exception:
                pass

        self._remove_pid()
        print("[Daemon] AEGIS EDR Agent stopped cleanly.")

    def _write_pid(self):
        try:
            self._pid_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._pid_file, "w") as f:
                f.write(str(os.getpid()))
        except Exception:
            pass

    def _remove_pid(self):
        try:
            if self._pid_file.exists():
                self._pid_file.unlink()
        except Exception:
            pass

    def _setup_signal_handlers(self):
        """Hooks standard OS termination signals."""
        def handler(signum, frame):
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

        if platform.system().lower() == "windows":
            try:
                import win32api
                win32api.SetConsoleCtrlHandler(lambda sig: self.stop() or True, True)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# DIAGNOSTICS & DOCTOR PROBE
# ---------------------------------------------------------------------------

def run_doctor(config: AegisAgentConfig) -> Dict[str, Any]:
    """Runs a comprehensive diagnostic check of the agent's environment and models."""
    print("=" * 65)
    print("  AEGIS AGENT DIAGNOSTIC HEALTH PROBE (DOCTOR)")
    print("=" * 65)

    checks = []

    # 1. Python Environment Check
    py_ver = sys.version_split = sys.version.split()[0]
    py_ok = sys.version_info >= (3, 10)
    checks.append({
        "name": "Python 3.10+ Runtime",
        "status": "PASS" if py_ok else "FAIL",
        "detail": f"Python {py_ver} ({sys.executable})",
    })

    # 2. Host OS & Architecture
    checks.append({
        "name": "Operating System",
        "status": "PASS",
        "detail": f"{platform.system()} {platform.release()} ({platform.machine()})",
    })

    # 3. Model Artifacts Discovery
    models_dir = _PROJECT_ROOT / "trained_models"
    model_files = [
        ("linux_ids", "linux_ids/linux_xgboost_model.pkl"),
        ("windows_advanced", "windows_advanced_v3/windows_advanced_v3.pkl"),
        ("cicids", "cicids/aegis_lgbm_cicids_model.pkl"),
        ("ember", "ember/aegis_ember_model_full.pkl"),
        ("hdfs", "hdfs/hdfs_xgboost_model.pkl"),
        ("zero_day", "zero_day/aegis_zero_day_model.pkl"),
    ]

    all_models_found = True
    for model_name, rel_path in model_files:
        full_path = models_dir / rel_path
        if full_path.exists() and full_path.stat().st_size > 1000:
            checks.append({
                "name": f"ML Model [{model_name}]",
                "status": "PASS",
                "detail": f"Present ({round(full_path.stat().st_size / 1024, 1)} KB)",
            })
        else:
            all_models_found = False
            checks.append({
                "name": f"ML Model [{model_name}]",
                "status": "WARN",
                "detail": f"Artifact not found at {rel_path}",
            })

    # 4. Command Node Connectivity
    cmd_url = config.command_node_url.rstrip("/")
    cmd_ok = False
    try:
        req = urllib.request.urlopen(f"{cmd_url}/api/health", timeout=3.0)
        if req.getcode() == 200:
            cmd_ok = True
            checks.append({
                "name": "Command Node API Reachability",
                "status": "PASS",
                "detail": f"Connected to {cmd_url} (HTTP 200)",
            })
    except Exception as exc:
        checks.append({
            "name": "Command Node API Reachability",
            "status": "FAIL",
            "detail": f"Cannot reach {cmd_url}: {exc}",
        })

    # 5. Quarantine & Log Permissions
    q_dir = Path(config.quarantine_dir)
    try:
        q_dir.mkdir(parents=True, exist_ok=True)
        test_file = q_dir / ".write_test"
        test_file.write_text("test")
        test_file.unlink()
        checks.append({
            "name": "Quarantine Vault Permissions",
            "status": "PASS",
            "detail": f"Writable ({q_dir})",
        })
    except Exception as exc:
        checks.append({
            "name": "Quarantine Vault Permissions",
            "status": "FAIL",
            "detail": f"Not writable ({q_dir}): {exc}",
        })

    # Print Summary
    print("\nDIAGNOSTIC RESULTS:")
    print("-" * 65)
    for c in checks:
        badge = "[PASS]" if c["status"] == "PASS" else "[WARN]" if c["status"] == "WARN" else "[FAIL]"
        print(f" {badge:8} {c['name']:32} : {c['detail']}")
    print("-" * 65)

    all_pass = all(c["status"] == "PASS" for c in checks if c["name"].startswith("Python") or c["name"].startswith("Quarantine"))
    print(f"Overall Health: {'READY FOR DEPLOYMENT' if all_pass else 'ISSUES DETECTED'}\n")
    return {"ready": all_pass, "checks": checks}


# ---------------------------------------------------------------------------
# CLI ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AEGIS EDR Agent Service Controller")
    parser.add_argument("action", choices=["start", "stop", "status", "doctor", "config"], default="start", nargs="?")
    parser.add_argument("--config", "-c", help="Path to custom agent.conf file", default=None)
    args = parser.parse_args()

    config = AegisAgentConfig.load(args.config)

    if args.action == "doctor":
        run_doctor(config)
    elif args.action == "config":
        print(json.dumps(config.__dict__, indent=2))
    elif args.action == "status":
        pid_file = get_pid_file_path()
        if pid_file.exists():
            pid = pid_file.read_text().strip()
            print(f"[AEGIS Agent] Running with PID {pid} (PID File: {pid_file})")
        else:
            print("[AEGIS Agent] Stopped (No active PID file found)")
    elif args.action == "stop":
        pid_file = get_pid_file_path()
        if pid_file.exists():
            pid = int(pid_file.read_text().strip())
            print(f"[AEGIS Agent] Terminating PID {pid}...")
            try:
                os.kill(pid, signal.SIGTERM)
                print("[AEGIS Agent] Termination signal sent.")
            except Exception as exc:
                print(f"[AEGIS Agent] Error stopping process: {exc}")
        else:
            print("[AEGIS Agent] No active agent PID file found.")
    elif args.action == "start":
        daemon = AegisAgentDaemon(config=config)
        daemon.run()


if __name__ == "__main__":
    main()
