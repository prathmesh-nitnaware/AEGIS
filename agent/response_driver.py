"""
agent/response_driver.py
========================
AEGIS - Local Agent Active Response Enforcement Driver
------------------------------------------------------
Executes automated OS-level response actions on monitored endpoint agents
based on consensus verdicts aggregated by Layer 2/3.

Supported Actions:
* **LOG**: Writes structured audit JSON entry to `aegis_audit.log`.
* **ALERT**: Emits administrative system notification and security log.
* **KILL_PROCESS**: Safely terminates malicious process PID and its child tree using `psutil`.
* **QUARANTINE_FILE**: Isolates target binary file into a restricted `.aegis_quarantine/` folder.
* **ISOLATE_HOST**: Applies temporary local firewall rules (`netsh advfirewall` on Windows,
  `iptables` on Linux) to drop external network traffic while maintaining Command Node connectivity.
* **UNISOLATE_HOST**: Restores host firewall rules to normal state.

Execution States:
- **EXECUTED**: Real OS operation completed successfully.
- **SIMULATED**: Simulation mode active or unprivileged safe fallback without OS elevation.
- **FAILED**: Operation execution encountered fatal error.
- **PARTIAL**: Sub-actions partially succeeded (e.g. allow rule succeeded, block rule failed).
- **NOT_FOUND**: Target PID or file path does not exist.
- **DENIED**: Protected PID or permission denied.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)


class AgentResponseDriver:
    """
    Cross-platform active response execution driver for AEGIS endpoint agents.
    Distinguishes real host enforcement from safe simulation.
    """

    def __init__(
        self,
        quarantine_dir: str = ".aegis_quarantine",
        audit_log_path: str = "aegis_audit.log",
        command_node_ip: str = "172.16.242.184",
        response_mode: Optional[str] = None,
        simulation_mode: Optional[bool] = None,
    ) -> None:
        self.quarantine_dir = Path(quarantine_dir).resolve()
        self.audit_log_path = Path(audit_log_path).resolve()
        self.command_node_ip = command_node_ip
        # Response mode: "real" or "simulation"
        if simulation_mode is not None:
            self.response_mode = "simulation" if simulation_mode else "real"
        else:
            self.response_mode = (response_mode or os.getenv("AEGIS_RESPONSE_MODE", "simulation")).lower()

        # Ensure quarantine folder exists
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.is_isolated: bool = False

    def log_action(self, action_name: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Record a response action into the structured local audit log."""
        record = {
            "timestamp": time.time(),
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action_name,
            "details": details,
        }

        try:
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            logger.info("[ResponseDriver] Audit log written: action=%s", action_name)
        except Exception as exc:
            logger.warning("[ResponseDriver] Failed to write audit log: %s", exc)

        return {"status": "EXECUTED", "record": record}

    def kill_process(self, pid: int) -> Dict[str, Any]:
        """
        Terminate a target process PID and its entire child process tree.
        """
        logger.info("[ResponseDriver] Attempting KILL_PROCESS for PID %d (mode=%s)", pid, self.response_mode)
        is_sim = (self.response_mode == "simulation")
        if pid <= 4:
            res = {"status": "DENIED", "reason": "Protected system PID", "target_pid": pid, "simulation": is_sim}
            self.log_action("KILL_PROCESS", res)
            return res

        if is_sim:
            res = {"status": "SIMULATED", "target_pid": pid, "mode": "simulation", "simulation": True}
            self.log_action("KILL_PROCESS", res)
            return res

        killed_pids: List[int] = []
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)

            for child in children:
                try:
                    child.kill()
                    killed_pids.append(child.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            parent.kill()
            killed_pids.append(pid)
            logger.info("[ResponseDriver] Successfully killed PID %d (and %d children)", pid, len(children))
            res = {"status": "EXECUTED", "target_pid": pid, "killed_pids": killed_pids, "simulation": False}
        except psutil.NoSuchProcess:
            logger.warning("[ResponseDriver] Process PID %d not found (already exited)", pid)
            res = {"status": "NOT_FOUND", "target_pid": pid, "simulation": False}
        except psutil.AccessDenied as exc:
            logger.error("[ResponseDriver] Access denied killing PID %d: %s", pid, exc)
            res = {"status": "DENIED", "reason": str(exc), "target_pid": pid, "simulation": False}
        except Exception as exc:
            logger.error("[ResponseDriver] Error killing PID %d: %s", pid, exc)
            res = {"status": "FAILED", "reason": str(exc), "target_pid": pid, "simulation": False}

        self.log_action("KILL_PROCESS", res)
        return res

    def quarantine_file(self, file_path: str) -> Dict[str, Any]:
        """
        Move a suspicious binary file to the secure quarantine folder.
        """
        p = Path(file_path).resolve()
        logger.info("[ResponseDriver] Attempting QUARANTINE_FILE for '%s'", p)

        is_sim = (self.response_mode == "simulation")
        if not p.exists() or not p.is_file():
            res = {"status": "NOT_FOUND", "reason": "File does not exist", "path": str(p), "simulation": is_sim}
            self.log_action("QUARANTINE_FILE", res)
            return res

        if is_sim:
            res = {"status": "SIMULATED", "path": str(p), "mode": "simulation", "simulation": True}
            self.log_action("QUARANTINE_FILE", res)
            return res

        try:
            dest_filename = f"{p.stem}_{int(time.time())}{p.suffix}.quarantine"
            dest_path = self.quarantine_dir / dest_filename
            shutil.move(str(p), str(dest_path))

            # Restrict permissions
            try:
                os.chmod(dest_path, 0o400)
            except Exception:
                pass

            logger.info("[ResponseDriver] Successfully quarantined '%s' -> '%s'", p, dest_path)
            res = {"status": "EXECUTED", "original_path": str(p), "quarantine_path": str(dest_path), "simulation": False}
        except PermissionError as exc:
            logger.error("[ResponseDriver] Permission denied quarantining '%s': %s", p, exc)
            res = {"status": "DENIED", "reason": str(exc), "path": str(p), "simulation": False}
        except Exception as exc:
            logger.error("[ResponseDriver] Failed to quarantine '%s': %s", p, exc)
            res = {"status": "FAILED", "reason": str(exc), "path": str(p), "simulation": False}

        self.log_action("QUARANTINE_FILE", res)
        return res

    def isolate_host(self, command_node_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Apply local OS firewall rules to isolate the host while still
        permitting outbound communication to the Command Node.

        Returns explicit status:
        - SIMULATED: when in simulation mode or fallback without root/admin.
        - EXECUTED: when firewall rules were genuinely applied.
        - FAILED / PARTIAL / DENIED: on real failure.
        """
        cn_ip = command_node_ip or self.command_node_ip
        logger.info("[ResponseDriver] Executing ISOLATE_HOST (Command Node IP=%s, mode=%s)", cn_ip, self.response_mode)
        os_type = platform.system()

        details: Dict[str, Any] = {
            "os": os_type,
            "command_node_ip": cn_ip,
            "rules_applied": [],
            "mode": self.response_mode,
        }

        if self.response_mode == "simulation":
            self.is_isolated = True
            details["simulated"] = True
            res = {"status": "SIMULATED", "details": details, "simulation": True}
            self.log_action("ISOLATE_HOST", res)
            return res

        # Real Mode Execution
        if os_type == "Windows":
            try:
                # Rule 1: Allow outbound specifically to Command Node
                allow_cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=AEGIS_AllowCN",
                    "dir=out",
                    "action=allow",
                    f"remoteip={cn_ip}",
                    "protocol=any",
                    "enable=yes",
                ]
                r1 = subprocess.run(allow_cmd, capture_output=True, timeout=5, text=True)
                details["rules_applied"].append(f"AEGIS_AllowCN -> {r1.returncode}")

                # Rule 2: Block ALL other outbound traffic
                block_cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=AEGIS_BlockAll",
                    "dir=out",
                    "action=block",
                    "remoteip=0.0.0.0-255.255.255.255",
                    "protocol=any",
                    "enable=yes",
                ]
                r2 = subprocess.run(block_cmd, capture_output=True, timeout=5, text=True)
                details["rules_applied"].append(f"AEGIS_BlockAll -> {r2.returncode}")

                if r1.returncode == 0 and r2.returncode == 0:
                    self.is_isolated = True
                    status = "EXECUTED"
                elif r1.returncode == 0 or r2.returncode == 0:
                    status = "PARTIAL"
                    details["stdout"] = r1.stdout + r2.stdout
                    details["stderr"] = r1.stderr + r2.stderr
                else:
                    status = "FAILED"
                    details["stdout"] = r1.stdout + r2.stdout
                    details["stderr"] = r1.stderr + r2.stderr
            except subprocess.TimeoutExpired:
                details["error"] = "netsh timed out"
                status = "FAILED"
            except PermissionError as exc:
                details["error"] = f"Insufficient privileges: {exc}"
                status = "DENIED"
            except Exception as exc:
                details["error"] = str(exc)
                status = "FAILED"

        else:  # Linux / macOS
            try:
                subprocess.run(
                    ["iptables", "-I", "OUTPUT", "1", "-m", "state",
                     "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                    capture_output=True, timeout=5, check=False,
                )
                r_cn = subprocess.run(
                    ["iptables", "-I", "OUTPUT", "2",
                     "-d", cn_ip, "-j", "ACCEPT"],
                    capture_output=True, timeout=5, text=True, check=False,
                )
                details["rules_applied"].append(f"iptables ALLOW {cn_ip} -> {r_cn.returncode}")

                r_drop = subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-j", "DROP"],
                    capture_output=True, timeout=5, text=True, check=False,
                )
                details["rules_applied"].append(f"iptables DROP all -> {r_drop.returncode}")

                if r_cn.returncode == 0 and r_drop.returncode == 0:
                    self.is_isolated = True
                    status = "EXECUTED"
                elif r_cn.returncode == 0 or r_drop.returncode == 0:
                    status = "PARTIAL"
                else:
                    status = "FAILED"
            except subprocess.TimeoutExpired:
                details["error"] = "iptables timed out"
                status = "FAILED"
            except PermissionError as exc:
                details["error"] = f"Insufficient privileges: {exc}"
                status = "DENIED"
            except FileNotFoundError:
                details["error"] = "iptables not found on PATH"
                status = "FAILED"
            except Exception as exc:
                details["error"] = str(exc)
                status = "FAILED"

        res = {"status": status, "details": details, "simulation": False}
        self.log_action("ISOLATE_HOST", res)
        return res

    def unisolate_host(self) -> Dict[str, Any]:
        """
        Remove the AEGIS isolation firewall rules and restore normal networking.
        """
        logger.info("[ResponseDriver] Executing UNISOLATE_HOST (mode=%s)", self.response_mode)
        os_type = platform.system()
        details: Dict[str, Any] = {"os": os_type, "rules_removed": [], "mode": self.response_mode}

        if self.response_mode == "simulation":
            self.is_isolated = False
            details["simulated"] = True
            res = {"status": "SIMULATED", "message": "Host un-isolated (simulation)", "details": details, "simulation": True}
            self.log_action("UNISOLATE_HOST", res)
            return res

        status = "EXECUTED"
        if os_type == "Windows":
            for rule_name in ("AEGIS_BlockAll", "AEGIS_AllowCN"):
                try:
                    r = subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                        capture_output=True, timeout=5, text=True, check=False,
                    )
                    details["rules_removed"].append(f"{rule_name} -> {r.returncode}")
                    if r.returncode != 0:
                        status = "PARTIAL"
                except PermissionError as exc:
                    details["rules_removed"].append(f"{rule_name} -> permission denied: {exc}")
                    status = "DENIED"
                except Exception as exc:
                    details["rules_removed"].append(f"{rule_name} -> error: {exc}")
                    status = "FAILED"
        else:  # Linux
            try:
                for rule in [
                    ["-D", "OUTPUT", "-j", "DROP"],
                    ["-D", "OUTPUT", "-d", self.command_node_ip, "-j", "ACCEPT"],
                    ["-D", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ]:
                    r = subprocess.run(
                        ["iptables"] + rule,
                        capture_output=True, timeout=5, check=False,
                    )
                    details["rules_removed"].append(f"{' '.join(rule)} -> {r.returncode}")
            except Exception as exc:
                details["error"] = str(exc)
                status = "FAILED"

        self.is_isolated = False
        res = {"status": status, "message": "Host un-isolated", "details": details, "simulation": False}
        self.log_action("UNISOLATE_HOST", res)
        return res

    def execute_verdict_action(self, verdict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute response action based on a consensus verdict dictionary.
        """
        action = verdict.get("response_action", verdict.get("severity", "LOG"))
        details = verdict.get("details", {})
        pid = details.get("pid") or verdict.get("pid")
        file_path = details.get("file_path") or details.get("filename") or verdict.get("file_path")

        logger.info("[ResponseDriver] Executing verdict action '%s' for vote_id=%s", action, verdict.get("vote_id"))

        if action == "KILL_PROCESS" and pid:
            return self.kill_process(int(pid))
        elif action == "QUARANTINE_FILE" and file_path:
            return self.quarantine_file(str(file_path))
        elif action == "ISOLATE_HOST":
            return self.isolate_host()
        elif action == "ALERT":
            res = {"status": "EXECUTED", "verdict": verdict}
            self.log_action("ALERT", res)
            return res
        else:
            return self.log_action("LOG", verdict)
