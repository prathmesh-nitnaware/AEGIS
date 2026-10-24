"""Polling response worker for AEGIS endpoint agents.

Default is simulation. This worker intentionally does not implement host isolation.
Process termination and file quarantine require explicit environment opt-in.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BASE_URL = os.getenv("COMMAND_NODE_URL", "").rstrip("/")
AGENT_ID = os.getenv("AEGIS_AGENT_ID", "").strip()
POLL_SECONDS = max(2.0, float(os.getenv("AEGIS_RESPONSE_POLL_SECONDS", "5")))
LIVE = os.getenv("AEGIS_RESPONSE_MODE", "simulation").lower() == "live"
AUTO_REMEDIATE = os.getenv("AEGIS_AUTO_REMEDIATE", "false").lower() in {
    "1", "true", "yes", "on"}
QUARANTINE_DIR = Path(os.getenv("AEGIS_QUARANTINE_DIR",
                      "./aegis_quarantine")).resolve()
TOKEN = os.getenv("X_AEGIS_AGENT_TOKEN", "").strip()


def _request(method: str, url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if TOKEN:
        headers["X-AEGIS-Agent-Token"] = TOKEN
    req = urllib.request.Request(
        url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        raw = response.read().decode("utf-8", errors="replace")
    return json.loads(raw) if raw.strip() else {}


def _ack(action_id: str, status: str, details: dict[str, Any]) -> None:
    payload = {"status": str(status).strip().upper(), "result_details": details}
    _request(
        "POST", f"{BASE_URL}/api/agents/{AGENT_ID}/actions/{action_id}/ack", payload)


def _safe_process_name(pid: int) -> str | None:
    try:
        import psutil
        return psutil.Process(pid).name()
    except Exception:
        return None


def _execute(action: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    action_type = str(action.get("action_type", "")).upper()
    params = action.get("parameters") or {}
    details = params.get("details") or {}
    pid = action.get("target_pid") or details.get("pid")
    target_file = (
        action.get("target_file")
        or details.get("target_file")
        or details.get("file_path")
    )
    target_ip = (
        action.get("target_ip")
        or details.get("remote_ip")
        or details.get("src_ip")
        or details.get("ip")
    )

    # 1. Validate the action type BEFORE simulation or execution.
    supported_actions = {
        "LOG",
        "ALERT",
        "KILL_PROCESS",
        "SUSPEND_PROCESS",
        "RESUME_PROCESS",
        "QUARANTINE_FILE",
        "BLOCK_REMOTE_IP",
        "UNBLOCK_REMOTE_IP",
        "ISOLATE_HOST",
        "SHUTDOWN_AGENT",
        "SHUTDOWN",
    }

    if action_type not in supported_actions:
        return "DENIED", {
            "message": f"Unsupported action type: {action_type!r}"
        }

    # Handle agent shutdown directive
    if action_type in {"SHUTDOWN_AGENT", "SHUTDOWN"}:
        import threading
        def _terminate_agent():
            time.sleep(1.0)
            os._exit(0)
        threading.Thread(target=_terminate_agent, daemon=True).start()
        return "SUCCESS", {"message": "Agent cascade shutdown triggered by Command Node"}

    # 2. Host isolation remains disabled (anti-lockout policy).
    if action_type == "ISOLATE_HOST":
        return "DENIED", {
            "message": "Host isolation is not implemented; action denied."
        }

    # 3. Non-destructive audit actions.
    if action_type in {"LOG", "ALERT"}:
        return ("SIMULATED" if not LIVE else "SUCCESS"), {
            "message": f"{action_type} recorded by response worker",
            "simulation": not LIVE,
        }

    # 4. Destructive actions require BOTH explicit opt-ins.
    if not LIVE or not AUTO_REMEDIATE:
        return "SIMULATED", {
            "message": (
                f"Would execute {action_type}; live mode and "
                "auto-remediation are not both enabled."
            ),
            "simulation": True,
            "target_pid": pid,
            "target_file": str(target_file) if target_file else None,
            "target_ip": str(target_ip) if target_ip else None,
        }

    # 5. Process termination: recursive process tree termination (EDR standard)
    if action_type == "KILL_PROCESS":
        if pid is None:
            return "DENIED", {"message": "Missing target PID."}

        try:
            pid = int(pid)
        except (TypeError, ValueError, OverflowError):
            return "DENIED", {"message": "Invalid target PID."}

        expected_name = str(
            details.get("process_name") or details.get("process") or ""
        ).strip()

        if pid <= 1 or not expected_name:
            return "DENIED", {
                "message": "PID must be > 1 and expected process name is required."
            }

        try:
            import psutil

            proc = psutil.Process(pid)
            actual_name = proc.name()

            if actual_name.casefold() != expected_name.casefold():
                return "DENIED", {
                    "message": "Process name mismatch; refusing to terminate.",
                    "expected_name": expected_name,
                    "actual_name": actual_name,
                }

            # EDR Standard: Terminate entire process tree (children first) to eliminate worker daemons/shells
            children = []
            try:
                children = proc.children(recursive=True)
            except Exception:
                pass

            # Suspend tree first to prevent spawning replacements
            for child in children:
                try:
                    child.suspend()
                except Exception:
                    pass
            try:
                proc.suspend()
            except Exception:
                pass

            # Kill children
            for child in children:
                try:
                    child.kill()
                except Exception:
                    pass

            # Kill parent process
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()

            return "SUCCESS", {
                "message": f"Process tree terminated ({len(children)} child processes neutralized).",
                "pid": pid,
                "process_name": actual_name,
                "children_killed": len(children),
            }

        except Exception as exc:
            return "FAILED", {
                "message": "Process termination failed.",
                "error": str(exc),
            }

    # 6. Process suspension and resumption (triage freeze)
    if action_type in {"SUSPEND_PROCESS", "RESUME_PROCESS"}:
        if pid is None:
            return "DENIED", {"message": "Missing target PID."}
        try:
            pid = int(pid)
            import psutil
            proc = psutil.Process(pid)
            expected_name = str(details.get("process_name") or details.get("process") or "").strip()
            if expected_name and proc.name().casefold() != expected_name.casefold():
                return "DENIED", {"message": "Process name mismatch."}

            if action_type == "SUSPEND_PROCESS":
                for child in proc.children(recursive=True):
                    try:
                        child.suspend()
                    except Exception:
                        pass
                proc.suspend()
                return "SUCCESS", {"message": "Process tree suspended.", "pid": pid}
            else:
                proc.resume()
                for child in proc.children(recursive=True):
                    try:
                        child.resume()
                    except Exception:
                        pass
                return "SUCCESS", {"message": "Process tree resumed.", "pid": pid}
        except Exception as exc:
            return "FAILED", {"message": f"{action_type} failed.", "error": str(exc)}

    # 7. File quarantine: enforce explicitly allowed directories.
    if action_type == "QUARANTINE_FILE":
        if not isinstance(target_file, str) or not target_file.strip():
            return "DENIED", {"message": "Missing target file path."}

        source = Path(target_file).resolve()

        if not source.is_file():
            return "NOT_FOUND", {
                "message": "Target is not a regular file."
            }

        allowed_roots = [
            p.strip()
            for p in os.getenv(
                "AEGIS_QUARANTINE_ALLOWED_ROOTS", ""
            ).split(os.pathsep)
            if p.strip()
        ]
        resolved_roots = [Path(p).resolve() for p in allowed_roots]

        if allowed_roots and not any(
            source == root or root in source.parents
            for root in resolved_roots
        ):
            return "DENIED", {
                "message": (
                    "File is outside AEGIS_QUARANTINE_ALLOWED_ROOTS."
                )
            }

        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        destination = QUARANTINE_DIR / f"{digest}_{source.name}"

        try:
            shutil.move(str(source), str(destination))
            return "SUCCESS", {
                "message": "File moved to quarantine.",
                "sha256": digest,
                "quarantine_path": str(destination),
            }
        except Exception as exc:
            return "FAILED", {
                "message": "Quarantine move failed.",
                "error": str(exc),
            }

    # 8. Network IP blocking with Anti-Lockout Demo Protection
    if action_type in {"BLOCK_REMOTE_IP", "UNBLOCK_REMOTE_IP"}:
        if not target_ip:
            return "DENIED", {"message": "Missing target IP address for network response."}

        target_ip_str = str(target_ip).strip()

        # Strict Anti-Lockout Whitelist: Protect loopback, local adapters, and Command Node host
        import urllib.parse
        import socket
        protected_ips = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}
        try:
            protected_ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
        except Exception:
            pass
        if BASE_URL:
            try:
                cmd_host = urllib.parse.urlsplit(BASE_URL).hostname
                if cmd_host:
                    protected_ips.add(cmd_host)
            except Exception:
                pass

        if target_ip_str in protected_ips or target_ip_str.startswith("127."):
            return "DENIED", {
                "message": f"Anti-Lockout: Target IP {target_ip_str} is protected AEGIS infrastructure (Command Node/Demo Device). Refusing to block.",
                "protected": True,
            }

        rule_name = f"AEGIS_BLOCK_{target_ip_str.replace(':', '_').replace('.', '_')}"
        import platform
        import subprocess
        system_platform = platform.system().lower()

        try:
            if action_type == "BLOCK_REMOTE_IP":
                if "windows" in system_platform:
                    cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={target_ip_str}"]
                    subprocess.run(cmd, capture_output=True, check=True, timeout=5)
                elif "linux" in system_platform:
                    cmd = ["iptables", "-I", "INPUT", "-s", target_ip_str, "-j", "DROP"]
                    subprocess.run(cmd, capture_output=True, check=True, timeout=5)
                return "SUCCESS", {"message": f"Firewall rule added blocking remote attacker IP {target_ip_str}.", "remote_ip": target_ip_str, "rule_name": rule_name}
            else:
                if "windows" in system_platform:
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                    subprocess.run(cmd, capture_output=True, timeout=5)
                elif "linux" in system_platform:
                    cmd = ["iptables", "-D", "INPUT", "-s", target_ip_str, "-j", "DROP"]
                    subprocess.run(cmd, capture_output=True, timeout=5)
                return "SUCCESS", {"message": f"Firewall rule removed for IP {target_ip_str}.", "remote_ip": target_ip_str}
        except Exception as exc:
            return "FAILED", {"message": f"Firewall modification failed: {exc}", "error": str(exc)}

    # Defensive fallback.
    return "DENIED", {
        "message": f"Unsupported action type: {action_type!r}"
    }


def process_action(action: dict[str, Any]) -> None:
    action_id = str(action.get("action_id", "")).strip()
    if not action_id:
        print("[response-worker] Skipping action without action_id")
        return
    try:
        status, result = _execute(action)
        print(
            f"[response-worker] action={action_id} type={action.get('action_type')} status={status}: {result}")
        _ack(action_id, status, result)
    except Exception as exc:
        # Avoid acknowledging if the API itself is unavailable; a later poll can retry.
        print(f"[response-worker] action={action_id} processing error: {exc}")


def main() -> None:
    if not BASE_URL or not AGENT_ID:
        raise SystemExit(
            "Set COMMAND_NODE_URL and AEGIS_AGENT_ID before starting response_worker.")
    print(
        f"[response-worker] agent={AGENT_ID} server={BASE_URL} mode={'LIVE' if LIVE else 'SIMULATION'}")
    while True:
        try:
            result = _request(
                "GET", f"{BASE_URL}/api/agents/{AGENT_ID}/actions/pending")
            for action in result.get("actions", []):
                process_action(action)
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            print(f"[response-worker] poll failed: {exc}")
        except Exception as exc:
            print(f"[response-worker] unexpected poll error: {exc}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
