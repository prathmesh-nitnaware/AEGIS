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
    payload = {"status": status, "result_details": details}
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
    pid = action.get("target_pid")
    target_file = (
        action.get("target_file")
        or details.get("target_file")
        or details.get("file_path")
    )

    # 1. Validate the action type BEFORE simulation or execution.
    supported_actions = {
        "LOG",
        "ALERT",
        "KILL_PROCESS",
        "QUARANTINE_FILE",
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

    # 2. Host isolation remains disabled.
    if action_type == "ISOLATE_HOST":
        return "DENIED", {
            "message": "Host isolation is not implemented; action denied."
        }

    # 3. Non-destructive actions.
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
        }

    # 5. Process termination: validate PID and process name.
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

            proc.terminate()

            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()

            return "SUCCESS", {
                "message": "Validated process terminated.",
                "pid": pid,
                "process_name": actual_name,
            }

        except Exception as exc:
            return "FAILED", {
                "message": "Process termination failed.",
                "error": str(exc),
            }

    # 6. File quarantine: enforce explicitly allowed directories.
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

        if not resolved_roots or not any(
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

    # Defensive fallback.
    return "DENIED", {
        "message": f"Unsupported action type: {action_type!r}"
    }
    action_type = str(action.get("action_type", "")).upper()
    params = action.get("parameters") or {}
    details = params.get("details") or {}
    pid = action.get("target_pid")
    target_file = action.get("target_file") or details.get(
        "target_file") or details.get("file_path")

    if action_type in {"LOG", "ALERT"}:
        return "SIMULATED" if not LIVE else "SUCCESS", {
            "message": f"{action_type} recorded by response worker",
            "simulation": not LIVE,
        }

    if action_type == "ISOLATE_HOST":
        return "DENIED", {"message": "Host isolation is not implemented; action denied."}

    if not LIVE or not AUTO_REMEDIATE:
        return "SIMULATED", {
            "message": f"Would execute {action_type}; live mode and auto-remediation are not both enabled.",
            "simulation": True,
            "target_pid": pid,
            "target_file": str(target_file) if target_file else None,
        }

    if action_type == "KILL_PROCESS":
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return "DENIED", {"message": "Missing or invalid target PID."}
        expected_name = str(details.get("process_name")
                            or details.get("process") or "").strip()
        if pid <= 1 or not expected_name:
            return "DENIED", {"message": "PID must be > 1 and expected process name is required."}
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
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            return "SUCCESS", {"message": "Validated process terminated.", "pid": pid, "process_name": actual_name}
        except Exception as exc:
            return "FAILED", {"message": "Process termination failed.", "error": str(exc)}

    if action_type == "QUARANTINE_FILE":
        if not isinstance(target_file, str) or not target_file.strip():
            return "DENIED", {"message": "Missing target file path."}
        source = Path(target_file).resolve()
        if not source.is_file():
            return "NOT_FOUND", {"message": "Target is not a regular file."}
        # Avoid moving core OS paths; quarantine only files under explicit configured roots.
        allowed_roots = [p.strip() for p in os.getenv(
            "AEGIS_QUARANTINE_ALLOWED_ROOTS", "").split(os.pathsep) if p.strip()]
        resolved_roots = [Path(p).resolve() for p in allowed_roots]
        if not resolved_roots or not any(source == r or r in source.parents for r in resolved_roots):
            return "DENIED", {"message": "File is outside AEGIS_QUARANTINE_ALLOWED_ROOTS."}
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
            return "FAILED", {"message": "Quarantine move failed.", "error": str(exc)}

    return "DENIED", {"message": f"Unsupported action type: {action_type!r}"}


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
