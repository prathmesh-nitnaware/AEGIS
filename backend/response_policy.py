"""Central policy gate for AEGIS remote response actions.

Safe defaults:
- Alerts are allowed.
- Destructive actions require consensus, a valid target, and explicit opt-in.
- Host isolation is denied because no safe, platform-specific isolation handler
  is implemented in this response component.
"""
from __future__ import annotations

import math
import os
from typing import Any, Mapping

ALLOWED_ACTIONS = {"LOG", "ALERT", "KILL_PROCESS", "QUARANTINE_FILE", "ISOLATE_HOST"}
DESTRUCTIVE_ACTIONS = {"KILL_PROCESS", "QUARANTINE_FILE", "ISOLATE_HOST"}


def _enabled(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def decide_response(verdict: Mapping[str, Any]) -> dict[str, Any]:
    """Return a normalized decision; never execute an action here."""
    try:
        score = float(verdict.get("final_weighted_score",
                                  verdict.get("threat_score",
                                              verdict.get("raw_threat_score", 0.0))))
    except (TypeError, ValueError):
        score = 0.0

    if not math.isfinite(score):
        score = 0.0
    score = min(1.0, max(0.0, score))

    severity = str(verdict.get("severity", "LOW")).upper()
    consensus = bool(verdict.get("consensus_reached", False))
    details = verdict.get("details") or {}
    if not isinstance(details, Mapping):
        details = {}

    # A score alone never authorizes destructive action.
    if score < 0.30:
        proposed = "LOG"
    elif score < 0.60 or not consensus:
        proposed = "ALERT"
    else:
        proposed = "ALERT"

    # Destructive response is opt-in and requires corroborated consensus.
    # Even when enabled, validate the exact target before queueing.
    if _enabled("AEGIS_AUTO_REMEDIATE", False) and consensus:
        if score >= float(os.getenv("AEGIS_KILL_THRESHOLD", "0.90")):
            pid = details.get("pid", verdict.get("target_pid"))
            process_name = details.get("process_name") or details.get("process")
            try:
                pid_int = int(pid)
            except (TypeError, ValueError):
                pid_int = -1
            if pid_int > 1 and process_name and str(process_name).strip():
                proposed = "KILL_PROCESS"

        if score >= float(os.getenv("AEGIS_QUARANTINE_THRESHOLD", "0.90")):
            file_path = (details.get("target_file") or details.get("file_path")
                         or details.get("filename") or verdict.get("target_file"))
            if isinstance(file_path, str) and file_path.strip():
                # Prefer quarantine for file-specific evidence if the event has a file target.
                if str(verdict.get("event_type", "")).lower() in {"file", "ember"}:
                    proposed = "QUARANTINE_FILE"

    if proposed == "ISOLATE_HOST":
        proposed = "ALERT"  # fail closed: no host-isolation executor implemented

    return {
        "action": proposed,
        "score": score,
        "severity": severity,
        "consensus_reached": consensus,
        "reason": (
            "destructive action is disabled or insufficiently corroborated"
            if proposed == "ALERT" and (score >= 0.60 or not consensus)
            else "policy decision"
        ),
    }
