"""
Score + consensus driven response policy for AEGIS.

Safe by default: automated destructive actions are disabled unless
AEGIS_AUTO_REMEDIATE=true. Host isolation has a separate opt-in.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict

from agent.response_driver import AgentResponseDriver

log = logging.getLogger("aegis.response_policy")


def _enabled(name: str) -> bool:
    return os.getenv(name, "false").strip().lower() in {"1", "true", "yes", "on"}


class ConsensusResponsePolicy:
    """Translate a consensus verdict plus event context into a bounded response."""

    def __init__(self, driver: AgentResponseDriver | None = None) -> None:
        self.driver = driver or AgentResponseDriver(
            quarantine_dir=os.getenv("AEGIS_QUARANTINE_DIR", ".aegis_quarantine"),
            audit_log_path=os.getenv("AEGIS_AUDIT_LOG", "aegis_audit.log"),
            response_mode=os.getenv("AEGIS_RESPONSE_MODE", "simulation"),
        )

    def handle(self, verdict: Any, details: Dict[str, Any] | None = None) -> Dict[str, Any]:
        details = dict(details or {})
        score = float(getattr(verdict, "final_weighted_score", getattr(verdict, "raw_threat_score", 0.0)))
        score = max(0.0, min(1.0, score))
        severity = str(getattr(verdict, "severity", "LOW")).upper()
        consensus = bool(getattr(verdict, "consensus_reached", False))
        quorum = str(getattr(verdict, "quorum_status", "NO_QUORUM"))
        verdict_type = str(getattr(verdict, "verdict_type", "UNKNOWN"))
        event_type = str(getattr(verdict, "event_type", details.get("event_type", "unknown")))
        vote_id = str(getattr(verdict, "vote_id", "unknown"))

        context = {
            "vote_id": vote_id, "score": score, "severity": severity,
            "consensus_reached": consensus, "quorum_status": quorum,
            "verdict_type": verdict_type, "event_type": event_type, **details,
        }

        # A missing quorum is never treated as distributed authorization.
        if score < 0.30:
            action = "LOG"
            result = self.driver.log_action("AEGIS_POLICY_LOG", context)
        elif score < 0.60:
            action = "ALERT"
            result = self.driver.log_action("ALERT", context)
        elif score < 0.80:
            # HIGH: notify only. Do not terminate/quarantine on score alone.
            action = "ALERT"
            result = self.driver.log_action("ALERT", {**context, "reason": "HIGH score; remediation threshold not met"})
        elif not consensus:
            # CRITICAL local signal without quorum: preserve evidence and alert.
            action = "ALERT"
            result = self.driver.log_action("ALERT", {**context, "reason": "CRITICAL local signal without peer quorum; no destructive action"})
        elif not _enabled("AEGIS_AUTO_REMEDIATE"):
            action = "ALERT"
            result = self.driver.log_action("ALERT", {**context, "reason": "Consensus reached; automated remediation disabled"})
        else:
            # With quorum + CRITICAL score, remediate only the matching event type.
            # Process killing is gated and excludes protected PIDs in the driver.
            pid = details.get("pid")
            file_path = details.get("file_path") or details.get("filename") or details.get("target_file")
            if event_type in {"process_linux", "process_windows"} and pid is not None:
                action = "KILL_PROCESS"
                result = self.driver.kill_process(int(pid))
            elif event_type == "file" and file_path:
                action = "QUARANTINE_FILE"
                result = self.driver.quarantine_file(str(file_path))
            elif score >= 0.95 and _enabled("AEGIS_AUTO_ISOLATE_HOST"):
                action = "ISOLATE_HOST"
                result = self.driver.isolate_host()
            else:
                action = "ALERT"
                result = self.driver.log_action("ALERT", {**context, "reason": "No safe, supported target for automated remediation"})

        output = {"action": action, "score": score, "severity": severity,
                  "consensus_reached": consensus, "quorum_status": quorum,
                  "result": result}
        log.info("[ResponsePolicy] vote=%s score=%.3f severity=%s consensus=%s quorum=%s action=%s status=%s",
                 vote_id, score, severity, consensus, quorum, action, result.get("status"))
        return output
