"""
agent/admin_trust.py
====================
AEGIS - Phase 4 Admin Trust System & Maintenance Window Portal
--------------------------------------------------------------
Provides identity context validation, administrative behavioral pattern analysis,
and pre-announced maintenance window suppression to eliminate false positive
alarms during legitimate administrative operations.

Architecture:
* **IdentityContext**: Encapsulates user identity (SID/username), operating hours,
  workstation context, and admin privilege status.
* **MaintenanceWindowPortal**: Manages scheduled maintenance windows. When an agent
  is within an active, approved maintenance window, threat alerts are suppressed
  or marked as MAINTENANCE_SUPPRESSED to prevent false positive incident response.
* **AdminTrustEngine**: Combines identity context and maintenance window checks to
  determine whether a high threat score should be suppressed or downgraded.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)


# ===========================================================================
# Dataclasses & Schemas
# ===========================================================================
@dataclass
class IdentityContext:
    """
    Identity and context metadata for an event actor.
    """
    user_id: str
    username: str
    is_admin: bool = False
    workstation_id: str = "local-node"
    operating_hours: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MaintenanceWindow:
    """
    Pre-announced maintenance window record.
    """
    window_id: str
    agent_id: str
    start_time: float
    end_time: float
    approved_by: str
    reason: str
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ===========================================================================
# MaintenanceWindowPortal
# ===========================================================================
class MaintenanceWindowPortal:
    """
    Thread-safe portal managing pre-announced maintenance windows across agents.
    """

    def __init__(self) -> None:
        self._windows: Dict[str, MaintenanceWindow] = {}
        self._lock = threading.Lock()

    def schedule_window(
        self,
        agent_id: str,
        duration_seconds: float,
        approved_by: str,
        reason: str,
        start_delay_seconds: float = 0.0,
    ) -> MaintenanceWindow:
        """Schedule a new pre-announced maintenance window."""
        now = time.time()
        start_t = now + start_delay_seconds
        end_t = start_t + duration_seconds
        window_id = str(uuid.uuid4())[:8]

        win = MaintenanceWindow(
            window_id=window_id,
            agent_id=agent_id,
            start_time=start_t,
            end_time=end_t,
            approved_by=approved_by,
            reason=reason,
            is_active=True,
        )

        with self._lock:
            self._windows[window_id] = win

        logger.info(
            "[MaintenancePortal] Scheduled window %s for agent '%s' (duration=%.0fs, approved_by='%s')",
            window_id, agent_id, duration_seconds, approved_by,
        )
        return win

    def cancel_window(self, window_id: str) -> bool:
        """Cancel an active maintenance window."""
        with self._lock:
            win = self._windows.get(window_id)
            if win:
                win.is_active = False
                logger.info("[MaintenancePortal] Cancelled window %s", window_id)
                return True
            return False

    def is_in_maintenance(self, agent_id: str, timestamp: Optional[float] = None) -> Tuple[bool, Optional[MaintenanceWindow]]:
        """
        Check if an agent is currently in an active maintenance window.
        """
        t = timestamp or time.time()
        with self._lock:
            for win in self._windows.values():
                if not win.is_active:
                    continue
                if win.agent_id in (agent_id, "*", "all"):
                    if win.start_time <= t <= win.end_time:
                        return True, win

        return False, None

    def list_windows(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """List all recorded maintenance windows."""
        now = time.time()
        with self._lock:
            results = []
            for win in self._windows.values():
                if active_only and (not win.is_active or win.end_time < now):
                    continue
                results.append(win.to_dict())
            return results


# ===========================================================================
# AdminTrustEngine
# ===========================================================================
class AdminTrustEngine:
    """
    Evaluates events against identity context, administrative patterns, and active
    maintenance windows to determine suppression or score adjustments.
    """

    # Legitimate admin tool patterns (e.g. windows update, ansible, powershell management)
    KNOWN_ADMIN_PROCESSES = {
        "msiexec.exe",
        "wuauclt.exe",
        "tiworker.exe",
        "ansible-playbook",
        "puppet",
        "chef-client",
        "dism.exe",
    }

    def __init__(self, portal: Optional[MaintenanceWindowPortal] = None) -> None:
        self.portal = portal or MaintenanceWindowPortal()

    def evaluate_event(
        self,
        agent_id: str,
        event_type: str,
        raw_threat_score: float,
        identity: Optional[IdentityContext] = None,
        process_name: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> Tuple[bool, float, str]:
        """
        Evaluate an event for potential administrative suppression or score adjustment.

        Returns
        -------
        (is_suppressed, adjusted_threat_score, rationale)
        """
        t = timestamp or time.time()

        # 1. Maintenance Window Check
        in_maint, win = self.portal.is_in_maintenance(agent_id, timestamp=t)
        if in_maint and win:
            logger.info(
                "[AdminTrust] Suppressing threat (raw=%.2f) on '%s': Active maintenance window %s ('%s')",
                raw_threat_score, agent_id, win.window_id, win.reason,
            )
            return True, 0.0, f"Suppressed by maintenance window {win.window_id} ({win.reason})"

        # 2. Admin Process & Identity Check
        if identity and identity.is_admin:
            if process_name and process_name.lower() in self.KNOWN_ADMIN_PROCESSES:
                adjusted_score = max(0.0, raw_threat_score * 0.2)
                logger.info(
                    "[AdminTrust] Downgrading threat (%.2f -> %.2f) for admin process '%s'",
                    raw_threat_score, adjusted_score, process_name,
                )
                return True, adjusted_score, f"Downgraded: Approved admin tool '{process_name}' by admin user '{identity.username}'"

        return False, raw_threat_score, "No administrative suppression applied"


# ===========================================================================
# Runnable Demo
# ===========================================================================
if __name__ == "__main__":
    print("=" * 72)
    print("AEGIS Phase 4 — Admin Trust System & Maintenance Window Demo")
    print("=" * 72)

    portal = MaintenanceWindowPortal()
    engine = AdminTrustEngine(portal=portal)

    # 1. Schedule a maintenance window for vm1
    win = portal.schedule_window(
        agent_id="vm1",
        duration_seconds=300.0,
        approved_by="admin_sec",
        reason="Scheduled OS Security Patching",
    )

    # 2. Evaluate high threat event during maintenance window
    is_supp, score, reason = engine.evaluate_event(
        agent_id="vm1",
        event_type="process_windows",
        raw_threat_score=0.88,
        process_name="msiexec.exe",
    )

    print(f"\n[Demo] Evaluation Result during Maintenance:")
    print(f"  Is Suppressed    : {is_supp}")
    print(f"  Adjusted Score   : {score}")
    print(f"  Rationale        : {reason}")

    # 3. Evaluate event on non-maintenance agent (vm2) with Admin Identity
    admin_id = IdentityContext(user_id="S-1-5-32-544", username="Admin", is_admin=True)
    is_supp2, score2, reason2 = engine.evaluate_event(
        agent_id="vm2",
        event_type="process_windows",
        raw_threat_score=0.75,
        identity=admin_id,
        process_name="dism.exe",
    )

    print(f"\n[Demo] Evaluation Result for Admin Tool (dism.exe):")
    print(f"  Is Suppressed    : {is_supp2}")
    print(f"  Adjusted Score   : {score2}")
    print(f"  Rationale        : {reason2}")

    print("=" * 72)
