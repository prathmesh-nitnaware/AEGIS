"""
agent/collectors/collector_health.py
====================================
AEGIS - Collector Health & Observability Tracker
------------------------------------------------
Provides structured telemetry health metrics for all AEGIS endpoint collectors:
- Linux Syscall Collector (strace/eBPF)
- Windows API / Sysmon Collector
- CICIDS Network Flow Collector
- EMBER PE File Collector
- HDFS Log Line Collector
- Zero-Day Event Collector
- Linux eBPF / Windows ETW Kernel Collectors

Ensures that security-relevant failures are never silently swallowed and
distinguishes IDLE (no events observed) from FAILED / DEGRADED states.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional

logger = logging.getLogger(__name__)

CollectorStatusType = Literal["HEALTHY", "DEGRADED", "FAILED", "IDLE"]


@dataclass
class CollectorHealth:
    collector: str
    status: CollectorStatusType = "IDLE"
    events_processed: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    last_error_timestamp: Optional[float] = None
    last_success_timestamp: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CollectorHealthRegistry:
    """Thread-safe central registry tracking health metrics for all active collectors."""

    def __init__(self) -> None:
        self._collectors: Dict[str, CollectorHealth] = {}
        self._lock = threading.Lock()

    def register(self, collector_name: str, details: Optional[Dict[str, Any]] = None) -> CollectorHealth:
        """Register a new collector into tracking."""
        with self._lock:
            if collector_name not in self._collectors:
                self._collectors[collector_name] = CollectorHealth(
                    collector=collector_name,
                    status="IDLE",
                    details=details or {},
                )
            return self._collectors[collector_name]

    def record_success(self, collector_name: str, count: int = 1) -> None:
        """Record successful event batch ingestion."""
        with self._lock:
            ch = self._collectors.setdefault(collector_name, CollectorHealth(collector=collector_name))
            ch.events_processed += count
            ch.last_success_timestamp = time.time()
            # If previously idle, transition to healthy
            if ch.status in ("IDLE", "DEGRADED"):
                ch.status = "HEALTHY"

    def record_error(self, collector_name: str, error_msg: str, fatal: bool = False) -> None:
        """Record a collector exception or degradation."""
        with self._lock:
            ch = self._collectors.setdefault(collector_name, CollectorHealth(collector=collector_name))
            ch.error_count += 1
            ch.last_error = error_msg
            ch.last_error_timestamp = time.time()
            ch.status = "FAILED" if fatal else "DEGRADED"
            logger.warning("[CollectorHealth] Collector '%s' entered %s state: %s", collector_name, ch.status, error_msg)

    def get_status(self, collector_name: str) -> Optional[Dict[str, Any]]:
        """Get snapshot of a specific collector."""
        with self._lock:
            ch = self._collectors.get(collector_name)
            return ch.to_dict() if ch else None

    def get_all_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Return health snapshots of all registered collectors."""
        with self._lock:
            return {name: ch.to_dict() for name, ch in self._collectors.items()}

    def reset(self) -> None:
        """Reset all tracked health metrics (for tests)."""
        with self._lock:
            self._collectors.clear()


# Global Singleton Registry
collector_registry = CollectorHealthRegistry()
