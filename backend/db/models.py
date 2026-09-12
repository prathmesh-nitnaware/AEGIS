"""
backend/db/models.py
=====================
AEGIS — SQLAlchemy ORM table definitions.

All tables are created by `init_db()` via Base.metadata.create_all().
Compatible with both PostgreSQL (NeonDB) and SQLite (aiosqlite fallback).

Tables
------
TelemetryEvent      — every raw event from every agent
ModelDetection      — per-model sub-scores attached to a TelemetryEvent
ConsensusVerdict    — centralized or P2P voting outcomes + response actions
SilenceAlarm        — when an agent went silent (missed heartbeat threshold)
AgentTrust          — EMA trust score per agent (mirrors AgentTrustTracker)
MaintenanceWindow   — pre-announced maintenance windows (previously in-memory)
AuditLog            — every response action executed by AgentResponseDriver
"""
from __future__ import annotations

import time
from typing import Optional

from sqlalchemy import (
    Boolean,
    Float,
    Integer,
    String,
    Text,
    JSON,
    BigInteger,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.database import Base


# ---------------------------------------------------------------------------
# Helper: current unix timestamp as float (works on both Pg and SQLite)
# ---------------------------------------------------------------------------
def _now() -> float:
    return time.time()


# ===========================================================================
# 1. TelemetryEvent
# ===========================================================================
class TelemetryEvent(Base):
    """
    Every raw telemetry event posted by any agent via POST /api/telemetry.
    Replaces the in-memory `events` deque in telemetry_service.py.
    """
    __tablename__ = "telemetry_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_uid: Mapped[str] = mapped_column(String(16), index=True)       # short uuid
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    verdict: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # LOW/MEDIUM/HIGH/CRITICAL
    process_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True) # full raw event dict
    received_at: Mapped[float] = mapped_column(Float, default=_now, index=True)
    event_timestamp: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


# ===========================================================================
# 2. ModelDetection
# ===========================================================================
class ModelDetection(Base):
    """
    Individual ML model sub-scores for a given TelemetryEvent.
    One row per (event_uid, model_name).
    """
    __tablename__ = "model_detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_uid: Mapped[str] = mapped_column(String(16), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    model_name: Mapped[str] = mapped_column(String(64))       # linux, cicids, ember, etc.
    sub_score: Mapped[float] = mapped_column(Float)
    predicted_class: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    recorded_at: Mapped[float] = mapped_column(Float, default=_now)


# ===========================================================================
# 3. ConsensusVerdict
# ===========================================================================
class ConsensusVerdict(Base):
    """
    Every voting outcome from CentralizedVotingCoordinator or P2P mesh.
    Replaces the in-memory `_verdicts_history` list in command_node.py.
    """
    __tablename__ = "consensus_verdicts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vote_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    origin_agent_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64))
    raw_threat_score: Mapped[float] = mapped_column(Float)
    final_weighted_score: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(16), index=True)        # LOW/MEDIUM/HIGH/CRITICAL
    response_action: Mapped[str] = mapped_column(String(32))             # LOG/ALERT/KILL_PROCESS/ISOLATE_HOST
    consensus_reached: Mapped[bool] = mapped_column(Boolean, default=False)
    participating_peers: Mapped[int] = mapped_column(Integer, default=0)
    total_weight: Mapped[float] = mapped_column(Float, default=0.0)
    # Admin feedback
    admin_confirmed: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)  # None=pending, True=TP, False=FP
    confirmed_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    verdict_timestamp: Mapped[float] = mapped_column(Float, default=_now, index=True)


# ===========================================================================
# 4. SilenceAlarm
# ===========================================================================
class SilenceAlarm(Base):
    """
    Persisted record every time SilenceDetector fires for a gone-dark agent.
    Previously these were only broadcast via WebSocket and then lost.
    """
    __tablename__ = "silence_alarms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    last_seen: Mapped[float] = mapped_column(Float)        # epoch of last heartbeat
    silence_duration: Mapped[float] = mapped_column(Float) # seconds since last heartbeat
    alarm_at: Mapped[float] = mapped_column(Float, default=_now, index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    resolved_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


# ===========================================================================
# 5. AgentTrust
# ===========================================================================
class AgentTrust(Base):
    """
    Central replica of the per-agent EMA trust score.
    AgentTrustTracker in confidence_engine.py writes to local SQLite per agent;
    this table is the Command Node's centralised view, updated via
    POST /api/trust/feedback.
    """
    __tablename__ = "agent_trust"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    trust_score: Mapped[float] = mapped_column(Float, default=0.5)
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    correct_events: Mapped[int] = mapped_column(Integer, default=0)
    last_updated: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


# ===========================================================================
# 6. MaintenanceWindow
# ===========================================================================
class MaintenanceWindowRecord(Base):
    """
    Persistent record for MaintenanceWindowPortal windows.
    Previously lived only in the in-memory dict; now survives server restarts.
    """
    __tablename__ = "maintenance_windows"

    window_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    start_time: Mapped[float] = mapped_column(Float, index=True)
    end_time: Mapped[float] = mapped_column(Float, index=True)
    approved_by: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[float] = mapped_column(Float, default=_now)


# ===========================================================================
# 7. AuditLog
# ===========================================================================
class AuditLogEntry(Base):
    """
    Centralised copy of every response action executed by AgentResponseDriver.
    Local agents also write to aegis_audit.log (file); this mirrors that to DB
    so the Command Node can query all actions across all agents.
    """
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(32), index=True)          # KILL_PROCESS / QUARANTINE_FILE / etc.
    vote_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, index=True)
    target_pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    target_file: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32))                      # success / failed / simulated_success
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    executed_at: Mapped[float] = mapped_column(Float, default=_now, index=True)


# ===========================================================================
# 8. RemoteAction (Autonomous Remote Command Dispatcher)
# ===========================================================================
class RemoteAction(Base):
    """
    Queue of automated containment and mitigation commands dispatched by the
    Command Node to specific endpoint agents following consensus verdicts.

    Lifecycle:
      PENDING -> DISPATCHED -> EXECUTING -> SUCCESS / SIMULATED_SUCCESS / FAILED
    """
    __tablename__ = "pending_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    action_type: Mapped[str] = mapped_column(String(32), index=True)        # KILL_PROCESS, ISOLATE_HOST, etc.
    vote_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, index=True)
    target_pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    target_file: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    command_node_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    parameters: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True)
    result_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, default=_now, index=True)
    dispatched_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    executed_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
