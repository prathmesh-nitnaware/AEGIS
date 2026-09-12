"""
backend/db/repository.py
========================
AEGIS — Async CRUD helpers for every DB table.

All functions accept an AsyncSession and are designed to be called inside
`async with get_session() as session:` blocks from FastAPI endpoints or
background tasks.

Each helper is a standalone coroutine — no class needed. Import what you
need:

    from backend.db.repository import (
        persist_telemetry_event,
        persist_consensus_verdict,
        persist_silence_alarm,
        persist_audit_log,
        upsert_agent_trust,
        persist_maintenance_window,
        ...
    )
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert as pg_insert

import sqlalchemy

from backend.db.models import (
    AuditLogEntry,
    AgentTrust,
    ConsensusVerdict,
    MaintenanceWindowRecord,
    ModelDetection,
    RemoteAction,
    SilenceAlarm,
    TelemetryEvent,
)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def _short_id() -> str:
    return str(uuid.uuid4())[:8]


def _is_postgres(session: AsyncSession) -> bool:
    return "postgresql" in str(session.bind.url) if session.bind else False


# ===========================================================================
# TelemetryEvent
# ===========================================================================
async def persist_telemetry_event(
    session: AsyncSession,
    event: Dict[str, Any],
    event_uid: Optional[str] = None,
) -> TelemetryEvent:
    """Persist a raw telemetry event dict and return the ORM row."""
    uid = event_uid or event.get("id") or _short_id()
    row = TelemetryEvent(
        event_uid=uid,
        agent_id=str(event.get("agent_id", event.get("agentId", "unknown"))),
        event_type=str(event.get("event_type", event.get("type", "unknown"))),
        threat_score=float(event.get("threat_score", event.get("score", 0.0))),
        verdict=event.get("verdict"),
        process_name=event.get("process") or event.get("process_name"),
        pid=event.get("pid"),
        payload=event,
        received_at=time.time(),
        event_timestamp=event.get("timestamp"),
    )
    session.add(row)
    await session.flush()
    return row


async def get_recent_telemetry(
    session: AsyncSession,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    min_score: float = 0.0,
    limit: int = 100,
    offset: int = 0,
) -> List[TelemetryEvent]:
    """Paginated query of telemetry events with optional filters."""
    stmt = (
        select(TelemetryEvent)
        .where(TelemetryEvent.threat_score >= min_score)
        .order_by(desc(TelemetryEvent.received_at))
        .limit(limit)
        .offset(offset)
    )
    if agent_id:
        stmt = stmt.where(TelemetryEvent.agent_id == agent_id)
    if event_type:
        stmt = stmt.where(TelemetryEvent.event_type == event_type)
    result = await session.execute(stmt)
    return list(result.scalars().all())


# ===========================================================================
# ModelDetection
# ===========================================================================
async def persist_model_detections(
    session: AsyncSession,
    event_uid: str,
    agent_id: str,
    sub_scores: Dict[str, Any],
) -> None:
    """Persist per-model sub-scores for a given event."""
    for model_name, score_data in sub_scores.items():
        if score_data is None:
            continue
        if isinstance(score_data, dict):
            sub_score = float(score_data.get("score", score_data.get("threat_score", 0.0)))
            predicted_class = score_data.get("predicted_class")
        else:
            sub_score = float(score_data)
            predicted_class = None

        session.add(ModelDetection(
            event_uid=event_uid,
            agent_id=agent_id,
            model_name=model_name,
            sub_score=sub_score,
            predicted_class=predicted_class,
        ))


# ===========================================================================
# ConsensusVerdict
# ===========================================================================
async def persist_consensus_verdict(
    session: AsyncSession,
    verdict: Dict[str, Any],
) -> ConsensusVerdict:
    """Persist a voting verdict dict and return the ORM row."""
    row = ConsensusVerdict(
        vote_id=verdict.get("vote_id") or _short_id(),
        origin_agent_id=verdict.get("origin_agent_id", "unknown"),
        event_type=verdict.get("event_type", "unknown"),
        raw_threat_score=float(verdict.get("raw_threat_score", 0.0)),
        final_weighted_score=float(verdict.get("final_weighted_score", 0.0)),
        severity=verdict.get("severity", "LOW"),
        response_action=verdict.get("response_action", "LOG"),
        consensus_reached=bool(verdict.get("consensus_reached", False)),
        participating_peers=int(verdict.get("participating_peers", 0)),
        total_weight=float(verdict.get("total_weight", 0.0)),
        verdict_timestamp=verdict.get("timestamp", time.time()),
    )
    session.add(row)
    await session.flush()
    return row


async def get_verdicts_history(
    session: AsyncSession,
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> List[ConsensusVerdict]:
    """Paginated history of verdicts with optional filters."""
    stmt = (
        select(ConsensusVerdict)
        .order_by(desc(ConsensusVerdict.verdict_timestamp))
        .limit(limit)
        .offset(offset)
    )
    if severity:
        stmt = stmt.where(ConsensusVerdict.severity == severity)
    if agent_id:
        stmt = stmt.where(ConsensusVerdict.origin_agent_id == agent_id)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def record_admin_feedback(
    session: AsyncSession,
    vote_id: str,
    confirmed: bool,
    confirmed_by: str,
) -> Optional[ConsensusVerdict]:
    """Mark a verdict as confirmed (True=true-positive, False=false-positive)."""
    stmt = (
        update(ConsensusVerdict)
        .where(ConsensusVerdict.vote_id == vote_id)
        .values(admin_confirmed=confirmed, confirmed_by=confirmed_by)
        .returning(ConsensusVerdict)
    )
    try:
        result = await session.execute(stmt)
        row = result.scalar_one_or_none()
    except Exception:
        # SQLite doesn't support RETURNING — fall back to a separate SELECT
        await session.execute(
            update(ConsensusVerdict)
            .where(ConsensusVerdict.vote_id == vote_id)
            .values(admin_confirmed=confirmed, confirmed_by=confirmed_by)
        )
        result2 = await session.execute(
            select(ConsensusVerdict).where(ConsensusVerdict.vote_id == vote_id)
        )
        row = result2.scalar_one_or_none()
    return row


# ===========================================================================
# SilenceAlarm
# ===========================================================================
async def persist_silence_alarm(
    session: AsyncSession,
    alarm: Dict[str, Any],
) -> SilenceAlarm:
    """Persist a silence alarm payload from SilenceDetector."""
    row = SilenceAlarm(
        agent_id=alarm.get("agent_id", "unknown"),
        last_seen=float(alarm.get("last_seen", time.time())),
        silence_duration=float(alarm.get("silence_duration", 0.0)),
        alarm_at=time.time(),
    )
    session.add(row)
    await session.flush()
    return row


async def get_active_silence_alarms(
    session: AsyncSession,
) -> List[SilenceAlarm]:
    """Return all unacknowledged silence alarms."""
    stmt = (
        select(SilenceAlarm)
        .where(SilenceAlarm.acknowledged == False)  # noqa: E712
        .order_by(desc(SilenceAlarm.alarm_at))
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def acknowledge_silence_alarm(
    session: AsyncSession,
    alarm_id: int,
    acknowledged_by: str,
) -> bool:
    """Acknowledge a silence alarm by id."""
    await session.execute(
        update(SilenceAlarm)
        .where(SilenceAlarm.id == alarm_id)
        .values(
            acknowledged=True,
            acknowledged_by=acknowledged_by,
            resolved_at=time.time(),
        )
    )
    return True


# ===========================================================================
# AgentTrust (centralised view)
# ===========================================================================
async def upsert_agent_trust(
    session: AsyncSession,
    agent_id: str,
    trust_score: float,
    was_correct: bool,
) -> AgentTrust:
    """
    Upsert the central agent_trust row.
    Uses PostgreSQL INSERT ... ON CONFLICT when available, falls back to
    SELECT + INSERT/UPDATE for SQLite.
    """
    now = time.time()
    correct_delta = 1 if was_correct else 0

    # Try to get existing row
    result = await session.execute(
        select(AgentTrust).where(AgentTrust.agent_id == agent_id)
    )
    row = result.scalar_one_or_none()

    if row is None:
        row = AgentTrust(
            agent_id=agent_id,
            trust_score=trust_score,
            total_events=1,
            correct_events=correct_delta,
            last_updated=now,
        )
        session.add(row)
    else:
        row.trust_score = trust_score
        row.total_events += 1
        row.correct_events += correct_delta
        row.last_updated = now

    await session.flush()
    return row


async def get_agent_trust(
    session: AsyncSession,
    agent_id: str,
) -> Optional[AgentTrust]:
    result = await session.execute(
        select(AgentTrust).where(AgentTrust.agent_id == agent_id)
    )
    return result.scalar_one_or_none()


async def get_all_agent_trust(session: AsyncSession) -> List[AgentTrust]:
    result = await session.execute(select(AgentTrust))
    return list(result.scalars().all())


# ===========================================================================
# MaintenanceWindow
# ===========================================================================
async def persist_maintenance_window(
    session: AsyncSession,
    window_data: Dict[str, Any],
) -> MaintenanceWindowRecord:
    """Persist a maintenance window record."""
    row = MaintenanceWindowRecord(
        window_id=window_data["window_id"],
        agent_id=window_data["agent_id"],
        start_time=float(window_data["start_time"]),
        end_time=float(window_data["end_time"]),
        approved_by=window_data.get("approved_by", "admin"),
        reason=window_data.get("reason", ""),
        is_active=window_data.get("is_active", True),
    )
    session.add(row)
    await session.flush()
    return row


async def cancel_maintenance_window_db(
    session: AsyncSession,
    window_id: str,
) -> bool:
    """Mark a maintenance window as inactive in DB."""
    await session.execute(
        update(MaintenanceWindowRecord)
        .where(MaintenanceWindowRecord.window_id == window_id)
        .values(is_active=False)
    )
    return True


async def load_active_maintenance_windows(
    session: AsyncSession,
) -> List[MaintenanceWindowRecord]:
    """Load all windows that are still active and not expired (for startup restore)."""
    now = time.time()
    stmt = (
        select(MaintenanceWindowRecord)
        .where(MaintenanceWindowRecord.is_active == True)  # noqa: E712
        .where(MaintenanceWindowRecord.end_time > now)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


# ===========================================================================
# AuditLog
# ===========================================================================
async def persist_audit_log(
    session: AsyncSession,
    agent_id: str,
    action: str,
    status: str,
    details: Optional[Dict[str, Any]] = None,
    vote_id: Optional[str] = None,
    target_pid: Optional[int] = None,
    target_file: Optional[str] = None,
) -> AuditLogEntry:
    """Persist a response action audit record."""
    row = AuditLogEntry(
        agent_id=agent_id,
        action=action,
        vote_id=vote_id,
        target_pid=target_pid,
        target_file=target_file,
        status=status,
        details=details,
    )
    session.add(row)
    await session.flush()
    return row


async def get_audit_log(
    session: AsyncSession,
    agent_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[AuditLogEntry]:
    """Query audit log with optional filters."""
    stmt = (
        select(AuditLogEntry)
        .order_by(desc(AuditLogEntry.executed_at))
        .limit(limit)
        .offset(offset)
    )
    if agent_id:
        stmt = stmt.where(AuditLogEntry.agent_id == agent_id)
    if action:
        stmt = stmt.where(AuditLogEntry.action == action)
    result = await session.execute(stmt)
    return list(result.scalars().all())


# ===========================================================================
# RemoteAction (Autonomous Remote Command Dispatcher)
# ===========================================================================
async def enqueue_remote_action(
    session: AsyncSession,
    agent_id: str,
    action_type: str,
    vote_id: Optional[str] = None,
    target_pid: Optional[int] = None,
    target_file: Optional[str] = None,
    command_node_ip: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    action_id: Optional[str] = None,
) -> RemoteAction:
    """Enqueue a remote command to be executed by an endpoint agent."""
    aid = action_id or f"act_{uuid.uuid4().hex[:12]}"
    row = RemoteAction(
        action_id=aid,
        agent_id=agent_id,
        action_type=action_type,
        vote_id=vote_id,
        target_pid=target_pid,
        target_file=target_file,
        command_node_ip=command_node_ip,
        parameters=parameters,
        status="PENDING",
        created_at=time.time(),
    )
    session.add(row)
    await session.flush()
    return row


async def get_pending_actions_for_agent(
    session: AsyncSession,
    agent_id: str,
    statuses: Optional[List[str]] = None,
    limit: int = 50,
) -> List[RemoteAction]:
    """Retrieve actionable commands pending execution for an agent."""
    if statuses is None:
        statuses = ["PENDING", "DISPATCHED"]
    stmt = (
        select(RemoteAction)
        .where(RemoteAction.agent_id == agent_id)
        .where(RemoteAction.status.in_(statuses))
        .order_by(RemoteAction.created_at.asc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def mark_actions_dispatched(
    session: AsyncSession,
    action_ids: List[str],
) -> int:
    """Mark actions as DISPATCHED with current timestamp."""
    if not action_ids:
        return 0
    now = time.time()
    stmt = (
        update(RemoteAction)
        .where(RemoteAction.action_id.in_(action_ids))
        .where(RemoteAction.status == "PENDING")
        .values(status="DISPATCHED", dispatched_at=now)
    )
    result = await session.execute(stmt)
    return result.rowcount


async def ack_action_execution(
    session: AsyncSession,
    action_id: str,
    status: str,
    result_details: Optional[Dict[str, Any]] = None,
) -> Optional[RemoteAction]:
    """
    Acknowledge execution of an action from an agent node.
    Updates status and writes to the centralized audit_log table.
    """
    stmt = select(RemoteAction).where(RemoteAction.action_id == action_id)
    result = await session.execute(stmt)
    action_row = result.scalar_one_or_none()
    if not action_row:
        return None

    now = time.time()
    action_row.status = status
    action_row.result_details = result_details
    action_row.executed_at = now

    # Also automatically record to AuditLogEntry in NeonDB
    audit_row = AuditLogEntry(
        agent_id=action_row.agent_id,
        action=action_row.action_type,
        vote_id=action_row.vote_id,
        target_pid=action_row.target_pid,
        target_file=action_row.target_file,
        status=status.lower(),
        details=result_details or {},
        executed_at=now,
    )
    session.add(audit_row)
    await session.flush()
    return action_row


async def get_all_remote_actions(
    session: AsyncSession,
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[RemoteAction]:
    """Query remote actions with optional filtering."""
    stmt = (
        select(RemoteAction)
        .order_by(desc(RemoteAction.created_at))
        .limit(limit)
        .offset(offset)
    )
    if agent_id:
        stmt = stmt.where(RemoteAction.agent_id == agent_id)
    if status:
        stmt = stmt.where(RemoteAction.status == status)
    result = await session.execute(stmt)
    return list(result.scalars().all())
