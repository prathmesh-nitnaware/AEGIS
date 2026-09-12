import asyncio
import time
import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# AEGIS TELEMETRY API
# ============================================================

from contextlib import asynccontextmanager

import platform

from backend.services.telemetry_service import add_event, add_model_result
from backend.api.telemetry import router as telemetry_router
from backend.command_node import CentralizedTelemetryRepository, CentralizedVotingCoordinator
from agent.admin_trust import AdminTrustEngine, MaintenanceWindowPortal
from agent.heartbeat import SilenceDetector
from backend.db.database import get_session, init_db
from backend.db.repository import (
    persist_telemetry_event,
    persist_consensus_verdict,
    persist_silence_alarm,
    persist_maintenance_window,
    cancel_maintenance_window_db,
    load_active_maintenance_windows,
    upsert_agent_trust,
    get_agent_trust,
    get_all_agent_trust,
    get_verdicts_history,
    get_recent_telemetry,
    record_admin_feedback,
    get_audit_log,
    get_active_silence_alarms,
    enqueue_remote_action,
    get_pending_actions_for_agent,
    mark_actions_dispatched,
    ack_action_execution,
    get_all_remote_actions,
)
from agent.confidence_engine import AgentTrustTracker

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s")

SERVER_START_TIME = time.time()

# ============================================================
# CENTRALIZED COMMAND NODE & REPOSITORY
# ============================================================
central_repo = CentralizedTelemetryRepository()
central_coordinator = CentralizedVotingCoordinator(repository=central_repo)
maintenance_portal = MaintenanceWindowPortal()
admin_trust_engine = AdminTrustEngine(portal=maintenance_portal)

# Local SQLite trust tracker (per-agent, used by voting coordinator)
local_trust_tracker = AgentTrustTracker(db_path="aegis_central_trust.db")

# ============================================================
# HEARTBEAT / SILENT-ALARM SUBSYSTEM
# ============================================================
def _on_silent_alarm(alarm_payload: dict):
    """
    Called from SilenceDetector's background thread when an agent goes silent.
    - Publishes the alarm over WebSocket to connected dashboards
    - Persists the alarm to NeonDB (fire-and-forget via asyncio)
    """
    publish_event({**alarm_payload, "type": "agent_alarm"})
    # Persist to DB — schedule on the event loop
    if api_loop is not None:
        asyncio.run_coroutine_threadsafe(_persist_alarm_bg(alarm_payload), api_loop)


async def _persist_alarm_bg(alarm_payload: dict) -> None:
    """Background coroutine: persist silence alarm to NeonDB."""
    try:
        async with get_session() as session:
            await persist_silence_alarm(session, alarm_payload)
            logger.info("[AEGIS DB] Silence alarm persisted for agent=%s", alarm_payload.get("agent_id"))
    except Exception as exc:
        logger.warning("[AEGIS DB] Failed to persist silence alarm: %s", exc)


silence_detector = SilenceDetector(
    silence_threshold=15.0,   # AEGIS spec default — no heartbeat for 15s → alarm
    check_interval=2.0,
    on_silent_alarm=_on_silent_alarm,
)


# ============================================================
# LIFESPAN — DB INIT + MAINTENANCE RESTORE
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global api_loop
    api_loop = asyncio.get_running_loop()

    # 1. Create all tables in NeonDB (idempotent — safe to run every start)
    await init_db()
    logger.info("[AEGIS API] NeonDB tables initialised")

    # 2. Restore active maintenance windows from DB so a server restart
    #    doesn't drop active suppression windows and cause false alarms.
    try:
        async with get_session() as session:
            active_windows = await load_active_maintenance_windows(session)
            for w in active_windows:
                from agent.admin_trust import MaintenanceWindow
                win_obj = MaintenanceWindow(
                    window_id=w.window_id,
                    agent_id=w.agent_id,
                    start_time=w.start_time,
                    end_time=w.end_time,
                    approved_by=w.approved_by,
                    reason=w.reason,
                    is_active=w.is_active,
                )
                with maintenance_portal._lock:
                    maintenance_portal._windows[w.window_id] = win_obj
            if active_windows:
                logger.info("[AEGIS API] Restored %d active maintenance window(s) from DB", len(active_windows))
    except Exception as exc:
        logger.warning("[AEGIS API] Could not restore maintenance windows: %s", exc)

    # 3. Start silence detector
    silence_detector.start()
    logger.info("[AEGIS API] Telemetry API started")
    logger.info("[AEGIS API] WebSocket: /ws/telemetry")
    logger.info("[AEGIS API] Heartbeat ingestion: POST /api/heartbeat")
    yield

    silence_detector.stop()


app = FastAPI(
    title="AEGIS Telemetry API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(telemetry_router)


# ============================================================
# GLOBAL STATE
# ============================================================

clients: set[WebSocket] = set()
api_loop: asyncio.AbstractEventLoop | None = None

latest_event = {
    "timestamp": 0,
    "pid": 0,
    "uid": 0,
    "process": "unknown",
    "syscall": 0,
    "window_size": 0,
    "predicted_class": "Normal",
    "normal_probability": 1.0,
    "threat_score": 0.0,
    "probabilities": {},
}


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():
    return {
        "service": "AEGIS Telemetry API",
        "version": "2.0.0",
        "status": "online",
        "platform": platform.system(),
        "websocket": "/ws/telemetry",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
async def health():
    uptime = time.time() - SERVER_START_TIME
    return {
        "status": "healthy",
        "platform": platform.system(),
        "connected_clients": len(clients),
        "uptime": round(uptime, 1),
        "server_start_time": SERVER_START_TIME,
        "timestamp": time.time(),
    }


# ============================================================
# LATEST TELEMETRY
# ============================================================

@app.get("/api/telemetry/latest")
async def get_latest():
    return latest_event


# ============================================================
# WEBSOCKET
# ============================================================

@app.websocket("/ws/telemetry")
async def telemetry_socket(websocket: WebSocket):

    await websocket.accept()
    clients.add(websocket)
    logger.info("[AEGIS API] Dashboard connected (clients=%d)", len(clients))

    try:
        # Immediately send latest known event
        await websocket.send_json(latest_event)

        # Keep connection alive
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "heartbeat", "timestamp": time.time()})

    except WebSocketDisconnect:
        clients.discard(websocket)
        logger.info("[AEGIS API] Dashboard disconnected (clients=%d)", len(clients))

    except Exception as exc:
        clients.discard(websocket)
        logger.warning("[AEGIS API] WebSocket error: %s", exc)


# ============================================================
# UPDATE LATEST EVENT
# ============================================================

def update_latest(event: dict):
    global latest_event
    latest_event = event


# ============================================================
# BROADCAST EVENT
# ============================================================

async def broadcast(event: dict):
    """Broadcast a telemetry event to every connected dashboard."""
    update_latest(event)

    if not clients:
        return

    dead_clients = set()

    for client in clients:
        try:
            await client.send_json(event)
        except Exception:
            dead_clients.add(client)

    for client in dead_clients:
        clients.discard(client)


# ============================================================
# THREAD-SAFE EVENT PUBLISHER
# ============================================================

def publish_event(event: dict):
    """
    Called by telemetry collectors running outside the asyncio event loop.
    Safely schedules broadcast on the FastAPI event loop.
    """
    update_latest(event)

    if api_loop is None:
        logger.warning("[AEGIS API] WARNING: API event loop is not ready")
        return

    try:
        asyncio.run_coroutine_threadsafe(broadcast(event), api_loop)
    except Exception as exc:
        logger.warning("[AEGIS API] Failed to publish event: %s", exc)


# ============================================================
# TELEMETRY INGESTION  (NOW WITH DB PERSISTENCE)
# ============================================================

@app.post("/api/telemetry")
async def post_telemetry(event: dict):
    """
    Primary ingestion endpoint. Persists every event to NeonDB,
    updates the in-memory service, and broadcasts to dashboards.
    """
    # Legacy in-memory service (keeps existing /api/telemetry/* routes working)
    add_event(event)
    central_repo.add_telemetry(event)
    if "threat_score" in event or "score" in event:
        add_model_result(event)

    # ── NeonDB persistence ──
    try:
        async with get_session() as session:
            await persist_telemetry_event(session, event)
    except Exception as exc:
        logger.warning("[AEGIS DB] Failed to persist telemetry event: %s", exc)

    await broadcast(event)
    return {"status": "published", "event": event}


@app.post("/api/telemetry/test")
async def test_telemetry():
    """Sends a fake telemetry event for dashboard connection testing."""
    event = {
        "timestamp": int(time.time() * 1000000),
        "pid": 2929,
        "uid": 1000,
        "process": "antigravity-ide",
        "syscall": 257,
        "window_size": 500,
        "predicted_class": "Normal",
        "normal_probability": 0.804637,
        "threat_score": 0.195363,
        "probabilities": {
            "Normal": 0.804637,
            "Hydra_SSH": 0.047496,
            "Hydra_FTP": 0.079507,
            "Web_Shell": 0.040864,
            "Meterpreter": 0.009346,
            "Adduser": 0.025446,
            "Java_Meterpreter": 0.027455,
        },
    }
    await broadcast(event)
    return {"status": "sent", "event": event}


# ============================================================
# HEARTBEAT INGESTION
# ============================================================

@app.post("/api/heartbeat")
async def post_heartbeat(payload: dict):
    silence_detector.record_heartbeat(payload)
    await broadcast({**payload, "type": "agent_heartbeat"})
    return {"status": "ok", "agent_id": payload.get("agent_id")}


@app.post("/api/heartbeat/shutdown")
async def post_heartbeat_shutdown(payload: dict):
    """
    Emergency Last-Gasp / Goodbye beacon sent during user-initiated OS shutdown or service stop.
    Suppresses the silence detector alarm and marks the agent gracefully offline.
    """
    agent_id = payload.get("agent_id", "unknown")
    reason = payload.get("reason", "user_initiated_shutdown")
    silence_detector.record_shutdown(agent_id, reason)

    # Persist in audit log
    try:
        from backend.db.repository import log_action
        async with get_session() as session:
            await log_action(
                session,
                agent_id=agent_id,
                action="GRACEFUL_SHUTDOWN",
                status="SUCCESS",
                details={"reason": reason, "timestamp": time.time()},
            )
    except Exception as exc:
        logger.warning("[AEGIS DB] Could not log graceful shutdown audit entry: %s", exc)

    # Broadcast to dashboard
    await broadcast({
        "type": "agent_shutdown",
        "agent_id": agent_id,
        "status": "OFFLINE_GRACEFUL",
        "reason": reason,
        "timestamp": time.time(),
    })
    return {"status": "shutdown_recorded", "agent_id": agent_id, "silence_alarm": "suppressed"}


@app.get("/api/agents")
async def get_agents():
    """Full snapshot of every tracked agent's heartbeat state."""
    return {"agents": silence_detector.list_agents()}


@app.get("/api/agents/{agent_id}/trust")
async def get_agent_trust_endpoint(agent_id: str):
    """Return the centralised trust score for a specific agent."""
    # First try central NeonDB view
    try:
        async with get_session() as session:
            row = await get_agent_trust(session, agent_id)
            if row:
                return {
                    "agent_id": agent_id,
                    "trust_score": row.trust_score,
                    "total_events": row.total_events,
                    "correct_events": row.correct_events,
                    "last_updated": row.last_updated,
                    "source": "neondb",
                }
    except Exception as exc:
        logger.warning("[AEGIS DB] Could not fetch trust from DB: %s", exc)

    # Fallback to local SQLite tracker
    local_score = local_trust_tracker.get_trust(agent_id)
    return {
        "agent_id": agent_id,
        "trust_score": local_score,
        "source": "local_sqlite",
    }


@app.get("/api/agents/trust/all")
async def get_all_agents_trust():
    """Return centralised trust scores for all known agents."""
    try:
        async with get_session() as session:
            rows = await get_all_agent_trust(session)
            return {
                "agents": [
                    {
                        "agent_id": r.agent_id,
                        "trust_score": r.trust_score,
                        "total_events": r.total_events,
                        "correct_events": r.correct_events,
                        "last_updated": r.last_updated,
                    }
                    for r in rows
                ]
            }
    except Exception as exc:
        logger.warning("[AEGIS DB] Could not fetch all trust scores: %s", exc)
        return {"agents": [], "error": str(exc)}


# ============================================================
# P2P CONSENSUS VOTING
# ============================================================

@app.post("/api/p2p/consensus")
async def post_p2p_consensus(verdict: dict):
    """
    Endpoint for P2PMeshNode to submit calculated consensus verdicts.
    Persists to DB and broadcasts to dashboards.
    """
    try:
        async with get_session() as session:
            await persist_consensus_verdict(session, verdict)
    except Exception as exc:
        logger.warning("[AEGIS DB] Failed to persist P2P consensus: %s", exc)

    event = {**verdict, "type": "p2p_consensus"}
    await broadcast(event)
    return {"status": "published", "vote_id": verdict.get("vote_id")}


@app.post("/api/p2p/vote")
async def post_p2p_vote(payload: dict):
    """HTTP REST fallback for peer consensus voting."""
    event = {**payload, "type": "p2p_vote_event"}
    await broadcast(event)
    return {"status": "received", "vote_id": payload.get("vote_id")}


# ============================================================
# CENTRALIZED COMMAND NODE ENDPOINTS
# ============================================================

@app.get("/api/centralized/telemetry")
async def get_centralized_telemetry(
    agent_id: str | None = None,
    event_type: str | None = None,
    min_score: float = 0.0,
    limit: int = 100,
    offset: int = 0,
):
    """
    Query telemetry from NeonDB (persistent, paginated) with optional filters.
    Falls back to in-memory repo if DB is unavailable.
    """
    try:
        async with get_session() as session:
            rows = await get_recent_telemetry(
                session,
                agent_id=agent_id,
                event_type=event_type,
                min_score=min_score,
                limit=limit,
                offset=offset,
            )
            return {
                "telemetries": [
                    {
                        "id": r.event_uid,
                        "agent_id": r.agent_id,
                        "event_type": r.event_type,
                        "threat_score": r.threat_score,
                        "verdict": r.verdict,
                        "received_at": r.received_at,
                        "payload": r.payload,
                    }
                    for r in rows
                ],
                "count": len(rows),
                "source": "neondb",
            }
    except Exception as exc:
        logger.warning("[AEGIS DB] Falling back to in-memory telemetry: %s", exc)
        telemetries = central_repo.query_telemetry(
            agent_id=agent_id, event_type=event_type, min_score=min_score, limit=limit
        )
        return {"telemetries": telemetries, "count": len(telemetries), "source": "memory"}


@app.get("/api/centralized/stats")
async def get_centralized_stats():
    """Retrieve system-wide aggregated telemetry statistics."""
    return central_repo.get_stats()


@app.post("/api/centralized/vote")
async def post_centralized_vote(payload: dict):
    """
    Centralized Voting Hub. Evaluates vote, persists verdict to NeonDB,
    and broadcasts to dashboards.
    """
    event_type = payload.get("event_type", "unknown")
    origin_agent_id = payload.get("origin_agent_id", payload.get("agent_id", "agent-local"))
    threat_score = float(payload.get("threat_score", payload.get("score", 0.0)))
    confidence = float(payload.get("confidence", 1.0))
    details = payload.get("details", payload)

    verdict = central_coordinator.process_vote_request(
        event_type=event_type,
        origin_agent_id=origin_agent_id,
        threat_score=threat_score,
        confidence=confidence,
        details=details,
    )

    # ── Persist verdict to NeonDB ──
    try:
        async with get_session() as session:
            await persist_consensus_verdict(session, verdict)
    except Exception as exc:
        logger.warning("[AEGIS DB] Failed to persist centralized verdict: %s", exc)

    # ── Autonomous Remote Command Dispatcher: Auto-Enqueue Mitigation Actions ──
    action_dict = None
    response_act = verdict.get("response_action")
    if response_act in ("KILL_PROCESS", "ISOLATE_HOST", "QUARANTINE_FILE", "ALERT"):
        try:
            async with get_session() as session:
                target_pid = details.get("pid") or payload.get("pid")
                target_file = (
                    details.get("target_file")
                    or details.get("filename")
                    or details.get("file_path")
                    or payload.get("target_file")
                )
                action_row = await enqueue_remote_action(
                    session=session,
                    agent_id=origin_agent_id,
                    action_type=response_act,
                    vote_id=verdict.get("vote_id"),
                    target_pid=int(target_pid) if target_pid is not None else None,
                    target_file=str(target_file) if target_file else None,
                    command_node_ip=details.get("command_node_ip", "127.0.0.1"),
                    parameters={"details": details, "severity": verdict.get("severity")},
                )
                action_dict = {
                    "action_id": action_row.action_id,
                    "agent_id": action_row.agent_id,
                    "action_type": action_row.action_type,
                    "vote_id": action_row.vote_id,
                    "target_pid": action_row.target_pid,
                    "target_file": action_row.target_file,
                    "command_node_ip": action_row.command_node_ip,
                    "status": action_row.status,
                    "created_at": action_row.created_at,
                }
                logger.info(
                    "[Dispatcher] Dispatched action %s (%s) to agent %s (vote_id=%s)",
                    action_row.action_id,
                    action_row.action_type,
                    origin_agent_id,
                    verdict.get("vote_id"),
                )
                # Broadcast live action dispatch event
                await broadcast({
                    "type": "remote_action_dispatched",
                    "action": action_dict,
                })
        except Exception as exc:
            logger.warning("[AEGIS DB] Failed to enqueue remote action: %s", exc)

    # Broadcast live to dashboards
    await broadcast({
        **verdict,
        "type": "centralized_consensus_verdict",
        "dispatched_action": action_dict,
    })

    return {"status": "success", "verdict": verdict, "dispatched_action": action_dict}


@app.get("/api/centralized/verdicts")
async def get_centralized_verdicts(
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    agent_id: str | None = None,
):
    """
    Retrieve paginated history of consensus verdicts from NeonDB.
    Falls back to in-memory history if DB is unavailable.
    """
    try:
        async with get_session() as session:
            rows = await get_verdicts_history(
                session,
                limit=limit,
                offset=offset,
                severity=severity,
                agent_id=agent_id,
            )
            return {
                "verdicts": [
                    {
                        "vote_id": r.vote_id,
                        "origin_agent_id": r.origin_agent_id,
                        "event_type": r.event_type,
                        "raw_threat_score": r.raw_threat_score,
                        "final_weighted_score": r.final_weighted_score,
                        "severity": r.severity,
                        "response_action": r.response_action,
                        "consensus_reached": r.consensus_reached,
                        "participating_peers": r.participating_peers,
                        "admin_confirmed": r.admin_confirmed,
                        "confirmed_by": r.confirmed_by,
                        "timestamp": r.verdict_timestamp,
                    }
                    for r in rows
                ],
                "count": len(rows),
                "source": "neondb",
            }
    except Exception as exc:
        logger.warning("[AEGIS DB] Falling back to in-memory verdicts: %s", exc)
        return {
            "verdicts": central_coordinator.get_verdicts(limit=limit),
            "source": "memory",
        }


# ============================================================
# AUTONOMOUS REMOTE COMMAND DISPATCHER ENDPOINTS
# ============================================================

@app.post("/api/actions/enqueue")
async def api_enqueue_action(payload: dict):
    """
    Manually or programmatically enqueue an action for an endpoint agent.
    """
    agent_id = payload.get("agent_id")
    action_type = payload.get("action_type")
    if not agent_id or not action_type:
        raise HTTPException(status_code=400, detail="agent_id and action_type are required")

    try:
        async with get_session() as session:
            action_row = await enqueue_remote_action(
                session=session,
                agent_id=agent_id,
                action_type=action_type,
                vote_id=payload.get("vote_id"),
                target_pid=payload.get("target_pid"),
                target_file=payload.get("target_file"),
                command_node_ip=payload.get("command_node_ip", "127.0.0.1"),
                parameters=payload.get("parameters"),
            )
            action_dict = {
                "action_id": action_row.action_id,
                "agent_id": action_row.agent_id,
                "action_type": action_row.action_type,
                "vote_id": action_row.vote_id,
                "target_pid": action_row.target_pid,
                "target_file": action_row.target_file,
                "command_node_ip": action_row.command_node_ip,
                "parameters": action_row.parameters,
                "status": action_row.status,
                "created_at": action_row.created_at,
            }
            await broadcast({"type": "remote_action_dispatched", "action": action_dict})
            return {"status": "success", "action": action_dict}
    except Exception as exc:
        logger.error("[Dispatcher] Failed to enqueue action: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/agents/{agent_id}/actions/pending")
async def api_get_pending_actions(agent_id: str):
    """
    Polled by endpoint agents to retrieve pending actions dispatched to them.
    Transitions pending actions to 'DISPATCHED'.
    """
    try:
        async with get_session() as session:
            rows = await get_pending_actions_for_agent(session, agent_id=agent_id)
            action_ids = [r.action_id for r in rows if r.status == "PENDING"]
            if action_ids:
                await mark_actions_dispatched(session, action_ids)

            actions = [
                {
                    "action_id": r.action_id,
                    "agent_id": r.agent_id,
                    "action_type": r.action_type,
                    "vote_id": r.vote_id,
                    "target_pid": r.target_pid,
                    "target_file": r.target_file,
                    "command_node_ip": r.command_node_ip,
                    "parameters": r.parameters,
                    "status": "DISPATCHED" if r.action_id in action_ids else r.status,
                    "created_at": r.created_at,
                }
                for r in rows
            ]
            return {"agent_id": agent_id, "actions": actions, "count": len(actions)}
    except Exception as exc:
        logger.error("[Dispatcher] Failed to fetch pending actions for %s: %s", agent_id, exc)
        return {"agent_id": agent_id, "actions": [], "count": 0, "error": str(exc)}


@app.post("/api/agents/{agent_id}/actions/{action_id}/ack")
async def api_ack_action_execution(agent_id: str, action_id: str, payload: dict):
    """
    Acknowledge completion of an action by an endpoint agent.
    Updates the RemoteAction status and records to NeonDB audit_log.
    """
    status = payload.get("status", "SUCCESS").upper()
    result_details = payload.get("result_details", payload.get("details", {}))

    try:
        async with get_session() as session:
            action_row = await ack_action_execution(
                session=session,
                action_id=action_id,
                status=status,
                result_details=result_details,
            )
            if not action_row:
                raise HTTPException(status_code=404, detail=f"action_id '{action_id}' not found")

            # Broadcast execution ACK to dashboard
            await broadcast({
                "type": "remote_action_ack",
                "action_id": action_id,
                "agent_id": agent_id,
                "status": status,
                "action_type": action_row.action_type,
                "result_details": result_details,
                "executed_at": action_row.executed_at,
            })
            return {"status": "acknowledged", "action_id": action_id, "execution_status": status}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[Dispatcher] Failed to ack action %s: %s", action_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/actions")
async def api_get_all_actions(
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    """
    Query all dispatched actions across the fleet (for SOC dashboard & audits).
    """
    try:
        async with get_session() as session:
            rows = await get_all_remote_actions(
                session=session,
                agent_id=agent_id,
                status=status,
                limit=limit,
                offset=offset,
            )
            return {
                "actions": [
                    {
                        "action_id": r.action_id,
                        "agent_id": r.agent_id,
                        "action_type": r.action_type,
                        "vote_id": r.vote_id,
                        "target_pid": r.target_pid,
                        "target_file": r.target_file,
                        "command_node_ip": r.command_node_ip,
                        "parameters": r.parameters,
                        "status": r.status,
                        "result_details": r.result_details,
                        "created_at": r.created_at,
                        "dispatched_at": r.dispatched_at,
                        "executed_at": r.executed_at,
                    }
                    for r in rows
                ],
                "count": len(rows),
            }
    except Exception as exc:
        logger.error("[Dispatcher] Failed to query actions: %s", exc)
        return {"actions": [], "count": 0, "error": str(exc)}


@app.get("/api/audit")
@app.get("/api/audit-log")
async def api_get_audit_log(
    agent_id: str | None = None,
    action: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    """
    Retrieve audit log entries of all executed response actions from NeonDB.
    """
    try:
        async with get_session() as session:
            rows = await get_audit_log(
                session=session,
                agent_id=agent_id,
                action=action,
                limit=limit,
                offset=offset,
            )
            return {
                "logs": [
                    {
                        "id": r.id,
                        "agent_id": r.agent_id,
                        "action": r.action,
                        "vote_id": r.vote_id,
                        "target_pid": r.target_pid,
                        "target_file": r.target_file,
                        "status": r.status,
                        "details": r.details,
                        "executed_at": r.executed_at,
                    }
                    for r in rows
                ],
                "count": len(rows),
            }
    except Exception as exc:
        logger.error("[Audit] Failed to fetch audit logs: %s", exc)
        return {"logs": [], "count": 0, "error": str(exc)}


# ============================================================
# TRUST FEEDBACK LOOP  ← NEW
# ============================================================

@app.post("/api/trust/feedback")
async def post_trust_feedback(payload: dict):
    """
    Admin confirms or denies a verdict outcome.
    Updates:
      1. The ConsensusVerdict row in NeonDB (admin_confirmed flag)
      2. The central AgentTrust EMA score for the origin agent
      3. The local SQLite AgentTrustTracker (via record_outcome)

    Body:
        {
          "vote_id": "abc123",
          "confirmed": true,       // true = true-positive, false = false-positive
          "confirmed_by": "admin"
        }
    """
    vote_id = payload.get("vote_id")
    confirmed = bool(payload.get("confirmed", True))
    confirmed_by = str(payload.get("confirmed_by", "admin"))

    if not vote_id:
        raise HTTPException(status_code=400, detail="vote_id is required")

    try:
        async with get_session() as session:
            # 1. Mark the verdict row
            verdict_row = await record_admin_feedback(session, vote_id, confirmed, confirmed_by)
            if not verdict_row:
                raise HTTPException(status_code=404, detail=f"vote_id '{vote_id}' not found")

            # 2. Update central trust EMA
            agent_id = verdict_row.origin_agent_id
            old_trust_row = await get_agent_trust(session, agent_id)
            old_trust = old_trust_row.trust_score if old_trust_row else 0.5
            alpha = 0.2
            new_trust = alpha * (1.0 if confirmed else 0.0) + (1 - alpha) * old_trust
            await upsert_agent_trust(session, agent_id, new_trust, confirmed)

        # 3. Also update local SQLite tracker (keeps AgentTrustTracker in sync)
        local_trust_tracker.record_outcome(agent_id, was_correct=confirmed)

        logger.info(
            "[Trust] Feedback: vote_id=%s agent=%s confirmed=%s → trust %.3f → %.3f",
            vote_id, agent_id, confirmed, old_trust, new_trust,
        )

        return {
            "status": "updated",
            "vote_id": vote_id,
            "agent_id": agent_id,
            "confirmed": confirmed,
            "new_trust_score": new_trust,
            "confirmed_by": confirmed_by,
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[AEGIS DB] Trust feedback failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================
# ALERTS (SILENCE ALARMS)  ← NEW
# ============================================================

@app.get("/api/alerts")
async def get_alerts():
    """List all unacknowledged silence alarms from NeonDB."""
    try:
        async with get_session() as session:
            rows = await get_active_silence_alarms(session)
            return {
                "alerts": [
                    {
                        "id": r.id,
                        "agent_id": r.agent_id,
                        "last_seen": r.last_seen,
                        "silence_duration": r.silence_duration,
                        "alarm_at": r.alarm_at,
                        "acknowledged": r.acknowledged,
                    }
                    for r in rows
                ]
            }
    except Exception as exc:
        logger.warning("[AEGIS DB] Could not fetch alerts: %s", exc)
        return {"alerts": [], "error": str(exc)}


@app.post("/api/alerts/{alarm_id}/ack")
async def acknowledge_alert(alarm_id: int, payload: dict = {}):
    """Acknowledge a silence alarm, marking it resolved."""
    from backend.db.repository import acknowledge_silence_alarm
    acknowledged_by = payload.get("acknowledged_by", "admin")
    try:
        async with get_session() as session:
            await acknowledge_silence_alarm(session, alarm_id, acknowledged_by)
        return {"status": "acknowledged", "alarm_id": alarm_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================
# AUDIT LOG  ← NEW ENDPOINT
# ============================================================

@app.get("/api/audit")
async def get_audit_log_endpoint(
    agent_id: str | None = None,
    action: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    """Query centralised response action audit log from NeonDB."""
    try:
        async with get_session() as session:
            rows = await get_audit_log(session, agent_id=agent_id, action=action, limit=limit, offset=offset)
            return {
                "entries": [
                    {
                        "id": r.id,
                        "agent_id": r.agent_id,
                        "action": r.action,
                        "vote_id": r.vote_id,
                        "target_pid": r.target_pid,
                        "target_file": r.target_file,
                        "status": r.status,
                        "details": r.details,
                        "executed_at": r.executed_at,
                    }
                    for r in rows
                ],
                "count": len(rows),
            }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================
# MAINTENANCE WINDOW PORTAL ENDPOINTS  (NOW DB-BACKED)
# ============================================================

@app.post("/api/maintenance/schedule")
async def schedule_maintenance_window(payload: dict):
    """
    Schedule a new pre-announced maintenance window.
    Persists to NeonDB so it survives server restarts.
    """
    agent_id = payload.get("agent_id", "*")
    duration_seconds = float(payload.get("duration_seconds", 3600.0))
    approved_by = payload.get("approved_by", "admin")
    reason = payload.get("reason", "Scheduled System Maintenance")

    # Schedule in-memory (for immediate use by AdminTrustEngine)
    win = maintenance_portal.schedule_window(
        agent_id=agent_id,
        duration_seconds=duration_seconds,
        approved_by=approved_by,
        reason=reason,
    )

    # Persist to NeonDB
    try:
        async with get_session() as session:
            await persist_maintenance_window(session, win.to_dict())
    except Exception as exc:
        logger.warning("[AEGIS DB] Failed to persist maintenance window: %s", exc)

    return {"status": "scheduled", "window": win.to_dict()}


@app.get("/api/maintenance/windows")
async def get_maintenance_windows(active_only: bool = True):
    """List active or all recorded maintenance windows."""
    return {"windows": maintenance_portal.list_windows(active_only=active_only)}


@app.delete("/api/maintenance/cancel")
async def cancel_maintenance_window(window_id: str):
    """Cancel an active maintenance window (in-memory + DB)."""
    success = maintenance_portal.cancel_window(window_id)

    # Also cancel in DB
    try:
        async with get_session() as session:
            await cancel_maintenance_window_db(session, window_id)
    except Exception as exc:
        logger.warning("[AEGIS DB] Failed to cancel maintenance window in DB: %s", exc)

    return {"status": "cancelled" if success else "not_found", "window_id": window_id}


if __name__ == "__main__":
    import os
    import sys
    import uvicorn

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    os.environ["PYTHONPATH"] = project_root + (os.pathsep + os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else "")

    # 0.0.0.0 — agent machines on the LAN need to reach this
    uvicorn.run("backend.telemetry_api:app", host="0.0.0.0", port=8000, reload=True)