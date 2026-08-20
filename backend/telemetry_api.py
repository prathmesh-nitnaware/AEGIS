import asyncio
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# AEGIS TELEMETRY API
# ============================================================

from contextlib import asynccontextmanager

import platform

from backend.services.telemetry_service import add_event, add_model_result
from backend.api.telemetry import router as telemetry_router
from agent.heartbeat import SilenceDetector

SERVER_START_TIME = time.time()

# ============================================================
# HEARTBEAT / SILENT-ALARM SUBSYSTEM
# ============================================================
# on_silent_alarm fires from SilenceDetector's own background thread, NOT
# the asyncio event loop - so it goes through publish_event() (the existing
# thread-safe bridge below) rather than calling broadcast() directly.
def _on_silent_alarm(alarm_payload: dict):
    publish_event({**alarm_payload, "type": "agent_alarm"})


silence_detector = SilenceDetector(
    silence_threshold=15.0,   # AEGIS spec default - no heartbeat for 15s -> alarm
    check_interval=2.0,
    on_silent_alarm=_on_silent_alarm,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global api_loop
    api_loop = asyncio.get_running_loop()
    silence_detector.start()
    print("[AEGIS API] Telemetry API started")
    print("[AEGIS API] WebSocket: /ws/telemetry")
    print("[AEGIS API] Heartbeat ingestion: POST /api/heartbeat")
    yield
    silence_detector.stop()


app = FastAPI(
    title="AEGIS Telemetry API",
    version="1.0.0",
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

    print(
        f"[AEGIS API] Dashboard connected "
        f"(clients={len(clients)})"
    )

    try:

        # Immediately send latest known event
        await websocket.send_json(latest_event)

        # Keep connection alive
        while True:

            await asyncio.sleep(30)

            # Ping-like message
            await websocket.send_json(
                {
                    "type": "heartbeat",
                    "timestamp": time.time(),
                }
            )

    except WebSocketDisconnect:

        clients.discard(websocket)

        print(
            f"[AEGIS API] Dashboard disconnected "
            f"(clients={len(clients)})"
        )

    except Exception as exc:

        clients.discard(websocket)

        print(
            f"[AEGIS API] WebSocket error: {exc}"
        )


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

    """
    Broadcast a telemetry event to every connected dashboard.
    """

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
    Called by the Linux telemetry collector.

    The collector can run outside the asyncio event loop.
    This function safely schedules the broadcast on the
    FastAPI event loop.
    """

    update_latest(event)

    if api_loop is None:

        print(
            "[AEGIS API] WARNING: "
            "API event loop is not ready"
        )

        return

    try:

        asyncio.run_coroutine_threadsafe(
            broadcast(event),
            api_loop,
        )

    except Exception as exc:

        print(
            f"[AEGIS API] Failed to publish event: {exc}"
        )


# ============================================================
# TEST EVENT
# ============================================================

@app.post("/api/telemetry")
async def post_telemetry(event: dict):
    """
    Endpoint for live telemetry collectors (e.g. run_all.py, linux_collector.py)
    to submit predictions to be broadcasted to all connected dashboards.
    """
    add_event(event)
    if "threat_score" in event or "score" in event:
        add_model_result(event)
    await broadcast(event)
    return {
        "status": "published",
        "event": event,
    }


@app.post("/api/telemetry/test")
async def test_telemetry():


    """
    Sends a fake telemetry event.

    Used only to verify that the WebSocket/dashboard
    connection works before connecting the real Linux
    collector.
    """

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

    return {
        "status": "sent",
        "event": event,
    }


# ============================================================
# HEARTBEAT INGESTION
# ============================================================
# Called by each agent machine every 5s (see agent/heartbeat_runner.py).
# Runs inside the async endpoint, but record_heartbeat() is protected by its
# own internal lock so this is safe to call directly.
@app.post("/api/heartbeat")
async def post_heartbeat(payload: dict):
    silence_detector.record_heartbeat(payload)

    # Use a distinct event type from the reserved "heartbeat" keepalive
    # ping (see telemetry_socket below) so the frontend doesn't drop it.
    await broadcast({**payload, "type": "agent_heartbeat"})

    return {"status": "ok", "agent_id": payload.get("agent_id")}


@app.get("/api/agents")
async def get_agents():
    """
    Full snapshot of every tracked agent's heartbeat state. The dashboard
    calls this once on load so it doesn't have to wait for a live event to
    know who's already registered.
    """
    return {"agents": silence_detector.list_agents()}


if __name__ == "__main__":
    import os
    import sys
    import uvicorn

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    os.environ["PYTHONPATH"] = project_root + (os.pathsep + os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else "")

    # 0.0.0.0, not 127.0.0.1 - agent machines on the LAN need to reach this,
    # not just processes on this same machine.
    uvicorn.run("backend.telemetry_api:app", host="0.0.0.0", port=8000, reload=True)