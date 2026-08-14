import asyncio
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# AEGIS TELEMETRY API
# ============================================================

app = FastAPI(
    title="AEGIS Telemetry API",
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():

    global api_loop

    api_loop = asyncio.get_running_loop()

    print("[AEGIS API] Telemetry API started")
    print("[AEGIS API] WebSocket: /ws/telemetry")


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    return {
        "service": "AEGIS Telemetry API",
        "status": "online",
        "websocket": "/ws/telemetry",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
async def health():

    return {
        "status": "healthy",
        "connected_clients": len(clients),
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
    Endpoint for live telemetry collectors (e.g. linux_collector.py)
    to submit predictions to be broadcasted to all connected dashboards.
    """
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


if __name__ == "__main__":
    import os
    import sys
    import uvicorn

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    os.environ["PYTHONPATH"] = project_root + (os.pathsep + os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else "")

    uvicorn.run("backend.telemetry_api:app", host="127.0.0.1", port=8000, reload=True)