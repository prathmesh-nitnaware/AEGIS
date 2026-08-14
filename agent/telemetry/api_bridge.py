import asyncio
import threading
from typing import Optional

from backend.telemetry_api import update_latest, broadcast


class TelemetryAPIBridge:
    """
    Sends completed telemetry/prediction events from the Linux
    collector to the AEGIS FastAPI WebSocket layer.
    """

    def __init__(self):
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop):
        self.loop = loop

    def publish(self, event: dict):
        """
        Publish one completed telemetry event.

        The collector may run in a normal synchronous/threaded context,
        while FastAPI uses asyncio. Therefore we schedule the broadcast
        safely on the API event loop.
        """

        update_latest(event)

        if self.loop is None:
            return

        asyncio.run_coroutine_threadsafe(
            broadcast(event),
            self.loop,
        )
