"""
agent/server_monitor.py
=======================
AEGIS - Main Server Liveness & Cascade Shutdown Watchdog
---------------------------------------------------------
Monitors connectivity to the central AEGIS Command Node / Main Server.
If the Main Server is shut down (gracefully or forcefully), this watchdog
detects the event and triggers an autonomous cascading shutdown of all
connected agent collectors, background workers, and emitter threads.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

logger = logging.getLogger("aegis.server_monitor")


class ServerShutdownWatchdog:
    """
    Continuous watchdog running on an endpoint agent.
    Actively monitors Main Server reachability via the /api/health endpoint.
    If the server shuts down or becomes unreachable, triggers on_server_shutdown.
    """

    def __init__(
        self,
        command_node_url: str,
        agent_id: str = "agent-local",
        check_interval: Optional[float] = None,
        max_consecutive_failures: Optional[int] = None,
        initial_connection_timeout: Optional[float] = None,
        on_server_shutdown: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.command_node_url = (command_node_url or "http://127.0.0.1:8000").rstrip("/")
        self.agent_id = agent_id
        self.check_interval = float(
            check_interval
            or os.environ.get("AEGIS_SERVER_CHECK_INTERVAL")
            or 2.0
        )
        self.max_consecutive_failures = int(
            max_consecutive_failures
            or os.environ.get("AEGIS_MAX_SERVER_FAILURES")
            or 3
        )
        self.initial_connection_timeout = float(
            initial_connection_timeout
            or os.environ.get("AEGIS_INITIAL_CONNECT_TIMEOUT")
            or 20.0
        )
        self.on_server_shutdown = on_server_shutdown

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._is_connected = False
        self._consecutive_failures = 0
        self._triggered = False
        self._lock = threading.Lock()

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    def start(self) -> None:
        """Starts the watchdog monitoring thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"AEGIS-ServerWatchdog-{self.agent_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Halts the watchdog monitoring thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _query_server_health(self) -> tuple[bool, Optional[str]]:
        """
        Queries {command_node_url}/api/health.
        Returns:
            (is_healthy: bool, server_status: Optional[str])
        """
        health_url = f"{self.command_node_url}/api/health"
        req = urllib.request.Request(
            health_url,
            headers={"User-Agent": f"AEGIS-Watchdog/{self.agent_id}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                if resp.status == 200:
                    raw = resp.read().decode("utf-8", errors="replace")
                    try:
                        data = json.loads(raw)
                        status = str(data.get("status", "")).lower()
                        return True, status
                    except Exception:
                        return True, "ok"
                return False, f"HTTP_{resp.status}"
        except urllib.error.HTTPError as exc:
            return False, f"HTTP_{exc.code}"
        except Exception as exc:
            return False, str(exc)

    def _trigger_shutdown(self, reason: str) -> None:
        """Initiates cascade shutdown of this agent."""
        with self._lock:
            if self._triggered:
                return
            self._triggered = True

        banner = (
            "\n" + "=" * 80 + "\n"
            f"  [!] CRITICAL: MAIN SERVER SHUTDOWN DETECTED\n"
            f"  Target Server:  {self.command_node_url}\n"
            f"  Trigger Reason: {reason}\n"
            f"  Action:         Cascading shutdown of AEGIS Agent '{self.agent_id}'\n"
            + "=" * 80 + "\n"
        )
        print(banner, flush=True)
        logger.warning(
            "[%s] Cascade shutdown triggered (reason=%s, server=%s)",
            self.agent_id,
            reason,
            self.command_node_url,
        )

        self._stop_event.set()

        if self.on_server_shutdown:
            try:
                self.on_server_shutdown(reason)
            except Exception as exc:
                logger.error("[%s] Error in on_server_shutdown callback: %s", self.agent_id, exc)

        # Fallback safeguard: if process remains alive after 4s, force terminate
        def _fallback_exit():
            time.sleep(4.0)
            print(f"[*] Force-terminating agent process '{self.agent_id}'.", flush=True)
            os._exit(0)

        threading.Thread(target=_fallback_exit, daemon=True).start()

    def _run_loop(self) -> None:
        """Main watchdog monitoring cycle."""
        # Phase 1: Wait for initial connection handshake
        connect_start = time.time()
        while not self._stop_event.is_set():
            is_healthy, status = self._query_server_health()
            if is_healthy and status not in ("shutdown", "server_shutting_down"):
                self._is_connected = True
                self._consecutive_failures = 0
                logger.info(
                    "[%s] Connected to Main Server at %s. Liveness watchdog armed.",
                    self.agent_id,
                    self.command_node_url,
                )
                break

            # If user stopped watchdog
            if self._stop_event.is_set():
                return

            if time.time() - connect_start > self.initial_connection_timeout:
                logger.warning(
                    "[%s] Could not confirm initial connection to Main Server at %s within %.1fs. Continuing retry...",
                    self.agent_id,
                    self.command_node_url,
                    self.initial_connection_timeout,
                )
                connect_start = time.time()  # reset to avoid spamming warning

            self._stop_event.wait(self.check_interval)

        # Phase 2: Continuous monitoring loop
        while not self._stop_event.is_set():
            self._stop_event.wait(self.check_interval)
            if self._stop_event.is_set():
                break

            is_healthy, status = self._query_server_health()

            # Case A: Explicit graceful shutdown signal from server
            if status in ("shutdown", "server_shutting_down"):
                self._trigger_shutdown(f"SERVER_EXPLICIT_SHUTDOWN ({status})")
                break

            # Case B: Server is healthy
            if is_healthy:
                self._consecutive_failures = 0
                continue

            # Case C: Failed connection
            self._consecutive_failures += 1
            logger.debug(
                "[%s] Server health check failed (%d/%d): %s",
                self.agent_id,
                self._consecutive_failures,
                self.max_consecutive_failures,
                status,
            )

            if self._consecutive_failures >= self.max_consecutive_failures:
                self._trigger_shutdown(
                    f"SERVER_UNREACHABLE (failed {self._consecutive_failures} consecutive checks: {status})"
                )
                break
