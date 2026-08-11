"""
agent/heartbeat.py
===================
AEGIS - Layer 1d Heartbeat & Silence Detection Mechanism
--------------------------------------------------------
Implements the distributed liveness and fault-detection heartbeat protocol for
AEGIS endpoint agents.

In a distributed Endpoint Detection and Response (EDR) architecture, every
monitored endpoint agent periodically emits a telemetry heartbeat payload to
signal that it is healthy and operational.

Architectural Role & Threat Model
---------------------------------
* **Silence IS the Alarm**: If an adversary gains elevated privileges on an
  endpoint and kills the AEGIS monitoring process or blocks network egress, the
  sudden cessation of heartbeats must trigger an immediate CRITICAL alert at
  Layer 3 (Command Node). Passive silence detection ensures tamper attempts do
  not go undetected.
* **Degraded State Awareness**: If CPU usage on an endpoint remains at near-100%
  capacity (e.g., due to crypto-mining, ransomware encryption, or resource exhaustion),
  heartbeats transition from "healthy" to "degraded", mapping to a Medium alert.
* **Pluggable Architecture**:
  - `HeartbeatEmitter` accepts an injected `send_fn` callable (pluggable seam
    for future ZeroMQ / REST egress to Layer 3 Command Node).
  - `SilenceDetector` accepts an injected `on_silent_alarm` callable (pluggable seam
    for future alert dispatch & automated response execution).

Design Decisions
----------------
* **Interruptible Threading**: Background threads use `threading.Event.wait(timeout)`
  instead of `time.sleep()`. This guarantees immediate thread termination upon calling
  `stop()`, avoiding shutdown hangs.
* **Thread-Safe Agent Tracking**: `SilenceDetector` guards its shared state map
  with a `threading.Lock` so multiple threads or incoming telemetry streams can
  concurrently record heartbeats without race conditions.
* **Alarm Suppression & Automatic Re-arming**: Once silence is detected for an
  agent and a CRITICAL alarm is raised, duplicate alarms are suppressed for
  subsequent check cycles until a new heartbeat arrives to clear the alarm state.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, List

import psutil

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)


# ===========================================================================
# Dataclasses & Types
# ===========================================================================
@dataclass
class AgentState:
    """
    In-memory tracking record maintained by SilenceDetector for a single agent.

    Attributes
    ----------
    agent_id : str
        Unique identifier for the monitored machine/agent.
    last_seen : float
        Unix epoch timestamp (seconds) when the last heartbeat was received.
    status : str
        Last reported health status (e.g., "healthy", "degraded").
    cpu : float
        Last reported CPU usage percentage.
    alarm_raised : bool
        True if a silent alarm has already been fired for this agent's current
        silence episode (used for alarm suppression).
    """

    agent_id: str
    last_seen: float
    status: str = "healthy"
    cpu: float = 0.0
    alarm_raised: bool = False


# ===========================================================================
# HeartbeatEmitter
# ===========================================================================
class HeartbeatEmitter:
    """
    Background worker that periodically collects local host telemetry (CPU usage,
    health status, timestamp) and emits a heartbeat payload via a pluggable seam.

    Parameters
    ----------
    agent_id : str, optional
        Unique machine identifier (default "agent-local").
    interval : float, optional
        Period in seconds between heartbeat emissions (AEGIS spec default 5.0).
    send_fn : Callable[[Dict[str, Any]], None], optional
        Callable taking a heartbeat payload dict and delivering it.
        If None, defaults to an internal logging fallback.
    cpu_threshold : float, optional
        CPU percentage threshold above which status transitions to "degraded"
        (default 90.0%).
    sustained_high_cpu_count : int, optional
        Number of consecutive high CPU checks required before setting status to
        "degraded" (default 2).

    Quirks / Implementation Details
    -------------------------------
    * `psutil.cpu_percent(interval=None)` is non-blocking to prevent stalling
      the emitter thread loop.
    * Uses `threading.Event` to support immediate, non-blocking thread cancellation.
    """

    def __init__(
        self,
        agent_id: str = "agent-local",
        interval: float = 5.0,
        send_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
        cpu_threshold: float = 90.0,
        sustained_high_cpu_count: int = 2,
    ) -> None:
        self.agent_id = agent_id
        self.interval = max(0.1, float(interval))
        self.send_fn = send_fn or self._default_send_fn
        self.cpu_threshold = float(cpu_threshold)
        self.sustained_high_cpu_count = max(1, int(sustained_high_cpu_count))

        self._consecutive_high_cpu: int = 0
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running: bool = False

    @staticmethod
    def _default_send_fn(payload: Dict[str, Any]) -> None:
        """Fallback payload sink when no external transport function is provided."""
        logger.info("[Emitter-DefaultSink] Heartbeat sent: %s", payload)

    def _determine_status(self, cpu_usage: float) -> str:
        """
        Evaluate CPU metrics against threshold to determine health status.

        Returns "degraded" if CPU load exceeds threshold for sustained cycles,
        otherwise returns "healthy".
        """
        if cpu_usage >= self.cpu_threshold:
            self._consecutive_high_cpu += 1
        else:
            self._consecutive_high_cpu = 0

        if self._consecutive_high_cpu >= self.sustained_high_cpu_count:
            return "degraded"
        return "healthy"

    def _collect_payload(self) -> Dict[str, Any]:
        """
        Build the AEGIS standard heartbeat payload.

        Format matches documented AEGIS Layer 1 spec:
            agent_id: str
            status: str ("healthy" | "degraded")
            cpu: float
            timestamp: int (unix epoch seconds)
        """
        # Call non-blocking CPU check
        cpu_usage = float(psutil.cpu_percent(interval=None))
        status = self._determine_status(cpu_usage)
        now_ts = int(time.time())

        return {
            "agent_id": self.agent_id,
            "status": status,
            "cpu": cpu_usage,
            "timestamp": now_ts,
        }

    def _run_loop(self) -> None:
        """Background thread main loop."""
        logger.info(
            "[HeartbeatEmitter] Started emitting for agent '%s' (interval=%.1fs)",
            self.agent_id,
            self.interval,
        )
        while not self._stop_event.is_set():
            try:
                payload = self._collect_payload()
                self.send_fn(payload)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "[HeartbeatEmitter] Error generating/sending heartbeat for '%s': %s",
                    self.agent_id,
                    exc,
                    exc_info=True,
                )

            # Interruptible wait for next interval
            if self._stop_event.wait(self.interval):
                break

        logger.info("[HeartbeatEmitter] Loop stopped for agent '%s'", self.agent_id)

    def start(self) -> None:
        """Start the background heartbeat emitter thread."""
        if self._is_running:
            logger.warning("[HeartbeatEmitter] Emitter is already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"AEGIS-HeartbeatEmitter-{self.agent_id}",
            daemon=True,
        )
        self._is_running = True
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """
        Signal the background thread to stop and wait for completion.

        Parameters
        ----------
        timeout : float, optional
            Maximum duration in seconds to wait for thread join (default 5.0s).
        """
        if not self._is_running or self._thread is None:
            return

        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._is_running = False
        self._thread = None
        logger.info("[HeartbeatEmitter] Stopped emitter for agent '%s'", self.agent_id)


# ===========================================================================
# SilenceDetector
# ===========================================================================
class SilenceDetector:
    """
    Receiving-side monitor that tracks active endpoint agents and detects when
    an agent stops sending heartbeats.

    Parameters
    ----------
    silence_threshold : float, optional
        Maximum allowed duration (seconds) without a heartbeat before raising a
        CRITICAL Silent Alarm (AEGIS spec default 15.0s).
    check_interval : float, optional
        Period (seconds) between silence evaluation cycles (default 1.0s).
    on_silent_alarm : Callable[[Dict[str, Any]], None], optional
        Callback invoked when an agent exceeds the silence threshold. Defaults
        to an internal CRITICAL log logger.

    Quirks / Design Decisions
    -------------------------
    * **Independent Multi-Agent Tracking**: Maintains separate last-seen state
      for every `agent_id` registered via `record_heartbeat()`.
    * **Alarm Suppression & Re-arming**: When silence threshold is breached,
      `on_silent_alarm` fires ONCE per agent. The alarm state automatically
      clears and re-arms if a subsequent heartbeat is recorded for that agent.
    * **Thread Safety**: All state reads and updates are synchronized with a lock.
    """

    def __init__(
        self,
        silence_threshold: float = 15.0,
        check_interval: float = 1.0,
        on_silent_alarm: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.silence_threshold = max(0.5, float(silence_threshold))
        self.check_interval = max(0.1, float(check_interval))
        self.on_silent_alarm = on_silent_alarm or self._default_alarm_handler

        self._agents: Dict[str, AgentState] = {}
        self._lock = threading.Lock()

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running: bool = False

    @staticmethod
    def _default_alarm_handler(alarm_payload: Dict[str, Any]) -> None:
        """Default handler logging CRITICAL alert when an agent goes silent."""
        logger.critical(
            "[SilenceDetector] CRITICAL SILENT ALARM - Agent '%s' went silent! "
            "Last seen %.1fs ago (threshold=%.1fs)",
            alarm_payload["agent_id"],
            alarm_payload["silence_duration"],
            alarm_payload["silence_threshold"],
        )

    def record_heartbeat(self, payload: Dict[str, Any]) -> None:
        """
        Process an incoming heartbeat payload and update agent tracking state.

        Parameters
        ----------
        payload : Dict[str, Any]
            Heartbeat payload containing `agent_id`, `timestamp`, `status`, `cpu`.
        """
        agent_id = payload.get("agent_id")
        if not agent_id or not isinstance(agent_id, str):
            logger.warning("[SilenceDetector] Received malformed heartbeat payload: %s", payload)
            return

        now = time.time()
        status = str(payload.get("status", "healthy"))
        cpu = float(payload.get("cpu", 0.0))

        with self._lock:
            if agent_id in self._agents:
                agent = self._agents[agent_id]
                if agent.alarm_raised:
                    logger.info(
                        "[SilenceDetector] Agent '%s' RECOVERED (heartbeat received after silence alarm)",
                        agent_id,
                    )
                agent.last_seen = now
                agent.status = status
                agent.cpu = cpu
                agent.alarm_raised = False  # Re-arm silence alarm for future dropouts
            else:
                self._agents[agent_id] = AgentState(
                    agent_id=agent_id,
                    last_seen=now,
                    status=status,
                    cpu=cpu,
                    alarm_raised=False,
                )
                logger.info("[SilenceDetector] Registered new agent tracking for '%s'", agent_id)

    def _check_silence(self) -> List[Dict[str, Any]]:
        """
        Evaluate all tracked agents against the silence threshold.

        Returns a list of generated alarm payloads for agents whose silence
        breached the threshold and have not yet been flagged.
        """
        now = time.time()
        alarms_to_fire: List[Dict[str, Any]] = []

        with self._lock:
            for agent_id, agent in self._agents.items():
                silence_duration = now - agent.last_seen
                if silence_duration >= self.silence_threshold and not agent.alarm_raised:
                    agent.alarm_raised = True
                    alarm_payload = {
                        "agent_id": agent_id,
                        "event": "SILENT_ALARM",
                        "severity": "CRITICAL",
                        "silence_duration": round(silence_duration, 2),
                        "silence_threshold": self.silence_threshold,
                        "last_seen_timestamp": agent.last_seen,
                        "last_reported_status": agent.status,
                        "timestamp": int(now),
                    }
                    alarms_to_fire.append(alarm_payload)

        return alarms_to_fire

    def _run_check_loop(self) -> None:
        """Background monitoring thread loop."""
        logger.info(
            "[SilenceDetector] Monitoring started (silence_threshold=%.1fs, check_interval=%.1fs)",
            self.silence_threshold,
            self.check_interval,
        )

        while not self._stop_event.is_set():
            try:
                alarms = self._check_silence()
                for alarm in alarms:
                    try:
                        self.on_silent_alarm(alarm)
                    except Exception as cb_exc:  # noqa: BLE001
                        logger.warning(
                            "[SilenceDetector] Exception in on_silent_alarm callback for '%s': %s",
                            alarm.get("agent_id"),
                            cb_exc,
                        )
            except Exception as exc:  # noqa: BLE001
                logger.warning("[SilenceDetector] Error in silence check loop: %s", exc)

            if self._stop_event.wait(self.check_interval):
                break

        logger.info("[SilenceDetector] Monitoring loop stopped.")

    def start(self) -> None:
        """Start the silence detector background thread."""
        if self._is_running:
            logger.warning("[SilenceDetector] SilenceDetector is already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_check_loop,
            name="AEGIS-SilenceDetector",
            daemon=True,
        )
        self._is_running = True
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """
        Signal monitoring thread to stop and wait for completion.

        Parameters
        ----------
        timeout : float, optional
            Maximum duration in seconds to wait for thread join (default 5.0s).
        """
        if not self._is_running or self._thread is None:
            return

        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._is_running = False
        self._thread = None
        logger.info("[SilenceDetector] Stopped silence detector.")

    def get_agent_status(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve current recorded tracking state for a specific agent.

        Returns None if agent_id is not tracked.
        """
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return None
            return {
                "agent_id": agent.agent_id,
                "last_seen": agent.last_seen,
                "silence_duration": round(time.time() - agent.last_seen, 2),
                "status": agent.status,
                "cpu": agent.cpu,
                "alarm_raised": agent.alarm_raised,
            }


# ===========================================================================
# Runnable Demo
# ===========================================================================
if __name__ == "__main__":
    print("=" * 72)
    print("AEGIS Layer 1d — Heartbeat & Silence Detector Verification Demo")
    print("=" * 72)

    # Recorded alarms for validation assertion
    fired_alarms: List[Dict[str, Any]] = []

    def demo_alarm_callback(alarm_payload: Dict[str, Any]) -> None:
        fired_alarms.append(alarm_payload)
        print("\n" + "!" * 70)
        print("!!! [CRITICAL ALERT RECEIVED VIA STUB CALLBACK] !!!")
        print(f"   Agent ID          : {alarm_payload['agent_id']}")
        print(f"   Event             : {alarm_payload['event']}")
        print(f"   Silence Duration  : {alarm_payload['silence_duration']}s")
        print(f"   Silence Threshold : {alarm_payload['silence_threshold']}s")
        print(f"   Last Reported Status: {alarm_payload['last_reported_status']}")
        print("!" * 70 + "\n")

    # Override defaults with fast intervals for quick demo execution
    DEMO_EMIT_INTERVAL = 0.5       # Emit every 500ms (demo override, default 5s)
    DEMO_SILENCE_THRESHOLD = 2.0   # Silence alarm after 2.0s (demo override, default 15s)
    DEMO_CHECK_INTERVAL = 0.2     # Monitor checks every 200ms

    target_agent_id = "agent-node-alpha"

    print(f"\n1. Initializing SilenceDetector (threshold={DEMO_SILENCE_THRESHOLD}s)...")
    detector = SilenceDetector(
        silence_threshold=DEMO_SILENCE_THRESHOLD,
        check_interval=DEMO_CHECK_INTERVAL,
        on_silent_alarm=demo_alarm_callback,
    )
    detector.start()

    print(f"2. Initializing HeartbeatEmitter for '{target_agent_id}' (interval={DEMO_EMIT_INTERVAL}s)...")
    emitter = HeartbeatEmitter(
        agent_id=target_agent_id,
        interval=DEMO_EMIT_INTERVAL,
        send_fn=detector.record_heartbeat,
    )
    emitter.start()

    print("\n3. Allowing heartbeats to emit for 2.0 seconds (expecting ~4 heartbeats)...")
    time.sleep(2.0)

    status_snapshot = detector.get_agent_status(target_agent_id)
    print(f"   [Snapshot] Agent status before failure: {status_snapshot}")

    print("\n4. Simulating Agent Failure / Attacker Process Kill (Stopping HeartbeatEmitter)...")
    emitter.stop()
    kill_time = time.time()
    print(f"   HeartbeatEmitter stopped at timestamp {int(kill_time)}.")

    print(f"\n5. Waiting {DEMO_SILENCE_THRESHOLD + 1.0:.1f}s for SilenceDetector to trigger alarm...")
    time.sleep(DEMO_SILENCE_THRESHOLD + 1.0)

    print("\n6. Cleaning up SilenceDetector...")
    detector.stop()

    print("\n7. Verification Results:")
    if len(fired_alarms) == 1 and fired_alarms[0]["agent_id"] == target_agent_id:
        print("   [SUCCESS] SilenceDetector correctly raised 1 CRITICAL SILENT ALARM for silent agent.")
    else:
        print(f"   [FAILURE] Expected 1 alarm, but got {len(fired_alarms)} alarms.")

    print("=" * 72)
