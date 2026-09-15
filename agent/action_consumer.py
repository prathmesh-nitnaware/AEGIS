"""
agent/action_consumer.py
========================
AEGIS - Autonomous Remote Action Consumer Daemon
------------------------------------------------
Runs on endpoint agent machines to autonomously receive, execute, and
acknowledge mitigation and containment commands dispatched by the Command
Node following peer/centralized consensus verdicts.

Complete Hands-Free Loop:
  1. Anomaly Detected (ML models: ember, cicids, linux, etc.)
  2. Peer / Centralized Consensus (weighted trust + correlation)
  3. Command Node dispatches RemoteAction (KILL_PROCESS / ISOLATE_HOST / etc.)
  4. This Consumer Daemon fetches pending commands for this agent
  5. Local AgentResponseDriver executes OS-level containment
  6. This Consumer sends ACK back to Command Node
  7. Command Node records execution to centralized NeonDB AuditLog & WebSocket

Usage:
  python -m agent.action_consumer --agent-id node-1 --server http://localhost:8000
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from agent.response_driver import AgentResponseDriver

logger = logging.getLogger("aegis.action_consumer")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
)


class ActionConsumerDaemon:
    """
    Autonomous command consumer for an AEGIS endpoint agent.
    Polls the Command Node for actions assigned to this agent_id,
    executes them locally using AgentResponseDriver, and sends execution ACKs.
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        command_node_url: Optional[str] = None,
        poll_interval: float = 2.0,
        response_driver: Optional[AgentResponseDriver] = None,
    ) -> None:
        self.agent_id = agent_id or os.getenv("AGENT_ID", "agent-local")
        self.command_node_url = (
            command_node_url or os.getenv("COMMAND_NODE_URL", "http://localhost:8000")
        ).rstrip("/")
        self.poll_interval = poll_interval

        # Extract host/IP of command node for firewall isolation rule bypass
        parsed = urlparse(self.command_node_url)
        cn_ip = parsed.hostname or "127.0.0.1"
        self.driver = response_driver or AgentResponseDriver(command_node_ip=cn_ip)

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._session = requests.Session()

    def execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatch an action dictionary to the appropriate local OS enforcement method.
        """
        action_id = action.get("action_id", "unknown")
        action_type = (action.get("action_type") or "").upper()
        target_pid = action.get("target_pid")
        target_file = action.get("target_file")
        command_node_ip = action.get("command_node_ip") or self.driver.command_node_ip

        logger.info(
            "[%s] Executing remote action %s (%s)...",
            self.agent_id,
            action_id,
            action_type,
        )

        try:
            if action_type == "KILL_PROCESS":
                if not target_pid:
                    return {"status": "failed", "reason": "Missing target_pid for KILL_PROCESS"}
                return self.driver.kill_process(int(target_pid))

            elif action_type == "QUARANTINE_FILE":
                if not target_file:
                    return {"status": "failed", "reason": "Missing target_file for QUARANTINE_FILE"}
                return self.driver.quarantine_file(str(target_file))

            elif action_type == "ISOLATE_HOST":
                return self.driver.isolate_host(command_node_ip=command_node_ip)

            elif action_type == "UNISOLATE_HOST":
                return self.driver.unisolate_host()

            elif action_type == "ALERT":
                return self.driver.log_action("ALERT", action)

            elif action_type == "LOG":
                return self.driver.log_action("LOG", action)

            else:
                logger.warning("[%s] Unknown action type: %s", self.agent_id, action_type)
                return {"status": "failed", "reason": f"Unknown action_type '{action_type}'"}

        except Exception as exc:
            logger.error(
                "[%s] Exception executing action %s (%s): %s",
                self.agent_id,
                action_id,
                action_type,
                exc,
            )
            return {"status": "error", "reason": str(exc)}

    def ack_action(
        self, action_id: str, status: str, result_details: Dict[str, Any]
    ) -> bool:
        """
        Send execution acknowledgment back to the Command Node.
        """
        ack_url = f"{self.command_node_url}/api/agents/{self.agent_id}/actions/{action_id}/ack"
        payload = {
            "status": status,
            "result_details": result_details,
        }
        try:
            resp = self._session.post(ack_url, json=payload, timeout=5)
            if resp.status_code == 200:
                logger.info(
                    "[%s] Acknowledged action %s -> %s",
                    self.agent_id,
                    action_id,
                    status,
                )
                return True
            else:
                logger.warning(
                    "[%s] Failed to ack action %s: HTTP %d %s",
                    self.agent_id,
                    action_id,
                    resp.status_code,
                    resp.text,
                )
        except Exception as exc:
            logger.error("[%s] Network error acknowledging action %s: %s", self.agent_id, action_id, exc)
        return False

    def poll_and_execute_once(self) -> List[Dict[str, Any]]:
        """
        Fetch pending commands from Command Node, execute each, and send ACKs.
        Returns a list of executed action result summaries.
        """
        url = f"{self.command_node_url}/api/agents/{self.agent_id}/actions/pending"
        try:
            resp = self._session.get(url, timeout=5)
            if resp.status_code != 200:
                return []
            data = resp.json()
            actions = data.get("actions", [])
        except Exception as exc:
            logger.debug("[%s] Error fetching pending actions: %s", self.agent_id, exc)
            return []

        results = []
        for action in actions:
            action_id = action.get("action_id")
            if not action_id:
                continue

            exec_result = self.execute_action(action)
            raw_status = exec_result.get("status", "failed").lower()

            if raw_status in ("success", "alert_raised", "not_found"):
                status = "SUCCESS"
            elif raw_status == "simulated_success":
                status = "SIMULATED_SUCCESS"
            else:
                status = "FAILED"

            self.ack_action(action_id, status=status, result_details=exec_result)
            results.append({
                "action_id": action_id,
                "action_type": action.get("action_type"),
                "status": status,
                "result": exec_result,
            })

        return results

    def _loop(self) -> None:
        """Background polling loop."""
        logger.info(
            "[%s] Autonomous Command Consumer loop started. Listening for actions from %s...",
            self.agent_id,
            self.command_node_url,
        )
        while self._running:
            try:
                self.poll_and_execute_once()
            except Exception as exc:
                logger.error("[%s] Unexpected error in polling loop: %s", self.agent_id, exc)
            time.sleep(self.poll_interval)
        logger.info("[%s] Autonomous Command Consumer loop stopped.", self.agent_id)

    def start(self) -> None:
        """Start the consumer loop in a background daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop,
            name=f"ActionConsumer-{self.agent_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the background consumer loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)


# ===========================================================================
# CLI Runner
# ===========================================================================
def main():
    parser = argparse.ArgumentParser(description="AEGIS Autonomous Action Consumer Daemon")
    parser.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent-local"), help="Agent identifier")
    parser.add_argument("--server", default=os.getenv("COMMAND_NODE_URL", "http://localhost:8000"), help="Command Node URL")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--once", action="store_true", help="Execute pending actions once and exit")
    args = parser.parse_args()

    daemon = ActionConsumerDaemon(
        agent_id=args.agent_id,
        command_node_url=args.server,
        poll_interval=args.interval,
    )

    if args.once:
        print(f"[{args.agent_id}] Checking pending actions once...")
        executed = daemon.poll_and_execute_once()
        print(f"[{args.agent_id}] Executed {len(executed)} actions: {executed}")
        return

    print("=" * 70)
    print(" AEGIS Autonomous Remote Action Consumer Daemon")
    print(f" Node Identifier   : {args.agent_id}")
    print(f" Command Node URL  : {args.server}")
    print(f" Polling Interval  : {args.interval}s")
    print(" Press Ctrl+C to shutdown")
    print("=" * 70)

    daemon.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nShutdown signal received. Stopping consumer...")
        daemon.stop()
        print("Consumer stopped cleanly.")


if __name__ == "__main__":
    main()
