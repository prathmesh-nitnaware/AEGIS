"""
tests/test_server_shutdown_cascade.py
======================================
Comprehensive unit tests for the Main Server Shutdown & Agent Cascading
Shutdown mechanism.
"""

import http.server
import json
import socketserver
import threading
import time
from typing import List

import pytest
from agent.server_monitor import ServerShutdownWatchdog
from agent.action_consumer import ActionConsumerDaemon


class MockServerHandler(http.server.BaseHTTPRequestHandler):
    status_response = "healthy"
    should_drop = False

    def do_GET(self):
        if self.path == "/api/health":
            if MockServerHandler.should_drop:
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b"Service Unavailable")
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {
                "status": MockServerHandler.status_response,
                "uptime": 12.3,
                "timestamp": time.time(),
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress console noise during testing


@pytest.fixture
def mock_server():
    """Spawns a local test HTTP server on an ephemeral port."""
    MockServerHandler.status_response = "healthy"
    MockServerHandler.should_drop = False

    server = socketserver.TCPServer(("127.0.0.1", 0), MockServerHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}"
    yield url, MockServerHandler

    server.shutdown()
    server.server_close()


def test_watchdog_initial_handshake_and_healthy(mock_server):
    url, handler = mock_server
    shutdown_reasons: List[str] = []

    watchdog = ServerShutdownWatchdog(
        command_node_url=url,
        agent_id="test-agent-1",
        check_interval=0.1,
        max_consecutive_failures=3,
        initial_connection_timeout=2.0,
        on_server_shutdown=lambda r: shutdown_reasons.append(r),
    )
    watchdog.start()

    time.sleep(0.3)
    assert watchdog.is_connected, "Watchdog must establish connection with healthy server"
    assert len(shutdown_reasons) == 0, "No shutdown should occur while server is healthy"

    watchdog.stop()


def test_watchdog_detects_explicit_server_shutdown(mock_server):
    url, handler = mock_server
    shutdown_reasons: List[str] = []

    watchdog = ServerShutdownWatchdog(
        command_node_url=url,
        agent_id="test-agent-2",
        check_interval=0.1,
        max_consecutive_failures=3,
        initial_connection_timeout=2.0,
        on_server_shutdown=lambda r: shutdown_reasons.append(r),
    )
    watchdog.start()
    time.sleep(0.2)
    assert watchdog.is_connected

    # Simulate server announcing shutdown in /api/health
    handler.status_response = "server_shutting_down"

    # Wait for next check cycle
    time.sleep(0.3)

    assert len(shutdown_reasons) == 1, "Watchdog must trigger cascade shutdown on explicit server shutdown status"
    assert "SERVER_EXPLICIT_SHUTDOWN" in shutdown_reasons[0]
    watchdog.stop()


def test_watchdog_detects_server_offline(mock_server):
    url, handler = mock_server
    shutdown_reasons: List[str] = []

    watchdog = ServerShutdownWatchdog(
        command_node_url=url,
        agent_id="test-agent-3",
        check_interval=0.08,
        max_consecutive_failures=3,
        initial_connection_timeout=2.0,
        on_server_shutdown=lambda r: shutdown_reasons.append(r),
    )
    watchdog.start()
    time.sleep(0.2)
    assert watchdog.is_connected

    # Server drops / becomes unreachable
    handler.should_drop = True

    # 3 failures * 0.08s = ~0.24s
    time.sleep(0.5)

    assert len(shutdown_reasons) == 1, "Watchdog must trigger cascade shutdown when server is unreachable"
    assert "SERVER_UNREACHABLE" in shutdown_reasons[0]
    watchdog.stop()


def test_watchdog_tolerates_transient_failures(mock_server):
    url, handler = mock_server
    shutdown_reasons: List[str] = []

    watchdog = ServerShutdownWatchdog(
        command_node_url=url,
        agent_id="test-agent-4",
        check_interval=0.08,
        max_consecutive_failures=4,
        initial_connection_timeout=2.0,
        on_server_shutdown=lambda r: shutdown_reasons.append(r),
    )
    watchdog.start()
    time.sleep(0.15)
    assert watchdog.is_connected

    # Simulate 1 transient failure, then recover
    handler.should_drop = True
    time.sleep(0.1)  # 1 failure
    handler.should_drop = False
    time.sleep(0.2)  # recovered

    assert len(shutdown_reasons) == 0, "Transient network hiccups below threshold must not trigger shutdown"
    assert watchdog._consecutive_failures == 0, "Failures must be reset upon successful check"
    watchdog.stop()


def test_action_consumer_executes_shutdown_agent():
    daemon = ActionConsumerDaemon(
        agent_id="test-agent-5",
        command_node_url="http://127.0.0.1:8000",
    )
    res = daemon.execute_action({
        "action_id": "act-test-shutdown-1",
        "action_type": "SHUTDOWN_AGENT",
        "parameters": {"reason": "main_server_shutdown"},
    })

    assert res.get("status") == "success"
    assert "initiated" in res.get("message", "").lower()
