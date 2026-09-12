"""
tests/test_remote_action_dispatcher.py
======================================
Comprehensive tests for AEGIS Autonomous Remote Command Dispatcher:
- Manual enqueueing and execution ACK via API endpoints
- Auto-enqueuing of mitigation actions upon Critical / High Consensus Verdicts
- End-to-end hands-free loop: Detection -> Centralized Vote -> Auto Dispatch -> Local Consumer Execution -> Central Audit Log
"""

import time
import httpx
import pytest

from backend.telemetry_api import app
from agent.action_consumer import ActionConsumerDaemon
from agent.response_driver import AgentResponseDriver


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ===========================================================================
# 1. Manual Action Enqueue, Pending Query, and ACK via HTTP Endpoints
# ===========================================================================
@pytest.mark.anyio
async def test_manual_action_enqueue_and_ack_endpoints():
    """Test manual /api/actions/enqueue, pending query, and ACK via HTTP."""
    agent_id = f"test-agent-{int(time.time())}"
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Enqueue manual action
        resp = await client.post("/api/actions/enqueue", json={
            "agent_id": agent_id,
            "action_type": "ALERT",
            "parameters": {"message": "Test security alert"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        action = data["action"]
        action_id = action["action_id"]
        assert action["agent_id"] == agent_id
        assert action["action_type"] == "ALERT"
        assert action["status"] == "PENDING"

        # 2. Fetch pending actions for agent (transitions to DISPATCHED)
        resp_pending = await client.get(f"/api/agents/{agent_id}/actions/pending")
        assert resp_pending.status_code == 200
        p_data = resp_pending.json()
        assert p_data["agent_id"] == agent_id
        actions = [a for a in p_data["actions"] if a["action_id"] == action_id]
        assert len(actions) == 1
        assert actions[0]["action_type"] == "ALERT"
        assert actions[0]["status"] == "DISPATCHED"

        # 3. Ack the action execution
        resp_ack = await client.post(f"/api/agents/{agent_id}/actions/{action_id}/ack", json={
            "status": "SUCCESS",
            "result_details": {"acknowledged": True, "action": "ALERT"},
        })
        assert resp_ack.status_code == 200
        ack_data = resp_ack.json()
        assert ack_data["status"] == "acknowledged"
        assert ack_data["execution_status"] == "SUCCESS"

        # 4. Verify in /api/actions list
        resp_all = await client.get(f"/api/actions?agent_id={agent_id}")
        assert resp_all.status_code == 200
        actions_list = resp_all.json()["actions"]
        matching = [a for a in actions_list if a["action_id"] == action_id]
        assert len(matching) == 1
        assert matching[0]["status"] == "SUCCESS"
        assert matching[0]["executed_at"] is not None


# ===========================================================================
# 2. Auto-Dispatch on Critical Consensus Verdict
# ===========================================================================
@pytest.mark.anyio
async def test_auto_dispatch_on_critical_vote():
    """Test that POST /api/centralized/vote automatically dispatches a RemoteAction."""
    agent_id = f"vm-ransomware-{int(time.time())}"
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "origin_agent_id": agent_id,
            "event_type": "process_windows",
            "threat_score": 0.99,
            "confidence": 0.95,
            "details": {
                "process": "cryptolocker.exe",
                "pid": 5432,
                "target_file": "C:\\malware\\cryptolocker.exe",
                "severity": "CRITICAL",
            },
        }

        resp = await client.post("/api/centralized/vote", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        verdict = data["verdict"]

        # Verdict should indicate containment action
        assert verdict["response_action"] in ("KILL_PROCESS", "ISOLATE_HOST", "QUARANTINE_FILE")

        # Dispatched action must be returned
        dispatched = data.get("dispatched_action")
        assert dispatched is not None
        assert dispatched["agent_id"] == agent_id
        assert dispatched["action_type"] == verdict["response_action"]
        assert dispatched["status"] == "PENDING"
        assert dispatched["target_pid"] == 5432 or dispatched["target_file"] is not None

        # Fetch pending for that agent
        resp_pending = await client.get(f"/api/agents/{agent_id}/actions/pending")
        assert resp_pending.status_code == 200
        pending_actions = resp_pending.json()["actions"]
        matching = [a for a in pending_actions if a["action_id"] == dispatched["action_id"]]
        assert len(matching) == 1


# ===========================================================================
# 3. Autonomous Hands-Free Loop (Consumer Daemon Integration)
# ===========================================================================
@pytest.mark.anyio
async def test_autonomous_hands_free_loop():
    """
    Simulate entire autonomous hands-free loop:
    1. Agent submits threat telemetry / vote
    2. Command Node reaches consensus and automatically dispatches command
    3. ActionConsumerDaemon consumes and executes locally
    4. ActionConsumerDaemon sends ACK back
    5. Action status and NeonDB AuditLog are updated
    """
    agent_id = f"vm-handsfree-{int(time.time())}"
    driver = AgentResponseDriver()
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Step 1: Centralized vote triggers auto-dispatch of action
        vote_payload = {
            "origin_agent_id": agent_id,
            "event_type": "process_windows",
            "threat_score": 0.95,
            "confidence": 0.90,
            "details": {
                "process": "test_trojan.exe",
                "pid": 9876,
                "target_file": "scratch/test_trojan.exe",
            },
        }
        vote_resp = await client.post("/api/centralized/vote", json=vote_payload)
        assert vote_resp.status_code == 200
        vote_data = vote_resp.json()
        action_id = vote_data["dispatched_action"]["action_id"]
        assert action_id is not None

        # Step 2: Consumer daemon polls and executes hands-free
        # We adapt consumer to use the async client's synchronous equivalent or mock session
        class AsyncSessionAdapter:
            def get(self, url, **kwargs):
                path = "/" + url.split("://", 1)[1].split("/", 1)[1]
                # Synchronous response wrapper around ASGI call
                class RespWrapper:
                    def __init__(self, data, code):
                        self._data = data
                        self.status_code = code
                        self.text = str(data)

                    def json(self):
                        return self._data

                import asyncio
                res = asyncio.run(client.get(path))
                return RespWrapper(res.json(), res.status_code)

            def post(self, url, json=None, **kwargs):
                path = "/" + url.split("://", 1)[1].split("/", 1)[1]
                class RespWrapper:
                    def __init__(self, data, code):
                        self._data = data
                        self.status_code = code
                        self.text = str(data)

                    def json(self):
                        return self._data

                import asyncio
                res = asyncio.run(client.post(path, json=json))
                return RespWrapper(res.json(), res.status_code)

        # Better: execute the action directly using ActionConsumerDaemon logic on the client
        pending_resp = await client.get(f"/api/agents/{agent_id}/actions/pending")
        assert pending_resp.status_code == 200
        pending_actions = pending_resp.json().get("actions", [])
        assert len(pending_actions) >= 1

        consumer = ActionConsumerDaemon(agent_id=agent_id, command_node_url="http://test")
        executed_results = []
        for act in pending_actions:
            res = consumer.execute_action(act)
            raw_status = res.get("status", "failed").lower()
            status = "SUCCESS" if raw_status in ("success", "alert_raised", "not_found") else (
                "SIMULATED_SUCCESS" if raw_status == "simulated_success" else "FAILED"
            )
            ack_resp = await client.post(
                f"/api/agents/{agent_id}/actions/{act['action_id']}/ack",
                json={"status": status, "result_details": res},
            )
            assert ack_resp.status_code == 200
            executed_results.append(res)

        assert len(executed_results) >= 1

        # Step 3: Verify the action is marked SUCCESS on Command Node
        resp_all = await client.get(f"/api/actions?agent_id={agent_id}")
        assert resp_all.status_code == 200
        matching_actions = [a for a in resp_all.json()["actions"] if a["action_id"] == action_id]
        assert len(matching_actions) == 1
        assert matching_actions[0]["status"] in ("SUCCESS", "SIMULATED_SUCCESS")
        assert matching_actions[0]["executed_at"] is not None

        # Step 4: Verify audit log on Command Node contains the executed action
        resp_audit = await client.get(f"/api/audit?agent_id={agent_id}")
        assert resp_audit.status_code == 200
        audit_entries = resp_audit.json()["logs"]
        assert len(audit_entries) >= 1
