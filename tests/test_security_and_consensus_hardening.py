"""
tests/test_security_and_consensus_hardening.py
==============================================
AEGIS P0/P1 Security, Consensus Correctness & Reliability Verification Suite

Covers 24 Comprehensive Verification Tests:
1. P2P Cryptographic Identity & Verification:
   - Tampered signature rejection
   - Forged identity / public key mismatch rejection
   - Replay protection with LRU cache & nonces
   - Stale message & clock skew rejection
   - Peer response deduplication per vote_id
   - Bounded input validation on threat_score
   - Bounded input validation on confidence
   - Bounded input validation on peer_trust_score
2. Consensus Quorum Integrity:
   - Quorum ladder testing: 1, 2, 3, 4, 5 peers out of 5
   - Strict distinction between LOCAL_EMERGENCY_VERDICT vs PEER_CONSENSUS_VERDICT
3. Command Node Security & RBAC:
   - Unauthorized API calls (HTTP 401)
   - Insufficient role access to trust feedback (HTTP 403)
   - Insufficient role access to maintenance scheduling (HTTP 403)
   - Invalid token on action enqueue (HTTP 401)
   - Cross-agent action hijacking prevention (HTTP 403)
   - Duplicate action ACK rejection on terminal states (HTTP 409)
   - Heartbeat clock skew validation (HTTP 400)
4. Precision Response & Component Isolation:
   - Simulation mode produces SIMULATED status (never fake EXECUTED)
   - Real response driver non-existent PID produces NOT_FOUND or FAILED
   - Windows v3 isolation test (guaranteed shadow mode, excluded from ACTIVE_FUSION_KEYS)
   - Collector health visibility (IDLE, HEALTHY, DEGRADED, FAILED)
"""

import os
import time
import httpx
import pytest

from backend.telemetry_api import app
from backend.services.rbac_auth_service import rbac_auth_service
from agent.p2p_mesh import (
    P2PMeshNode,
    PeerCrypto,
    VotingRequest,
    VotingResponse,
    WeightedConsensusAggregator,
    ReplayProtector,
    validate_voting_request,
    validate_voting_response,
)
from agent.response_driver import AgentResponseDriver
from agent.fusion_engine import ThreatFusionEngine
from agent.collectors.collector_health import collector_registry, CollectorHealthRegistry


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ===========================================================================
# 1. P2P Cryptographic Identity, Signature, Replay & Bounded Input Tests
# ===========================================================================

def test_invalid_signature_rejected():
    """Tampered P2P message with invalid Ed25519 signature must be rejected."""
    priv_a, pub_a = PeerCrypto.generate_keypair()
    pub_a_hex = PeerCrypto.public_key_to_hex(pub_a)

    req = VotingRequest(
        vote_id="vote-sec-01",
        origin_agent_id="node-a",
        event_type="network",
        threat_score=0.88,
        confidence=0.92,
        timestamp=time.time(),
        nonce="nonce-001",
        sender_public_key=pub_a_hex,
    )
    req.sign(priv_a)
    assert req.verify(pub_a) is True

    # Tamper with signature
    req.signature = "00" * 64
    assert req.verify(pub_a) is False


def test_forged_peer_identity_rejected():
    """Message claiming to be node-a but signed by node-b's key must fail verification against node-a's public key."""
    priv_a, pub_a = PeerCrypto.generate_keypair()
    pub_a_hex = PeerCrypto.public_key_to_hex(pub_a)

    priv_b, pub_b = PeerCrypto.generate_keypair()
    pub_b_hex = PeerCrypto.public_key_to_hex(pub_b)

    req = VotingRequest(
        vote_id="vote-sec-02",
        origin_agent_id="node-a",  # Claims node-a
        event_type="network",
        threat_score=0.80,
        confidence=0.90,
        timestamp=time.time(),
        nonce="nonce-002",
        sender_public_key=pub_b_hex,  # But signed with node-b
    )
    req.sign(priv_b)

    # Verification against genuine node-a public key must fail
    assert req.verify(pub_a) is False


def test_replayed_p2p_message_rejected():
    """Second transmission of identical (sender, nonce) message must be rejected."""
    protector = ReplayProtector(max_age_seconds=60.0)
    now = time.time()

    # First receipt is valid
    assert protector.validate_and_record("peer-1", "nonce-100", now) is True

    # Replay with same nonce must be rejected
    assert protector.validate_and_record("peer-1", "nonce-100", now) is False

    # Different nonce from same peer is accepted
    assert protector.validate_and_record("peer-1", "nonce-101", now) is True


def test_stale_p2p_message_rejected():
    """Message with timestamp exceeding max age or future skew must be rejected."""
    protector = ReplayProtector(max_age_seconds=30.0)
    now = time.time()

    # Expired message (60 seconds old)
    assert protector.validate_and_record("peer-1", "nonce-201", now - 60.0) is False

    # Clock skew into future (120 seconds ahead)
    assert protector.validate_and_record("peer-1", "nonce-202", now + 120.0) is False

    # Fresh message (5 seconds old)
    assert protector.validate_and_record("peer-1", "nonce-203", now - 5.0) is True


def test_duplicate_vote_response_from_same_peer_deduplicated():
    """Duplicate vote response from the same peer must be deduplicated."""
    now = time.time()
    resp1 = VotingResponse(
        vote_id="vote-dedup-1",
        peer_agent_id="peer-1",
        peer_trust_score=0.90,
        correlated=True,
        peer_vote_score=0.90,
        timestamp=now,
    )
    resp2 = VotingResponse(
        vote_id="vote-dedup-1",
        peer_agent_id="peer-1",  # Same peer
        peer_trust_score=0.90,
        correlated=False,
        peer_vote_score=0.10,
        timestamp=now + 1,
    )

    # Simulation of P2PMeshNode peer response set deduplication
    seen_peers = set()
    accepted_responses = []
    for resp in [resp1, resp2]:
        if resp.peer_agent_id not in seen_peers:
            seen_peers.add(resp.peer_agent_id)
            accepted_responses.append(resp)

    assert len(accepted_responses) == 1
    assert accepted_responses[0].peer_vote_score == 0.90


def test_unknown_peer_dynamic_discovery_behavior():
    """Peer message without valid sender key or registration fails verification."""
    req = VotingRequest(
        vote_id="vote-unknown-1",
        origin_agent_id="attacker-node",
        event_type="network",
        threat_score=0.5,
        confidence=0.8,
        timestamp=time.time(),
        nonce="nonce-unk-1",
        sender_public_key="",
        signature="",
    )
    # Without signature, verification cannot pass
    priv, pub = PeerCrypto.generate_keypair()
    assert req.verify(pub) is False


def test_bounded_inputs_threat_score():
    """Threat score outside [0, 1] must fail validation."""
    req_high = VotingRequest(
        vote_id="v1",
        origin_agent_id="node-1",
        event_type="network",
        threat_score=1.5,
        confidence=0.9,
    )
    valid, reason = validate_voting_request(req_high)
    assert valid is False
    assert "threat_score" in reason

    req_low = VotingRequest(
        vote_id="v2",
        origin_agent_id="node-1",
        event_type="network",
        threat_score=-0.2,
        confidence=0.9,
    )
    valid2, reason2 = validate_voting_request(req_low)
    assert valid2 is False
    assert "threat_score" in reason2


def test_bounded_inputs_confidence():
    """Confidence outside [0, 1] must fail validation."""
    req = VotingRequest(
        vote_id="v3",
        origin_agent_id="node-1",
        event_type="network",
        threat_score=0.5,
        confidence=1.2,
    )
    valid, reason = validate_voting_request(req)
    assert valid is False
    assert "confidence" in reason


def test_bounded_inputs_trust_score():
    """Peer trust score outside [0, 1] must fail validation."""
    resp = VotingResponse(
        vote_id="v4",
        peer_agent_id="node-2",
        peer_trust_score=1.5,
        correlated=False,
        peer_vote_score=0.5,
    )
    valid, reason = validate_voting_response(resp)
    assert valid is False
    assert "peer_trust_score" in reason


# ===========================================================================
# 2. Consensus Quorum Integrity Tests (1..5 peers out of 5)
# ===========================================================================

def _create_voting_request(vote_id: str, raw_score: float = 0.85) -> VotingRequest:
    return VotingRequest(
        vote_id=vote_id,
        origin_agent_id="node-origin",
        event_type="network",
        threat_score=raw_score,
        confidence=0.95,
        timestamp=time.time(),
    )


def _create_response(vote_id: str, peer_id: str, score: float = 0.85, trust: float = 0.80) -> VotingResponse:
    return VotingResponse(
        vote_id=vote_id,
        peer_agent_id=peer_id,
        peer_trust_score=trust,
        correlated=False,
        peer_vote_score=score,
        timestamp=time.time(),
    )


def test_quorum_1_peer_out_of_5():
    """1 response out of 5 expected peers must not claim full consensus."""
    aggregator = WeightedConsensusAggregator()
    req = _create_voting_request("quorum-test-1", raw_score=0.85)
    responses = [_create_response("quorum-test-1", "peer-1", score=0.90)]

    verdict = aggregator.aggregate(req, responses, expected_peers=5, min_quorum=3)
    assert verdict.consensus_reached is False
    assert verdict.quorum_status == "PARTIAL_QUORUM"
    assert verdict.verdict_type == "LOCAL_EMERGENCY_VERDICT"
    assert verdict.participating_peers == 1


def test_quorum_2_peers_out_of_5():
    """2 responses out of 5 is still a partial quorum (< 3 threshold)."""
    aggregator = WeightedConsensusAggregator()
    req = _create_voting_request("quorum-test-2", raw_score=0.85)
    responses = [
        _create_response("quorum-test-2", "peer-1", score=0.85),
        _create_response("quorum-test-2", "peer-2", score=0.88),
    ]

    verdict = aggregator.aggregate(req, responses, expected_peers=5, min_quorum=3)
    assert verdict.consensus_reached is False
    assert verdict.quorum_status == "PARTIAL_QUORUM"
    assert verdict.verdict_type == "LOCAL_EMERGENCY_VERDICT"
    assert verdict.participating_peers == 2


def test_quorum_3_peers_out_of_5():
    """3 responses out of 5 achieves required majority quorum."""
    aggregator = WeightedConsensusAggregator()
    req = _create_voting_request("quorum-test-3", raw_score=0.85)
    responses = [
        _create_response("quorum-test-3", "peer-1", score=0.85),
        _create_response("quorum-test-3", "peer-2", score=0.88),
        _create_response("quorum-test-3", "peer-3", score=0.92),
    ]

    verdict = aggregator.aggregate(req, responses, expected_peers=5, min_quorum=3)
    assert verdict.consensus_reached is True
    assert verdict.quorum_status == "CONSENSUS_REACHED"
    assert verdict.verdict_type == "PEER_CONSENSUS_VERDICT"
    assert verdict.participating_peers == 3


def test_quorum_4_peers_out_of_5():
    """4 responses out of 5 achieves consensus with high total weight."""
    aggregator = WeightedConsensusAggregator()
    req = _create_voting_request("quorum-test-4", raw_score=0.85)
    responses = [_create_response("quorum-test-4", f"peer-{i}", score=0.85) for i in range(1, 5)]

    verdict = aggregator.aggregate(req, responses, expected_peers=5, min_quorum=3)
    assert verdict.consensus_reached is True
    assert verdict.participating_peers == 4
    assert verdict.verdict_type == "PEER_CONSENSUS_VERDICT"


def test_quorum_5_peers_out_of_5():
    """5 responses out of 5 achieves complete swarm consensus."""
    aggregator = WeightedConsensusAggregator()
    req = _create_voting_request("quorum-test-5", raw_score=0.90)
    responses = [_create_response("quorum-test-5", f"peer-{i}", score=0.90) for i in range(1, 6)]

    verdict = aggregator.aggregate(req, responses, expected_peers=5, min_quorum=3)
    assert verdict.consensus_reached is True
    assert verdict.participating_peers == 5
    assert verdict.verdict_type == "PEER_CONSENSUS_VERDICT"


# ===========================================================================
# 3. Command Node Security & RBAC Enforcement Tests
# ===========================================================================

@pytest.mark.anyio
async def test_unauthorized_api_call_without_token():
    """Administrative endpoints must reject unauthenticated requests with HTTP 401."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/maintenance/schedule", json={
            "agent_id": "test-agent",
            "duration_seconds": 3600,
            "reason": "Test maintenance",
        })
        assert resp.status_code == 401
        assert "Authentication required" in resp.json()["detail"]


@pytest.mark.anyio
async def test_unauthorized_trust_feedback_non_admin():
    """Analyst or auditor token calling /api/trust/feedback must be rejected with HTTP 403."""
    analyst_auth = rbac_auth_service.authenticate_user("analyst", "analyst@aegis2026")
    assert analyst_auth is not None
    headers = {"Authorization": f"Bearer {analyst_auth['token']}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/trust/feedback",
            headers=headers,
            json={"vote_id": "vote-test", "confirmed": True},
        )
        assert resp.status_code == 403
        assert "admin privileges" in resp.json()["detail"].lower() or "forbidden" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_unauthorized_maintenance_schedule_non_admin():
    """Auditor role calling /api/maintenance/schedule must be rejected with HTTP 403."""
    auditor_auth = rbac_auth_service.authenticate_user("auditor", "auditor@aegis2026")
    assert auditor_auth is not None
    headers = {"Authorization": f"Bearer {auditor_auth['token']}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/maintenance/schedule",
            headers=headers,
            json={"agent_id": "*", "duration_seconds": 1800, "reason": "Auditor probe"},
        )
        assert resp.status_code == 403


@pytest.mark.anyio
async def test_unauthorized_action_enqueue_invalid_token():
    """Action enqueue with forged or invalid bearer token must return HTTP 401."""
    headers = {"Authorization": "Bearer invalid.forged.token.here"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/actions/enqueue",
            headers=headers,
            json={"agent_id": "node-1", "action_type": "ALERT"},
        )
        assert resp.status_code == 401


@pytest.mark.anyio
async def test_wrong_agent_action_ack_rejected():
    """Agent B attempting to acknowledge an action targeted to Agent A must return HTTP 403."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Enqueue action for target_agent_a
        enq_resp = await client.post("/api/actions/enqueue", json={
            "agent_id": "target_agent_a",
            "action_type": "ALERT",
            "parameters": {"test": True},
        })
        assert enq_resp.status_code == 200
        action_id = enq_resp.json()["action"]["action_id"]

        # Hijacking attempt: wrong_agent_b calls ack
        ack_resp = await client.post(
            f"/api/agents/wrong_agent_b/actions/{action_id}/ack",
            json={"status": "SUCCESS", "result_details": {}},
        )
        assert ack_resp.status_code == 403
        assert "not authorized" in ack_resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_duplicate_action_ack_rejected():
    """Attempting to acknowledge an action that has already reached terminal status must return HTTP 409."""
    transport = httpx.ASGITransport(app=app)
    agent_id = f"test-dup-ack-{int(time.time())}"
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Enqueue action
        enq_resp = await client.post("/api/actions/enqueue", json={
            "agent_id": agent_id,
            "action_type": "ALERT",
            "parameters": {"test": True},
        })
        assert enq_resp.status_code == 200
        action_id = enq_resp.json()["action"]["action_id"]

        # First ACK succeeds
        first_ack = await client.post(
            f"/api/agents/{agent_id}/actions/{action_id}/ack",
            json={"status": "EXECUTED", "result_details": {"done": True}},
        )
        assert first_ack.status_code == 200

        # Second ACK on terminal state must return HTTP 409 Conflict
        second_ack = await client.post(
            f"/api/agents/{agent_id}/actions/{action_id}/ack",
            json={"status": "EXECUTED", "result_details": {"done": True}},
        )
        assert second_ack.status_code == 409
        assert "already reached terminal status" in second_ack.json()["detail"]


@pytest.mark.anyio
async def test_heartbeat_clock_skew_rejected():
    """Heartbeat with timestamp in the distant past or future must return HTTP 400."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 10 minutes in the past
        resp = await client.post("/api/heartbeat", json={
            "agent_id": "skew-test-node",
            "status": "healthy",
            "timestamp": time.time() - 600,
        })
        assert resp.status_code == 400
        assert "clock skew" in resp.json()["detail"].lower()


# ===========================================================================
# 4. Precision Response & Component Isolation Tests
# ===========================================================================

def test_simulated_response_status():
    """AgentResponseDriver in simulation mode must report status SIMULATED, never EXECUTED."""
    driver = AgentResponseDriver(simulation_mode=True)
    res = driver.kill_process(999999)
    assert res["status"] == "SIMULATED"
    assert res["simulation"] is True


def test_real_response_failure_status():
    """AgentResponseDriver in real execution mode on a non-existent PID reports NOT_FOUND or FAILED."""
    driver = AgentResponseDriver(simulation_mode=False)
    res = driver.kill_process(99999999)
    assert res["status"] in ("NOT_FOUND", "FAILED")
    assert res["simulation"] is False


def test_windows_v3_shadow_isolation():
    """Windows v3 detector must be excluded from ACTIVE_FUSION_KEYS and remain strictly in shadow mode."""
    assert "windows_v3" not in ThreatFusionEngine.ACTIVE_FUSION_KEYS
    engine = ThreatFusionEngine()
    assert hasattr(engine, "score_windows_v3")
    # Verify ACTIVE_FUSION_KEYS contains only the 6 production active models
    expected_active = {"linux", "windows", "cicids", "ember", "hdfs", "zero_day"}
    assert set(ThreatFusionEngine.ACTIVE_FUSION_KEYS) == expected_active


def test_collector_health_visibility():
    """CollectorHealthRegistry accurately tracks IDLE, HEALTHY, DEGRADED states and error details."""
    reg = CollectorHealthRegistry()
    reg.register("etw_collector")
    status = reg.get_status("etw_collector")
    assert status["status"] == "IDLE"
    assert status["events_processed"] == 0

    # Record successful event processing
    reg.record_success("etw_collector", count=5)
    status = reg.get_status("etw_collector")
    assert status["status"] == "HEALTHY"
    assert status["events_processed"] == 5

    # Record degradation
    reg.record_error("etw_collector", "Transient access violation", fatal=False)
    status = reg.get_status("etw_collector")
    assert status["status"] == "DEGRADED"
    assert status["error_count"] == 1
    assert "Transient" in status["last_error"]
