"""
tests/test_gaps_e2e_verification.py
====================================
End-to-End verification of the 3 identified gaps in the AEGIS system:
1. Live detection auto-triggering peer voting for scores >= 0.30 (MEDIUM, HIGH, CRITICAL).
2. P2P and Centralized consensus linkage, database persistence, deduplication, and automated action enqueueing.
3. Registered peer handling, quorum state tracking, missing response handling, and critical emergency fallback.
"""
import pytest
from starlette.testclient import TestClient
from backend.telemetry_api import app, central_coordinator
from agent.p2p_mesh import (
    WeightedConsensusAggregator,
    VotingRequest,
    VotingResponse,
    P2PMeshNode,
)
from agent.run_all import _trigger_peer_voting_async, _vote_cooldown, _vote_lock


class TestGap1LiveDetectionTrigger:
    """Gap 1: Auto-triggering peer voting for threat scores >= 0.30."""

    def test_cooldown_and_trigger_deduplication(self):
        with _vote_lock:
            _vote_cooldown.clear()

        # Score >= 0.30 triggers voting
        _trigger_peer_voting_async(
            model="cicids",
            score=0.85,
            verdict="CRITICAL",
            extra={"destination_port": 443, "ip": "10.0.0.5"}
        )
        with _vote_lock:
            assert any("cicids:port=443" in k for k in _vote_cooldown)

        # Immediate repeat should be suppressed by cooldown cache
        count_before = len(_vote_cooldown)
        _trigger_peer_voting_async(
            model="cicids",
            score=0.85,
            verdict="CRITICAL",
            extra={"destination_port": 443, "ip": "10.0.0.5"}
        )
        with _vote_lock:
            assert len(_vote_cooldown) == count_before


class TestGap2P2PCentralizedLinkageAndDeduplication:
    """Gap 2: P2P to Centralized persistence, deduplication, and auto-mitigation."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_p2p_consensus_forwarding_and_deduplication(self, client):
        vote_id = "test-gap2-vote"
        p2p_payload = {
            "vote_id": vote_id,
            "origin_agent_id": "agent-alpha",
            "event_type": "process_windows",
            "raw_threat_score": 0.92,
            "final_weighted_score": 0.94,
            "severity": "CRITICAL",
            "response_action": "ISOLATE_HOST",
            "consensus_reached": True,
            "participating_peers": 2,
            "total_weight": 2.5,
            "quorum_status": "CONSENSUS_REACHED",
            "verdict_type": "PEER_CONSENSUS_VERDICT",
            "peer_votes": [
                {"peer_agent_id": "peer-1", "peer_vote_score": 0.90, "weight": 1.0, "correlated": True},
                {"peer_agent_id": "peer-2", "peer_vote_score": 0.95, "weight": 1.5, "correlated": True},
            ],
            "details": {"process": "mimikatz.exe", "pid": 4040},
        }

        # 1. Post P2P Consensus verdict
        res1 = client.post("/api/p2p/consensus", json=p2p_payload)
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["status"] == "published"
        assert data1["vote_id"] == vote_id
        assert data1.get("dispatched_action") is not None
        assert data1["dispatched_action"]["action_type"] == "ISOLATE_HOST"

        # 2. Verify coordinator recorded the external verdict in memory
        recorded = [v for v in central_coordinator._verdicts_history if v.get("vote_id") == vote_id]
        assert len(recorded) >= 1
        assert recorded[0]["severity"] == "CRITICAL"

        # 3. Call centralized vote endpoint with the same vote_id
        # Must return the existing consensus verdict without duplicate re-voting
        vote_payload = {
            "vote_id": vote_id,
            "origin_agent_id": "agent-alpha",
            "event_type": "process_windows",
            "threat_score": 0.92,
            "details": {"process": "mimikatz.exe", "pid": 4040},
        }
        res2 = client.post("/api/centralized/vote", json=vote_payload)
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["status"] == "success"
        assert data2["verdict"]["vote_id"] == vote_id
        assert data2["verdict"]["final_weighted_score"] == 0.94

        # 4. Verify GET /api/voting/latest returns this verdict
        res_latest = client.get("/api/voting/latest")
        assert res_latest.status_code == 200
        latest_data = res_latest.json()
        assert latest_data["status"] == "success"
        assert latest_data["verdict"]["vote_id"] == vote_id


class TestGap3QuorumAndEmergencyHandling:
    """Gap 3: Quorum states, registered peers, missing responses, and emergency verdicts."""

    def test_missing_responses_emergency_vs_insufficient(self):
        agg = WeightedConsensusAggregator()

        # Case A: Critical threat without quorum -> LOCAL_EMERGENCY_VERDICT
        critical_req = VotingRequest(
            vote_id="emerg-1",
            origin_agent_id="node1",
            event_type="network",
            threat_score=0.95,
        )
        # Expected peers = 3, but 0 responses received
        v_emerg = agg.aggregate(critical_req, responses=[], expected_peers=3, min_quorum=2)
        assert v_emerg.consensus_reached is False
        assert v_emerg.quorum_status == "NO_QUORUM"
        assert v_emerg.verdict_type == "LOCAL_EMERGENCY_VERDICT"
        assert v_emerg.severity == "CRITICAL"

        # Case B: Medium non-critical threat without quorum -> INSUFFICIENT_QUORUM
        medium_req = VotingRequest(
            vote_id="med-1",
            origin_agent_id="node1",
            event_type="network",
            threat_score=0.45,
        )
        v_med = agg.aggregate(medium_req, responses=[], expected_peers=3, min_quorum=2)
        assert v_med.consensus_reached is False
        assert v_med.quorum_status == "NO_QUORUM"
        assert v_med.verdict_type == "INSUFFICIENT_QUORUM"
        assert v_med.severity == "MEDIUM"

        # Case C: Quorum satisfied -> PEER_CONSENSUS_VERDICT with peer vote details
        resp1 = VotingResponse(
            vote_id="conf-1",
            peer_agent_id="node2",
            peer_trust_score=0.8,
            correlated=True,
            peer_vote_score=0.90,
        )
        resp2 = VotingResponse(
            vote_id="conf-1",
            peer_agent_id="node3",
            peer_trust_score=0.7,
            correlated=True,
            peer_vote_score=0.85,
        )
        v_conf = agg.aggregate(critical_req, responses=[resp1, resp2], expected_peers=3, min_quorum=2)
        assert v_conf.consensus_reached is True
        assert v_conf.quorum_status == "CONSENSUS_REACHED"
        assert v_conf.verdict_type == "PEER_CONSENSUS_VERDICT"
        assert len(v_conf.peer_votes) == 2
        assert v_conf.peer_votes[0]["peer_agent_id"] == "node2"
        assert v_conf.peer_votes[0]["weight"] > 0
