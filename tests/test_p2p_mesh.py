"""
tests/test_p2p_mesh.py
========================
Tests for AEGIS Layer 2 Peer-to-Peer Consensus Voting Protocol (agent/p2p_mesh.py).
"""

import time
import pytest

from agent.p2p_mesh import (
    ConsensusVerdict,
    P2PMeshNode,
    PeerCorrelationEngine,
    VotingRequest,
    VotingResponse,
    WeightedConsensusAggregator,
)


class TestP2PProtocolSchemas:
    """Test message serialization and schema validation."""

    def test_voting_request_serialization(self):
        req = VotingRequest(
            vote_id="v123",
            origin_agent_id="vm1",
            event_type="network",
            threat_score=0.85,
            confidence=0.90,
            details={"port": 443, "dest_ip": "10.0.0.1"},
        )
        d = req.to_dict()
        assert d["vote_id"] == "v123"
        assert d["origin_agent_id"] == "vm1"
        assert d["threat_score"] == 0.85

        reconstructed = VotingRequest.from_dict(d)
        assert reconstructed.vote_id == req.vote_id
        assert reconstructed.origin_agent_id == req.origin_agent_id
        assert reconstructed.details == req.details

    def test_voting_response_serialization(self):
        resp = VotingResponse(
            vote_id="v123",
            peer_agent_id="vm2",
            peer_trust_score=0.8,
            correlated=True,
            peer_vote_score=0.85,
        )
        d = resp.to_dict()
        assert d["peer_agent_id"] == "vm2"
        assert d["correlated"] is True

        reconstructed = VotingResponse.from_dict(d)
        assert reconstructed.vote_id == resp.vote_id
        assert reconstructed.peer_trust_score == 0.8
        assert reconstructed.correlated is True


class TestPeerCorrelationEngine:
    """Test correlation matching logic across network, process, and file events."""

    def test_network_correlation_match(self):
        engine = PeerCorrelationEngine(buffer_ttl_seconds=10.0)
        engine.record_local_event("network", {"port": 8080, "dest_ip": "192.168.1.50"})

        req = VotingRequest(
            vote_id="v1",
            origin_agent_id="vm1",
            event_type="network",
            threat_score=0.8,
            confidence=0.9,
            details={"port": 8080, "dest_ip": "192.168.1.50"},
        )

        is_corr, score = engine.check_correlation(req)
        assert is_corr is True
        assert score == 0.8

    def test_process_correlation_match(self):
        engine = PeerCorrelationEngine(buffer_ttl_seconds=10.0)
        engine.record_local_event("process_linux", {"process": "nc", "pid": 1337})

        req = VotingRequest(
            vote_id="v2",
            origin_agent_id="vm1",
            event_type="process_linux",
            threat_score=0.75,
            confidence=0.85,
            details={"process": "nc", "pid": 1337},
        )

        is_corr, score = engine.check_correlation(req)
        assert is_corr is True

    def test_no_correlation_match(self):
        engine = PeerCorrelationEngine(buffer_ttl_seconds=10.0)
        engine.record_local_event("network", {"port": 53, "dest_ip": "8.8.8.8"})

        req = VotingRequest(
            vote_id="v3",
            origin_agent_id="vm1",
            event_type="network",
            threat_score=0.9,
            confidence=0.95,
            details={"port": 443, "dest_ip": "1.1.1.1"},
        )

        is_corr, score = engine.check_correlation(req)
        assert is_corr is False
        assert score == pytest.approx(0.45, abs=1e-3)


class TestWeightedConsensusAggregator:
    """Test trust multipliers and final severity classification."""

    def test_weight_multipliers(self):
        calc = WeightedConsensusAggregator.calculate_weight

        # 2.0x: High trust + correlated
        assert calc(0.8, is_correlated=True) == pytest.approx(1.6, abs=1e-3)

        # 1.0x: High trust uncorrelated OR standard trust correlated
        assert calc(0.8, is_correlated=False) == pytest.approx(0.8, abs=1e-3)
        assert calc(0.5, is_correlated=True) == pytest.approx(0.5, abs=1e-3)

        # 0.5x: Standard trust uncorrelated
        assert calc(0.5, is_correlated=False) == pytest.approx(0.25, abs=1e-3)

        # 0.3x: Low trust (<0.4)
        assert calc(0.3, is_correlated=False) == pytest.approx(0.09, abs=1e-3)

    def test_aggregation_verdict(self):
        agg = WeightedConsensusAggregator()
        req = VotingRequest(
            vote_id="v99",
            origin_agent_id="vm1",
            event_type="network",
            threat_score=0.9,
            confidence=0.9,
        )

        resp1 = VotingResponse(
            vote_id="v99",
            peer_agent_id="vm2",
            peer_trust_score=0.8,
            correlated=True,
            peer_vote_score=0.85,
        )
        resp2 = VotingResponse(
            vote_id="v99",
            peer_agent_id="vm3",
            peer_trust_score=0.5,
            correlated=False,
            peer_vote_score=0.2,
        )

        verdict = agg.aggregate(req, [resp1, resp2], origin_trust=1.0)
        assert isinstance(verdict, ConsensusVerdict)
        assert verdict.consensus_reached is True
        assert verdict.participating_peers == 2
        assert verdict.severity in ("HIGH", "CRITICAL")


class TestP2PMeshNodeIntegration:
    """Integration test for 3 nodes communicating over UDP socket mesh."""

    def test_three_node_consensus_mesh(self, tmp_path):
        db1 = tmp_path / "t1.db"
        db2 = tmp_path / "t2.db"
        db3 = tmp_path / "t3.db"

        node1 = P2PMeshNode(agent_id="node1", bind_port=9201)
        node2 = P2PMeshNode(agent_id="node2", bind_port=9202)
        node3 = P2PMeshNode(agent_id="node3", bind_port=9203)

        node1.start()
        node2.start()
        node3.start()

        try:
            node1.register_peer("node2", "127.0.0.1", 9202)
            node1.register_peer("node3", "127.0.0.1", 9203)

            node2.register_peer("node1", "127.0.0.1", 9201)
            node3.register_peer("node1", "127.0.0.1", 9201)

            # Record correlated event on node2
            node2.correlation_engine.record_local_event(
                "network", {"port": 22, "dest_ip": "10.0.0.5"}
            )

            verdict = node1.initiate_vote(
                event_type="network",
                threat_score=0.88,
                confidence=0.95,
                details={"port": 22, "dest_ip": "10.0.0.5"},
                timeout=1.5,
            )

            assert verdict.origin_agent_id == "node1"
            assert verdict.participating_peers == 2
            assert verdict.severity in ("HIGH", "CRITICAL")
            assert verdict.consensus_reached is True

        finally:
            node1.stop()
            node2.stop()
            node3.stop()
