"""
tests/test_centralized_server.py
==================================
Tests for AEGIS Centralized Command Node & Telemetry/Voting Coordinator
(backend/command_node.py & backend/telemetry_api.py).
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.command_node import CentralizedTelemetryRepository, CentralizedVotingCoordinator
from backend.telemetry_api import app


class TestCentralizedTelemetryRepository:
    """Test storage, filtering, and aggregate statistics of CentralizedTelemetryRepository."""

    def test_add_and_query_telemetry(self):
        repo = CentralizedTelemetryRepository(max_capacity=50)
        repo.add_telemetry({
            "agent_id": "vm1",
            "event_type": "network",
            "threat_score": 0.85,
            "details": {"port": 443, "dest_ip": "10.0.0.1"},
        })
        repo.add_telemetry({
            "agent_id": "vm2",
            "event_type": "process_linux",
            "threat_score": 0.15,
            "details": {"process": "ls", "pid": 101},
        })

        # Test filter by agent_id
        vm1_events = repo.query_telemetry(agent_id="vm1")
        assert len(vm1_events) == 1
        assert vm1_events[0]["agent_id"] == "vm1"
        assert vm1_events[0]["threat_score"] == 0.85

        # Test filter by min_score
        high_threats = repo.query_telemetry(min_score=0.50)
        assert len(high_threats) == 1
        assert high_threats[0]["agent_id"] == "vm1"

    def test_repository_stats(self):
        repo = CentralizedTelemetryRepository()
        repo.add_telemetry({"agent_id": "vm1", "event_type": "network", "threat_score": 0.90})
        repo.add_telemetry({"agent_id": "vm2", "event_type": "file", "threat_score": 0.20})

        stats = repo.get_stats()
        assert stats["total_events"] == 2
        assert stats["active_agents"] == 2
        assert stats["critical_threat_events"] == 1


class TestCentralizedVotingCoordinator:
    """Test cross-agent correlation, weighted consensus, and response action mapping."""

    def test_process_vote_request_with_correlation(self):
        repo = CentralizedTelemetryRepository()
        coordinator = CentralizedVotingCoordinator(repository=repo)

        # Store prior event on vm2
        repo.add_telemetry({
            "agent_id": "vm2",
            "event_type": "network",
            "threat_score": 0.80,
            "details": {"port": 443, "dest_ip": "172.16.255.36"},
            "timestamp": time.time() - 5,
        })

        # vm1 submits voting request for matching port 443
        verdict = coordinator.process_vote_request(
            event_type="network",
            origin_agent_id="vm1",
            threat_score=0.88,
            details={"port": 443, "dest_ip": "172.16.255.36"},
        )

        assert verdict["origin_agent_id"] == "vm1"
        assert verdict["participating_peers"] == 1
        assert verdict["severity"] == "CRITICAL"
        assert verdict["response_action"] == "ISOLATE_HOST"

    def test_response_action_mapping(self):
        repo = CentralizedTelemetryRepository()
        coordinator = CentralizedVotingCoordinator(repository=repo)

        # Low score -> LOG
        res_low = coordinator.process_vote_request(
            event_type="log_line",
            origin_agent_id="vm1",
            threat_score=0.10,
        )
        assert res_low["severity"] == "LOW"
        assert res_low["response_action"] == "LOG"

        # High score -> KILL_PROCESS
        res_high = coordinator.process_vote_request(
            event_type="process_windows",
            origin_agent_id="vm1",
            threat_score=0.72,
        )
        assert res_high["severity"] == "HIGH"
        assert res_high["response_action"] == "KILL_PROCESS"


class TestCentralizedFastAPIEndpoints:
    """Test REST API routes for centralized server."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_post_centralized_vote_endpoint(self, client):
        payload = {
            "origin_agent_id": "vm1",
            "event_type": "network",
            "threat_score": 0.85,
            "details": {"port": 80, "dest_ip": "192.168.1.1"},
        }
        response = client.post("/api/centralized/vote", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "verdict" in data
        assert data["verdict"]["origin_agent_id"] == "vm1"
        assert data["verdict"]["response_action"] in ("HIGH", "CRITICAL", "KILL_PROCESS", "ISOLATE_HOST")

    def test_get_centralized_telemetry_endpoint(self, client):
        response = client.get("/api/centralized/telemetry?min_score=0.0")
        assert response.status_code == 200
        data = response.json()
        assert "telemetries" in data
        assert "count" in data

    def test_get_centralized_stats_endpoint(self, client):
        response = client.get("/api/centralized/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_events" in data
        assert "active_agents" in data
        assert "critical_threat_events" in data

    def test_get_centralized_verdicts_endpoint(self, client):
        response = client.get("/api/centralized/verdicts")
        assert response.status_code == 200
        data = response.json()
        assert "verdicts" in data
