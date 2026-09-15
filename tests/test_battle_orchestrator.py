"""
tests/test_battle_orchestrator.py
=================================
Test suite for AEGIS Automated Red vs. Blue Live Battle Campaign Orchestrator.
Verifies 5-phase kill-chain execution, defender latency metrics, autonomous mitigations,
and FastAPI REST API endpoints.
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.services.battle_orchestrator import BattleOrchestrator
from backend.telemetry_api import app


@pytest.fixture
def orchestrator():
    return BattleOrchestrator()


@pytest.fixture
def client():
    return TestClient(app)


def test_battle_orchestrator_full_campaign(orchestrator):
    """Verify execution of full 5-phase adversary kill-chain and defender metrics."""
    assert orchestrator.is_running is False
    assert len(orchestrator.phase_results) == 0

    # Run synchronously with 0 delay for fast automated testing
    success = orchestrator.start_battle(
        target_agent_id="endpoint-linux",
        target_ip="172.30.0.21",
        step_delay=0.0,
        async_run=False,
    )
    assert success is True
    assert orchestrator.is_running is False
    assert len(orchestrator.phase_results) == 5

    # Verify Phase 1: Reconnaissance
    p1 = orchestrator.phase_results[0]
    assert p1.phase_number == 1
    assert "Reconnaissance" in p1.phase_name
    assert p1.threat_score >= 0.90
    assert p1.mitigation_action == "RATE_LIMIT_FIREWALL"
    assert p1.detection_latency_us > 0

    # Verify Phase 2: Initial Access
    p2 = orchestrator.phase_results[1]
    assert p2.phase_number == 2
    assert "Initial Access" in p2.phase_name
    assert p2.severity == "CRITICAL"
    assert p2.mitigation_action == "DROP_SRC_IP_FIREWALL"

    # Verify Phase 3: Privilege Escalation
    p3 = orchestrator.phase_results[2]
    assert p3.phase_number == 3
    assert "Privilege Escalation" in p3.phase_name
    assert p3.severity == "CRITICAL"
    assert p3.mitigation_action == "KILL_PROCESS"

    # Verify Phase 4: Ransomware Dropper
    p4 = orchestrator.phase_results[3]
    assert p4.phase_number == 4
    assert "Ransomware" in p4.phase_name
    assert p4.severity == "CRITICAL"
    assert p4.mitigation_action == "ISOLATE_HOST"

    # Verify Phase 5: Defense Evasion & Silence Sabotage
    p5 = orchestrator.phase_results[4]
    assert p5.phase_number == 5
    assert "Defense Evasion" in p5.phase_name
    assert p5.severity == "CRITICAL"
    assert p5.mitigation_action == "SILENCE_AS_ALARM_BROADCAST"

    # Verify Defender KPIs
    kpis = orchestrator.kpis
    assert kpis.completed_phases == 5
    assert kpis.avg_detection_latency_us > 0
    assert kpis.autonomous_processes_killed >= 2
    assert kpis.autonomous_hosts_isolated >= 1
    assert kpis.firewall_rules_injected >= 2
    assert kpis.pdf_report_generated is True
    assert len(orchestrator.logs) >= 5


def test_battle_orchestrator_stop(orchestrator):
    """Verify clean abortion of active campaign."""
    orchestrator.is_running = True
    orchestrator.stop_battle()
    assert orchestrator.is_running is False
    assert orchestrator.completed_at is not None


def test_battle_api_endpoints(client):
    """Verify /api/battle/start, /api/battle/status, and /api/battle/stop."""
    # 1. Get initial status
    res_status = client.get("/api/battle/status")
    assert res_status.status_code == 200
    data = res_status.json()
    assert "is_running" in data
    assert "kpis" in data

    # 2. Start battle
    res_start = client.post("/api/battle/start", json={"target_agent_id": "vm2-windows", "step_delay": 0.05})
    assert res_start.status_code in (200, 409)

    # 3. Stop battle
    res_stop = client.post("/api/battle/stop")
    assert res_stop.status_code == 200
    assert res_stop.json()["status"] == "stopped"


def test_alert_dispatcher_api_endpoints(client):
    """Verify /api/alerts/config and /api/alerts/dispatch-test."""
    # 1. Get config
    res_cfg = client.get("/api/alerts/config")
    assert res_cfg.status_code == 200
    assert "destinations" in res_cfg.json()

    # 2. Add destination
    res_set = client.post(
        "/api/alerts/config",
        json={
            "name": "test_slack_channel",
            "type": "slack",
            "config": {"webhook_url": "https://hooks.slack.com/test"},
            "min_severity": "HIGH",
        },
    )
    assert res_set.status_code == 200
    assert res_set.json()["status"] == "configured"

    # 3. Trigger test dispatch
    res_disp = client.post(
        "/api/alerts/dispatch-test",
        json={"event_type": "unit_test_event", "severity": "CRITICAL", "threat_score": 0.99},
    )
    assert res_disp.status_code == 200
    assert res_disp.json()["status"] == "dispatched"
