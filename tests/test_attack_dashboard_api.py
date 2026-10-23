"""
tests/test_attack_dashboard_api.py
==================================
Unit and Integration tests for AEGIS Adversary C2 Attack Dashboard Endpoints.
Verifies:
1. Target discovery (GET /api/attack/targets)
2. Target probing & port scanning (POST /api/attack/probe)
3. Custom payload templates (GET /api/attack/payloads)
4. Interactive C2 CLI execution (POST /api/attack/command)
5. Exploit launch & status polling (POST /api/attack/launch & GET /api/attack/status)
6. Campaign report export (GET /api/attack/export)
"""

import pytest
from fastapi.testclient import TestClient
from backend.telemetry_api import app


@pytest.fixture
def client():
    return TestClient(app)


def test_get_attack_targets(client):
    res = client.get("/api/attack/targets")
    assert res.status_code == 200
    targets = res.json()
    assert isinstance(targets, list)
    assert len(targets) >= 3
    target_ids = [t["id"] for t in targets]
    assert "node1-linux" in target_ids
    assert "node2-windows" in target_ids


def test_probe_attack_target(client):
    res = client.post("/api/attack/probe", json={"ip": "127.0.0.1", "port": 8000})
    assert res.status_code == 200
    data = res.json()
    assert "target_ip" in data
    assert "status" in data
    assert "avg_latency_ms" in data


def test_get_attack_payloads(client):
    res = client.get("/api/attack/payloads")
    assert res.status_code == 200
    payloads = res.json()
    assert isinstance(payloads, list)
    payload_ids = [p["id"] for p in payloads]
    assert "meterpreter_linux_x64" in payload_ids
    assert "ransomware_pe_dropper" in payload_ids


def test_run_attack_c2_commands(client):
    # Test 'help'
    res_help = client.post("/api/attack/command", json={"command": "help"})
    assert res_help.status_code == 200
    assert "AEGIS Adversary C2" in res_help.json()["output"]

    # Test 'targets'
    res_targets = client.post("/api/attack/command", json={"command": "targets"})
    assert res_targets.status_code == 200
    assert "AVAILABLE SWARM TARGETS" in res_targets.json()["output"]

    # Test 'config'
    res_cfg = client.post("/api/attack/command", json={"command": "config concurrency 15"})
    assert res_cfg.status_code == 200
    assert "concurrency = 15" in res_cfg.json()["output"]


def test_attack_lifecycle(client):
    # Reset
    res_reset = client.post("/api/attack/reset")
    assert res_reset.status_code == 200

    # Status check
    res_status = client.get("/api/attack/status")
    assert res_status.status_code == 200
    st = res_status.json()
    assert "is_running" in st
    assert "victim_feedback" in st

    # Launch exploit
    res_launch = client.post(
        "/api/attack/launch",
        json={
            "scenario": "graceful",
            "target_id": "node1-linux",
            "target_ip": "10.0.0.10",
            "custom_config": {"intensity": "stealth"},
        },
    )
    assert res_launch.status_code == 200
    assert res_launch.json()["status"] in ("started", "busy")


def test_export_campaign_report(client):
    res = client.get("/api/attack/export")
    assert res.status_code == 200
    rep = res.json()
    assert "markdown" in rep
    assert "stats" in rep
    assert "# AEGIS Red Team Adversary C2" in rep["markdown"]
