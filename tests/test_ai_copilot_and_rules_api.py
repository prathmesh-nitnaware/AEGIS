import pytest
from fastapi.testclient import TestClient
from backend.telemetry_api import app
from backend.services.ai_copilot_service import ai_copilot_service


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_ai_copilot_service_ransomware_synthesis():
    incident_data = {
        "threat_score": 0.95,
        "verdict": "CRITICAL",
        "mitre_technique": "T1486",
        "node_id": "vm2-windows",
        "sigma_matches": [{"title": "VSSADMIN Shadow Copies Deletion"}],
        "yara_matches": [{"rule": "Ransomware_Readme_Note"}],
        "xai_features": [{"feature": "Shannon Entropy", "importance": 0.45}]
    }
    result = ai_copilot_service.generate_incident_investigation(incident_data)
    
    assert "INC-" in result["incident_id"]
    assert result["verdict"] == "CRITICAL"
    assert result["mitre_technique"] == "T1486"
    assert "VSSADMIN" in result["executive_summary"]
    assert len(result["recommended_containment_steps"]) >= 3
    assert "Stop-Process" in result["playbooks"]["powershell_script"]
    assert "iptables" in result["playbooks"]["bash_script"]
    assert len(result["forensic_checklist"]) >= 2


def test_ai_copilot_service_ptrace_synthesis():
    incident_data = {
        "threat_score": 0.88,
        "verdict": "HIGH",
        "mitre_technique": "T1055",
        "node_id": "endpoint-linux"
    }
    result = ai_copilot_service.generate_incident_investigation(incident_data)
    assert result["mitre_technique"] == "T1055"
    assert "sysctl -w kernel.yama.ptrace_scope" in result["playbooks"]["bash_script"]


def test_api_copilot_analyze_endpoint(client):
    res = client.post("/api/copilot/analyze", json={
        "threat_score": 0.90,
        "verdict": "CRITICAL",
        "mitre_technique": "T1486",
        "node_id": "endpoint-windows"
    })
    assert res.status_code == 200
    data = res.json()
    assert "executive_summary" in data
    assert "playbooks" in data


def test_api_sigma_compile_endpoint(client):
    yaml_content = """
id: TEST-API-SIGMA-01
title: API Test Rule
level: medium
logsource:
  category: process_creation
detection:
  selection:
    image|endswith: 'notepad.exe'
  condition: selection
"""
    res = client.post("/api/rules/sigma/compile", json={"yaml": yaml_content})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "compiled"
    assert data["rule_id"] == "TEST-API-SIGMA-01"


def test_api_yara_compile_endpoint(client):
    res = client.post("/api/rules/yara/compile", json={
        "name": "API_Test_Yara_Rule",
        "strings_dict": {"$a": "test_malware_pattern"},
        "condition": "any of them"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "compiled"
    assert data["rule_name"] == "API_Test_Yara_Rule"


def test_api_stress_test_endpoint(client):
    res = client.post("/api/benchmark/stress-test", json={
        "target_rate": 5000,
        "duration": 0.2,
        "threads": 2
    })
    assert res.status_code == 200
    data = res.json()
    assert data["total_generated"] > 0
    assert "latency_us" in data


def test_api_flamegraph_endpoint(client):
    res = client.get("/api/benchmark/flamegraph")
    assert res.status_code == 200
    assert "image/svg+xml" in res.headers["content-type"]
    assert "<svg" in res.text
