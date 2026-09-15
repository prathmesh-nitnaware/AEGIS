import pytest
from fastapi.testclient import TestClient
from backend.telemetry_api import app
from backend.services.threat_intel_service import ThreatIntelService, threat_intel_service


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_threat_intel_default_feeds():
    svc = ThreatIntelService()
    indicators = svc.list_indicators()
    assert len(indicators) >= 4
    
    # Check pre-seeded APT29 C2
    hit_ip = svc.check_ioc("ip", "198.51.100.24")
    assert hit_ip is not None
    assert hit_ip["matched"] is True
    assert "APT29" in hit_ip["threat_actor"]


def test_threat_intel_stix_bundle_import():
    svc = ThreatIntelService()
    sample_stix_bundle = {
        "type": "bundle",
        "id": "bundle--12345",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "name": "LockBit Ingress Gateway",
                "pattern": "[ipv4-addr:value = '192.0.2.100']",
                "labels": ["ransomware", "lockbit"]
            },
            {
                "type": "indicator",
                "id": "indicator--2",
                "name": "Malicious Dropper Domain",
                "pattern": "[domain-name:value = 'evil-c2.darkweb.onion']",
                "labels": ["c2"]
            },
            {
                "type": "indicator",
                "id": "indicator--3",
                "name": "Cobalt Strike Stager",
                "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
                "labels": ["stager"]
            }
        ]
    }
    res = svc.import_stix_bundle(sample_stix_bundle)
    assert res["imported_count"] == 3
    
    # Verify lookups
    assert svc.check_ioc("ip", "192.0.2.100") is not None
    assert svc.check_ioc("domain", "evil-c2.darkweb.onion") is not None
    assert svc.check_ioc("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is not None


def test_threat_intel_cidr_subnet_matching():
    svc = ThreatIntelService()
    # 203.0.113.0/24 is pre-seeded
    hit = svc.check_ioc("ip", "203.0.113.45")
    assert hit is not None
    assert hit["matched"] is True
    assert hit["type"] == "ip_cidr"


def test_threat_intel_api_endpoints(client):
    # GET list
    res = client.get("/api/intel/indicators")
    assert res.status_code == 200
    assert "indicators" in res.json()

    # POST lookup positive
    res_lookup = client.post("/api/intel/lookup", json={
        "type": "ip",
        "value": "198.51.100.24"
    })
    assert res_lookup.status_code == 200
    assert res_lookup.json()["matched"] is True

    # POST lookup negative
    res_clean = client.post("/api/intel/lookup", json={
        "type": "ip",
        "value": "8.8.8.8"
    })
    assert res_clean.status_code == 200
    assert res_clean.json()["matched"] is False
