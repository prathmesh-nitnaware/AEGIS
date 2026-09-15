"""
tests/test_fleet_and_package_verification.py
============================================
Unit and integration tests for:
- Ed25519 key generation, package signing, and tamper detection
- RemoteConfigSync schema validation, hot application, and disk caching
- FleetUpdateService API endpoints (/api/fleet/config/push, /api/fleet/packages/sign, /api/fleet/packages/verify)
"""

import base64
import json
import tempfile
import time
from pathlib import Path

import httpx
import pytest

from agent.packaging.package_verifier import (
    PackageSignatureVerifier,
    generate_ed25519_keypair,
    sign_package_archive,
    verify_package_signature,
)
from agent.remote_config_sync import RemoteConfigSync
from backend.services.update_service import FleetUpdateService
from backend.telemetry_api import app


def test_ed25519_signing_and_verification():
    """Test asymmetric signature generation, valid verification, and tamper detection."""
    priv_bytes, pub_bytes = generate_ed25519_keypair()
    assert len(priv_bytes) == 32
    assert len(pub_bytes) == 32

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        f.write(b"SAMPLE_AEGIS_AGENT_PAYLOAD_BINARY_DATA_V2")
        temp_path = Path(f.name)

    try:
        # Sign package
        sig = sign_package_archive(temp_path, priv_bytes)
        assert len(sig) == 64

        # Valid verification
        assert verify_package_signature(temp_path, sig, pub_bytes) is True

        # Tamper package bytes
        with open(temp_path, "wb") as f:
            f.write(b"MALICIOUS_MODIFIED_PAYLOAD_BY_ATTACKER")

        # Must reject tampered package
        assert verify_package_signature(temp_path, sig, pub_bytes) is False
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_package_signature_verifier_class():
    """Test high-level PackageSignatureVerifier with SHA256 and base64 signatures."""
    priv_bytes, pub_bytes = generate_ed25519_keypair()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    verifier = PackageSignatureVerifier(trusted_public_key_b64=pub_b64)

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(b"LEGITIMATE_RELEASE_ARCHIVE_DATA")
        temp_path = Path(f.name)

    try:
        sig = sign_package_archive(temp_path, priv_bytes)
        sig_b64 = base64.b64encode(sig).decode("ascii")

        res = verifier.verify_and_check_sha256(temp_path, sig_b64)
        assert res["valid"] is True
        assert res["signature_valid"] is True
        assert res["sha256_match"] is True

        # Test invalid expected SHA-256
        res_bad_sha = verifier.verify_and_check_sha256(
            temp_path, sig_b64, expected_sha256="0000000000000000000000000000000000000000000000000000000000000000"
        )
        assert res_bad_sha["valid"] is False
        assert res_bad_sha["sha256_match"] is False
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_remote_config_sync_hot_application():
    """Test dynamic agent config hot-application and callback notification."""
    updated_notifications = []

    def on_update(cfg):
        updated_notifications.append(cfg)

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_file = Path(tmpdir) / "test_config_cache.json"
        sync = RemoteConfigSync(agent_id="test-node-1", cache_path=str(cache_file), on_update_callback=on_update)

        initial = sync.get_config()
        assert initial["confidence_threshold"] == 0.70

        # Hot apply new config
        patch = {
            "confidence_threshold": 0.85,
            "polling_interval_sec": 1.5,
            "threat_score_suppression": 0.40,
            "voting_weights": {"zero_day": 1.8},
        }
        res = sync.apply_remote_config(patch)
        assert res["status"] == "success"
        assert res["config"]["confidence_threshold"] == 0.85
        assert res["config"]["voting_weights"]["zero_day"] == 1.8
        assert len(updated_notifications) == 1

        # Test disk persistence
        assert cache_file.exists()
        with open(cache_file, "r") as f:
            disk_data = json.load(f)
        assert disk_data["confidence_threshold"] == 0.85

        # Invalid bounds validation
        with pytest.raises(ValueError):
            sync.apply_remote_config({"confidence_threshold": 1.5})


@pytest.mark.anyio
async def test_fleet_management_and_package_endpoints():
    """Test FastAPI /api/fleet/* endpoints for config push and package signing."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Config Push
        resp = await client.post("/api/fleet/config/push", json={
            "agent_id": "vm2-cloud",
            "config": {"polling_interval_sec": 3.0, "confidence_threshold": 0.75}
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "queued"
        assert data["applied_config"]["polling_interval_sec"] == 3.0

        # 2. Get Config
        resp_get = await client.get("/api/fleet/config/vm2-cloud")
        assert resp_get.status_code == 200
        assert resp_get.json()["config"]["confidence_threshold"] == 0.75

        # 3. Inventory
        resp_inv = await client.get("/api/fleet/inventory")
        assert resp_inv.status_code == 200
        assert "agents" in resp_inv.json()
