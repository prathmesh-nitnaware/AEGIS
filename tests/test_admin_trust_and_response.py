"""
tests/test_admin_trust_and_response.py
========================================
Tests for AEGIS Phase 4 Admin Trust System, Maintenance Window Portal,
and Local Agent Active Response Enforcement Driver.
"""

import os
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from agent.admin_trust import AdminTrustEngine, IdentityContext, MaintenanceWindowPortal
from agent.response_driver import AgentResponseDriver
from backend.telemetry_api import app


class TestAdminTrustEngine:
    """Test identity context and maintenance window suppression logic."""

    def test_maintenance_window_suppression(self):
        portal = MaintenanceWindowPortal()
        engine = AdminTrustEngine(portal=portal)

        win = portal.schedule_window(
            agent_id="vm1",
            duration_seconds=300.0,
            approved_by="sec_admin",
            reason="Routine OS Patching",
        )

        is_supp, score, reason = engine.evaluate_event(
            agent_id="vm1",
            event_type="process_linux",
            raw_threat_score=0.90,
        )

        assert is_supp is True
        assert score == 0.0
        assert win.window_id in reason

    def test_admin_process_downgrade(self):
        portal = MaintenanceWindowPortal()
        engine = AdminTrustEngine(portal=portal)

        admin_identity = IdentityContext(user_id="1000", username="root", is_admin=True)

        is_supp, score, reason = engine.evaluate_event(
            agent_id="vm2",
            event_type="process_windows",
            raw_threat_score=0.80,
            identity=admin_identity,
            process_name="msiexec.exe",
        )

        assert is_supp is True
        assert score == pytest.approx(0.16, abs=1e-3)
        assert "Approved admin tool" in reason

    def test_maintenance_cancellation(self):
        portal = MaintenanceWindowPortal()
        win = portal.schedule_window(
            agent_id="vm1",
            duration_seconds=100.0,
            approved_by="admin",
            reason="Test",
        )

        in_maint_before, _ = portal.is_in_maintenance("vm1")
        assert in_maint_before is True

        portal.cancel_window(win.window_id)

        in_maint_after, _ = portal.is_in_maintenance("vm1")
        assert in_maint_after is False


class TestAgentResponseDriver:
    """Test local response enforcement actions (LOG, ALERT, KILL_PROCESS, QUARANTINE_FILE, ISOLATE_HOST)."""

    def test_audit_logging(self, tmp_path):
        audit_file = tmp_path / "audit.log"
        driver = AgentResponseDriver(audit_log_path=str(audit_file))

        res = driver.log_action("LOG", {"event": "test_event"})
        assert res["status"] == "success"
        assert audit_file.exists()

    def test_quarantine_file(self, tmp_path):
        q_dir = tmp_path / "quarantine"
        driver = AgentResponseDriver(quarantine_dir=str(q_dir))

        sample_file = tmp_path / "malicious.exe"
        sample_file.write_text("MZ malware payload")

        assert sample_file.exists()

        res = driver.quarantine_file(str(sample_file))
        assert res["status"] == "success"
        assert not sample_file.exists()
        assert Path(res["quarantine_path"]).exists()

    def test_isolate_host_and_unisolate(self, tmp_path):
        driver = AgentResponseDriver()
        res_iso = driver.isolate_host()
        assert res_iso["status"] in ("success", "simulated_success")
        assert driver.is_isolated is True

        res_uniso = driver.unisolate_host()
        assert res_uniso["status"] == "success"
        assert driver.is_isolated is False


class TestMaintenancePortalFastAPIEndpoints:
    """Test REST APIs for maintenance window portal."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_schedule_and_list_maintenance_windows(self, client):
        payload = {
            "agent_id": "vm1",
            "duration_seconds": 600,
            "approved_by": "admin_unit_test",
            "reason": "Pytest Maintenance Window",
        }
        res_sched = client.post("/api/maintenance/schedule", json=payload)
        assert res_sched.status_code == 200
        sched_data = res_sched.json()
        assert sched_data["status"] == "scheduled"
        window_id = sched_data["window"]["window_id"]

        res_list = client.get("/api/maintenance/windows")
        assert res_list.status_code == 200
        windows = res_list.json()["windows"]
        assert any(w["window_id"] == window_id for w in windows)

        res_cancel = client.delete(f"/api/maintenance/cancel?window_id={window_id}")
        assert res_cancel.status_code == 200
        assert res_cancel.json()["status"] == "cancelled"
