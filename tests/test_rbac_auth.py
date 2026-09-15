import pytest
from fastapi.testclient import TestClient
from backend.telemetry_api import app
from backend.services.rbac_auth_service import RBACAuthService, rbac_auth_service


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_rbac_auth_user_authentication():
    svc = RBACAuthService()
    
    # Successful login
    auth = svc.authenticate_user("admin", "aegis@admin2026")
    assert auth is not None
    assert auth["role"] == "admin"
    assert "token" in auth

    # Bad password
    bad_auth = svc.authenticate_user("admin", "wrong_password")
    assert bad_auth is None


def test_rbac_role_authorization_hierarchy():
    svc = RBACAuthService()
    admin_auth = svc.authenticate_user("admin", "aegis@admin2026")
    analyst_auth = svc.authenticate_user("analyst", "analyst@aegis2026")
    auditor_auth = svc.authenticate_user("auditor", "auditor@aegis2026")

    # Admin has access to admin, analyst, and auditor capabilities
    assert svc.authorize_role(admin_auth["token"], "admin") is True
    assert svc.authorize_role(admin_auth["token"], "analyst") is True
    assert svc.authorize_role(admin_auth["token"], "auditor") is True

    # Analyst has access to analyst and auditor, but not admin
    assert svc.authorize_role(analyst_auth["token"], "admin") is False
    assert svc.authorize_role(analyst_auth["token"], "analyst") is True
    assert svc.authorize_role(analyst_auth["token"], "auditor") is True

    # Auditor only has auditor capability
    assert svc.authorize_role(auditor_auth["token"], "admin") is False
    assert svc.authorize_role(auditor_auth["token"], "analyst") is False
    assert svc.authorize_role(auditor_auth["token"], "auditor") is True


def test_agent_token_generation_and_verification():
    svc = RBACAuthService()
    agent_info = svc.generate_agent_key("vm99-linux", cluster_id="test-cluster")
    assert agent_info["agent_id"] == "vm99-linux"
    assert "token" in agent_info

    # Valid token verification
    assert svc.verify_agent_token("vm99-linux", agent_info["token"]) is True
    # Invalid token verification
    assert svc.verify_agent_token("vm99-linux", "invalid-fake-token") is False


def test_rbac_api_login_and_me(client):
    # Login as analyst
    res = client.post("/api/auth/login", json={
        "username": "analyst",
        "password": "analyst@aegis2026"
    })
    assert res.status_code == 200
    token = res.json()["token"]

    # Verify identity via /api/auth/me
    res_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res_me.status_code == 200
    assert res_me.json()["user"]["sub"] == "analyst"
    assert res_me.json()["user"]["role"] == "analyst"


def test_rbac_agent_token_issue_endpoint(client):
    # Login as admin
    res_login = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "aegis@admin2026"
    })
    admin_token = res_login.json()["token"]

    # Issue agent token
    res = client.post(
        "/api/auth/tokens/agent",
        json={"agent_id": "test-agent-01"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 200
    assert res.json()["agent_id"] == "test-agent-01"
    assert "token" in res.json()
