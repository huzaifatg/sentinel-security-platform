import os
os.environ["DATABASE_URL"] = "sqlite:///./test-sentinel.db"
os.environ["JWT_SECRET"] = "test-secret"

from fastapi.testclient import TestClient
from backend.database import Base, engine
from backend.main import app
from backend.risk import assess, severity_for

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
client = TestClient(app)


def register(email: str) -> str:
    response = client.post("/api/v1/auth/register", json={"email": email, "password": "correct horse battery"})
    assert response.status_code == 201
    login = client.post("/api/v1/auth/login", data={"username": email, "password": "correct horse battery"})
    assert login.status_code == 200
    return login.json()["access_token"]


def test_auth_and_validation() -> None:
    token = register("alice@example.com")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.post("/api/v1/auth/register", json={"email": "bad", "password": "short"}).status_code == 422


def test_risk_assessment_returns_findings_and_score() -> None:
    token = register("risk@example.com")
    response = client.post(
        "/api/v1/risk/assess",
        headers={"Authorization": f"Bearer {token}"},
        json={"asset_id": "laptop-1", "signals": {"disk_encryption_disabled": True, "mfa_disabled": True}},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] == 40
    assert body["security_score"] == 60
    assert body["severity"] == "medium"
    assert {finding["rule"] for finding in body["findings"]} == {"disk_encryption_disabled", "mfa_disabled"}


def test_risk_assessment_requires_authentication() -> None:
    response = client.post("/api/v1/risk/assess", json={"asset_id": "laptop-1", "signals": {}})
    assert response.status_code == 401


def test_device_ownership_and_telemetry() -> None:
    alice = register("owner@example.com")
    bob = register("other@example.com")
    created = client.post("/api/v1/devices", headers={"Authorization": f"Bearer {alice}"}, json={"name": "Laptop", "serial_number": "A-1"})
    device_id = created.json()["id"]
    assert client.get(f"/api/v1/devices/{device_id}", headers={"Authorization": f"Bearer {bob}"}).status_code == 404
    ingest = client.post(f"/api/v1/devices/{device_id}/telemetry", headers={"Authorization": f"Bearer {alice}"}, json={"event_type": "login", "payload": {"source": "test"}})
    assert ingest.status_code == 201
    assert client.get(f"/api/v1/devices/{device_id}/telemetry", headers={"Authorization": f"Bearer {bob}"}).status_code == 404
    assert client.get(f"/api/v1/devices/{device_id}/telemetry", headers={"Authorization": f"Bearer {alice}"}).json()[0]["payload"] == {"source": "test"}


def test_risk_boundaries_caps_and_evidence() -> None:
    all_signals = {key: True for key in ("disk_encryption_disabled", "unusual_login", "firewall_disabled", "operating_system_outdated", "mfa_disabled", "unknown_device")}
    score, findings = assess("workstation-1", all_signals)
    assert score == 100
    assert severity_for(score).value == "critical"
    assert all(finding.evidence.startswith("signal:") for finding in findings)
    assert all(finding.severity.value == "critical" for finding in findings)

    score, findings = assess("workstation-1", {"mfa_disabled": True, "unknown_device": True})
    assert score == 25
    assert severity_for(score).value == "low"
    assert {finding.rule for finding in findings} == {"mfa_disabled", "unknown_device"}

    score, findings = assess("workstation-1", {"mfa_disabled": True, "unknown_device": True, "ignored": True})
    assert score == 25
    assert len(findings) == 2


def test_severity_boundaries_are_inclusive() -> None:
    assert severity_for(30).value == "low"
    assert severity_for(31).value == "medium"
    assert severity_for(60).value == "medium"
    assert severity_for(61).value == "high"
    assert severity_for(80).value == "high"
    assert severity_for(81).value == "critical"
