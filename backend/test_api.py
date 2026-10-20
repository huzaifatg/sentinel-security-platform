import os
os.environ["DATABASE_URL"] = "sqlite:///./test-sentinel.db"
os.environ["JWT_SECRET"] = "test-secret"

from fastapi.testclient import TestClient
from backend.database import Base, engine
from backend.main import app

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
