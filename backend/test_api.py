import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./test-sentinel.db"
os.environ["JWT_SECRET"] = "test-secret"

from fastapi.testclient import TestClient
import pytest

from backend.anomaly import FeatureValidationError, ModelUnavailableError, infer, train_model
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


def anomaly_features(hour: int = 9, attempts: int = 0, new: bool = False, network: bool = False) -> dict[str, int | bool]:
    return {"login_hour": hour, "failed_attempts": attempts, "new_device": new, "network_change": network}


def test_anomaly_model_training_inference_and_failures(tmp_path: Path) -> None:
    model_path = tmp_path / "isolation-forest.joblib"
    rows = [anomaly_features(hour) for hour in range(8, 16)]
    metadata = train_model(rows, model_path)
    assert metadata["feature_count"] == 4
    result = infer(anomaly_features(23, 5, True, True), model_path)
    assert result.model_version == "isolation-forest-v1"
    assert isinstance(result.is_anomaly, bool)
    assert isinstance(result.score, float)
    with pytest.raises(FeatureValidationError):
        infer({"login_hour": 9}, model_path)
    with pytest.raises(ModelUnavailableError):
        infer(anomaly_features(), tmp_path / "missing.joblib")
    model_path.write_text("not a model")
    with pytest.raises(ModelUnavailableError):
        infer(anomaly_features(), model_path)


def test_anomaly_api_training_detection_and_cross_user_access(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import backend.main as main_module

    monkeypatch.setattr(main_module, "MODEL_PATH", tmp_path / "isolation-forest.joblib")
    alice = register("anomaly-owner@example.com")
    bob = register("anomaly-other@example.com")
    device = client.post("/api/v1/devices", headers={"Authorization": f"Bearer {alice}"}, json={"name": "Anomaly laptop", "serial_number": "AN-1"}).json()
    trained = client.post("/api/v1/anomalies/model/train", headers={"Authorization": f"Bearer {alice}"}, json={})
    assert trained.status_code == 200
    detected = client.post("/api/v1/anomalies/events", headers={"Authorization": f"Bearer {alice}"}, json={"device_id": device["id"], "features": anomaly_features(23, 5, True, True)})
    assert detected.status_code == 201
    event_id = detected.json()["id"]
    assert client.get("/api/v1/anomalies/events", headers={"Authorization": f"Bearer {alice}"}).json()[0]["id"] == event_id
    assert client.get("/api/v1/anomalies/events", headers={"Authorization": f"Bearer {bob}"}).json() == []
    assert client.post("/api/v1/anomalies/events", headers={"Authorization": f"Bearer {bob}"}, json={"device_id": device["id"], "features": anomaly_features()}).status_code == 404


def test_simulation_is_deterministic_owner_scoped_and_non_mutating() -> None:
    alice = register("simulation-owner@example.com")
    bob = register("simulation-other@example.com")
    payload = {"asset_id": "workstation-1", "current_signals": {"mfa_disabled": True, "disk_encryption_disabled": True}, "changes": {"mfa_enabled": True}}
    before = client.post("/api/v1/risk/assess", headers={"Authorization": f"Bearer {alice}"}, json={"asset_id": "workstation-1", "signals": payload["current_signals"]}).json()
    created = client.post("/api/v1/simulations", headers={"Authorization": f"Bearer {alice}"}, json=payload)
    assert created.status_code == 201
    result = created.json()
    assert result["before_risk_score"] == before["risk_score"]
    assert result["after_risk_score"] < result["before_risk_score"]
    assert result["before_security_score"] == 100 - result["before_risk_score"]
    assert client.post("/api/v1/risk/assess", headers={"Authorization": f"Bearer {alice}"}, json={"asset_id": "workstation-1", "signals": payload["current_signals"]}).json()["risk_score"] == before["risk_score"]
    assert client.get("/api/v1/simulations", headers={"Authorization": f"Bearer {bob}"}).json() == []
    assert client.post("/api/v1/simulations", headers={"Authorization": f"Bearer {bob}"}, json={"asset_id": "", "current_signals": {}, "changes": {}}).status_code == 422
