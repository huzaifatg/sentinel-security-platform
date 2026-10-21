import json
from dataclasses import asdict
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import create_access_token, get_current_user, hash_password, verify_password
from .config import get_settings
from .database import Base, engine, get_db
from .models import AnomalyEvent, Device, SimulationRecord, TelemetryEvent, User
from .schemas import DeviceCreate, DeviceRead, TelemetryCreate, TelemetryRead, Token, UserCreate, UserRead
from .risk import assess
from .risk_schemas import RiskAssessmentRead, RiskAssessmentRequest
from .anomaly import FEATURE_NAMES, ModelUnavailableError, infer, train_model
from .anomaly_schemas import AnomalyEventCreate, AnomalyEventRead, AnomalyModelTrainRead, AnomalyModelTrainRequest
from .simulation_schemas import SimulationRead, SimulationRequest

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def create_tables_for_local_development() -> None:
    # Production uses Alembic; this keeps the SQLite development smoke test self-contained.
    if settings.database_url.startswith("sqlite"):
        Base.metadata.create_all(bind=engine)


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok", "database": "configured" if settings.database_url else "not_configured"}


@app.post("/api/v1/auth/register", response_model=UserRead, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    email = payload.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/v1/auth/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> Token:
    user = db.scalar(select(User).where(User.email == form.username.lower()))
    if user is None or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    return Token(access_token=create_access_token(user.id))


@app.get("/api/v1/auth/me", response_model=UserRead)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@app.post("/api/v1/devices", response_model=DeviceRead, status_code=201)
def create_device(payload: DeviceCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Device:
    device = Device(owner_id=user.id, name=payload.name, serial_number=payload.serial_number)
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@app.get("/api/v1/devices", response_model=list[DeviceRead])
def list_devices(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Device]:
    return list(db.scalars(select(Device).where(Device.owner_id == user.id).order_by(Device.id)).all())


def owned_device(device_id: int, user: User, db: Session) -> Device:
    device = db.scalar(select(Device).where(Device.id == device_id, Device.owner_id == user.id))
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@app.get("/api/v1/devices/{device_id}", response_model=DeviceRead)
def get_device(device_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Device:
    return owned_device(device_id, user, db)


@app.post("/api/v1/devices/{device_id}/telemetry", response_model=TelemetryRead, status_code=201)
def ingest_telemetry(device_id: int, payload: TelemetryCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> TelemetryRead:
    device = owned_device(device_id, user, db)
    event = TelemetryEvent(device_id=device.id, event_type=payload.event_type, payload=json.dumps(payload.payload))
    db.add(event)
    db.commit()
    db.refresh(event)
    return TelemetryRead(id=event.id, device_id=event.device_id, event_type=event.event_type, payload=payload.payload, observed_at=event.observed_at)


@app.get("/api/v1/devices/{device_id}/telemetry", response_model=list[TelemetryRead])
def list_telemetry(device_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[TelemetryRead]:
    device = owned_device(device_id, user, db)
    events = db.scalars(select(TelemetryEvent).where(TelemetryEvent.device_id == device.id).order_by(TelemetryEvent.id)).all()
    return [TelemetryRead(id=e.id, device_id=e.device_id, event_type=e.event_type, payload=json.loads(e.payload), observed_at=e.observed_at) for e in events]


@app.post("/api/v1/risk/assess", response_model=RiskAssessmentRead)
def assess_risk(payload: RiskAssessmentRequest, user: User = Depends(get_current_user)) -> RiskAssessmentRead:
    risk_score, findings = assess(payload.asset_id, payload.signals)
    from .risk import severity_for
    severity = severity_for(risk_score)
    return RiskAssessmentRead(
        risk_score=risk_score,
        security_score=100 - risk_score,
        severity=severity,
        findings=[asdict(finding) for finding in findings],
    )


MODEL_PATH = Path(settings.model_directory) / "isolation-forest.joblib"


def synthetic_training_events() -> list[dict[str, int | bool]]:
    return [
        {"login_hour": hour, "failed_attempts": attempts, "new_device": new, "network_change": network}
        for hour, attempts, new, network in ((9, 0, False, False), (10, 0, False, False), (8, 1, False, False), (12, 0, False, False), (14, 1, False, False), (16, 0, False, False), (11, 1, False, False), (13, 0, False, False))
    ]


@app.post("/api/v1/anomalies/model/train", response_model=AnomalyModelTrainRead)
def train_anomaly_model(payload: AnomalyModelTrainRequest, user: User = Depends(get_current_user)) -> AnomalyModelTrainRead:
    events = payload.events or synthetic_training_events()
    metadata = train_model(events, MODEL_PATH)
    return AnomalyModelTrainRead(**metadata, feature_names=FEATURE_NAMES, training_events=len(events))


@app.post("/api/v1/anomalies/events", response_model=AnomalyEventRead, status_code=201)
def detect_anomaly(payload: AnomalyEventCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> AnomalyEvent:
    owned_device(payload.device_id, user, db)
    try:
        result = infer(payload.features, MODEL_PATH)
    except ModelUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    event = AnomalyEvent(owner_id=user.id, device_id=payload.device_id, features=json.dumps(payload.features), source=payload.source, is_anomaly=result.is_anomaly, score=result.score, explanation=result.explanation, model_version=result.model_version)
    db.add(event)
    db.commit()
    db.refresh(event)
    return AnomalyEventRead(id=event.id, device_id=event.device_id, features=payload.features, source=event.source, is_anomaly=event.is_anomaly, score=event.score, explanation=event.explanation, model_version=event.model_version, observed_at=event.observed_at)


@app.get("/api/v1/anomalies/events", response_model=list[AnomalyEventRead])
def list_anomalies(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[AnomalyEventRead]:
    events = db.scalars(select(AnomalyEvent).where(AnomalyEvent.owner_id == user.id).order_by(AnomalyEvent.id)).all()
    return [AnomalyEventRead(id=e.id, device_id=e.device_id, features=json.loads(e.features), source=e.source, is_anomaly=e.is_anomaly, score=e.score, explanation=e.explanation, model_version=e.model_version, observed_at=e.observed_at) for e in events]


@app.post("/api/v1/simulations", response_model=SimulationRead, status_code=201)
def create_simulation(payload: SimulationRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> SimulationRecord:
    before_score, before_findings = assess(payload.asset_id, payload.current_signals)
    signals = dict(payload.current_signals)
    changes = payload.changes.model_dump(exclude_none=True)
    mapping = {"mfa_enabled": "mfa_disabled", "operating_system_updated": "operating_system_outdated", "firewall_enabled": "firewall_disabled", "disk_encryption_enabled": "disk_encryption_disabled"}
    for change, rule in mapping.items():
        if change in changes:
            signals[rule] = not changes[change]
    if changes.get("remove_unknown_device"):
        signals["unknown_device"] = False
    after_score, after_findings = assess(payload.asset_id, signals)
    before_rules = {finding.rule for finding in before_findings}
    after_rules = {finding.rule for finding in after_findings}
    removed_findings = sorted(before_rules - after_rules)
    added_findings = sorted(after_rules - before_rules)
    explanation = "Projected scores are calculated by the same rules as risk assessment and are not persisted as device state."
    record = SimulationRecord(owner_id=user.id, asset_id=payload.asset_id, before_risk_score=before_score, after_risk_score=after_score, before_security_score=100 - before_score, after_security_score=100 - after_score, removed_findings=json.dumps(removed_findings), added_findings=json.dumps(added_findings), explanation=explanation)
    db.add(record)
    db.commit()
    db.refresh(record)
    return SimulationRead(id=record.id, asset_id=record.asset_id, before_risk_score=record.before_risk_score, after_risk_score=record.after_risk_score, before_security_score=record.before_security_score, after_security_score=record.after_security_score, removed_findings=removed_findings, added_findings=added_findings, explanation=record.explanation, created_at=record.created_at)


@app.get("/api/v1/simulations", response_model=list[SimulationRead])
def list_simulations(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[SimulationRead]:
    rows = db.scalars(select(SimulationRecord).where(SimulationRecord.owner_id == user.id).order_by(SimulationRecord.id.desc())).all()
    return [SimulationRead(id=row.id, asset_id=row.asset_id, before_risk_score=row.before_risk_score, after_risk_score=row.after_risk_score, before_security_score=row.before_security_score, after_security_score=row.after_security_score, removed_findings=json.loads(row.removed_findings), added_findings=json.loads(row.added_findings), explanation=row.explanation, created_at=row.created_at) for row in rows]

