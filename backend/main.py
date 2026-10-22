import json
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .auth import create_access_token, get_current_user, hash_password, verify_password
from .config import get_settings
from .database import Base, engine, get_db
from .models import AnomalyEvent, Device, RiskAssessmentRecord, SimulationRecord, TelemetryEvent, User
from .schemas import DeviceCreate, DeviceRead, TelemetryCreate, TelemetryRead, Token, UserCreate, UserRead
from .risk import (
    LEGACY_CHANGE_MAP,
    METHODOLOGY_VERSION,
    Assessment,
    SignalInput,
    SignalState,
    SignalValidationError,
    apply_overrides,
    compare,
    evaluate,
    legacy_inputs,
    methodology,
)
from .risk_schemas import (
    RiskAssessmentRead,
    RiskAssessmentRequest,
    SecurityProfileRead,
    SecurityProfileUpdate,
    StoredAssessmentRead,
)
from .assessment_service import device_inputs, profile_payload, update_controls
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
    if not settings.database_url:
        return {"status": "degraded", "database": "not_configured", "connectivity": "not_checked", "schema": "not_checked"}

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            inspector = inspect(connection)
            schema_ready = inspector.has_table("alembic_version") if not settings.database_url.startswith("sqlite") else all(
                inspector.has_table(table.name) for table in Base.metadata.sorted_tables
            )
            if not schema_ready:
                return {"status": "degraded", "database": "configured", "connectivity": "ok", "schema": "not_ready"}
    except SQLAlchemyError:
        return {"status": "degraded", "database": "configured", "connectivity": "unavailable", "schema": "not_ready"}

    return {"status": "ok", "database": "configured", "connectivity": "ok", "schema": "ready"}


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


@app.get("/api/v1/risk/methodology")
def risk_methodology() -> dict:
    """Public, static description of the scoring formula, weights and thresholds."""
    return methodology()


def _validation_error(exc: SignalValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@app.post("/api/v1/risk/assess", response_model=RiskAssessmentRead)
def assess_risk(payload: RiskAssessmentRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    """Ad-hoc, non-persisted assessment using the same engine as stored assessments and simulations."""
    inputs: dict[str, SignalInput] = {}
    if payload.device_id is not None:
        inputs, _ = device_inputs(db, user, owned_device(payload.device_id, user, db))
    inputs.update(legacy_inputs(payload.signals))
    inputs.update({key: SignalInput(state) for key, state in payload.controls.items()})
    try:
        return evaluate(payload.asset_id, inputs).to_dict()
    except SignalValidationError as exc:
        raise _validation_error(exc) from exc


@app.get("/api/v1/devices/{device_id}/security-profile", response_model=SecurityProfileRead)
def get_security_profile(device_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    device = owned_device(device_id, user, db)
    inputs, evidence = device_inputs(db, user, device)
    return profile_payload(device, inputs, evidence)


@app.put("/api/v1/devices/{device_id}/security-profile", response_model=SecurityProfileRead)
def put_security_profile(device_id: int, payload: SecurityProfileUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    device = owned_device(device_id, user, db)
    try:
        update_controls(user, device, payload.controls, payload.source)
    except SignalValidationError as exc:
        db.rollback()
        raise _validation_error(exc) from exc
    db.commit()
    db.refresh(device)
    db.refresh(user)
    inputs, evidence = device_inputs(db, user, device)
    return profile_payload(device, inputs, evidence)


def _asset_label(device: Device) -> str:
    return f"device:{device.id}"


def _stored_assessment(row: RiskAssessmentRecord) -> dict:
    return {**json.loads(row.result), "id": row.id, "device_id": row.device_id, "created_at": row.created_at}


@app.post("/api/v1/devices/{device_id}/assessments", response_model=StoredAssessmentRead, status_code=201)
def create_assessment(device_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    device = owned_device(device_id, user, db)
    inputs, _ = device_inputs(db, user, device)
    result = evaluate(_asset_label(device), inputs)
    row = RiskAssessmentRecord(owner_id=user.id, device_id=device.id, methodology_version=result.methodology_version, risk_score=result.risk_score,
                               security_score=result.security_score, severity=result.severity.value, coverage=result.coverage, result=json.dumps(result.to_dict()))
    db.add(row)
    db.commit()
    db.refresh(row)
    return _stored_assessment(row)


@app.get("/api/v1/devices/{device_id}/assessments", response_model=list[StoredAssessmentRead])
def list_assessments(device_id: int, limit: int = 10, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    device = owned_device(device_id, user, db)
    rows = db.scalars(select(RiskAssessmentRecord).where(RiskAssessmentRecord.device_id == device.id, RiskAssessmentRecord.owner_id == user.id)
                      .order_by(RiskAssessmentRecord.id.desc()).limit(max(1, min(limit, 50)))).all()
    return [_stored_assessment(row) for row in rows]


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


def _simulation_read(row: SimulationRecord) -> SimulationRead:
    details = json.loads(row.details) if row.details else {}
    return SimulationRead(id=row.id, asset_id=row.asset_id, device_id=row.device_id, before_risk_score=row.before_risk_score, after_risk_score=row.after_risk_score,
                          before_security_score=row.before_security_score, after_security_score=row.after_security_score,
                          removed_findings=json.loads(row.removed_findings), added_findings=json.loads(row.added_findings), explanation=row.explanation,
                          created_at=row.created_at, **details)


@app.post("/api/v1/simulations", response_model=SimulationRead, status_code=201)
def create_simulation(payload: SimulationRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> SimulationRead:
    """Score baseline and a hypothetical copy with the same engine. Stored device controls are never modified."""
    device: Device | None = None
    if payload.device_id is not None:
        device = owned_device(payload.device_id, user, db)
        baseline_inputs, _ = device_inputs(db, user, device)
        asset_id = _asset_label(device)
    else:
        baseline_inputs = legacy_inputs(payload.current_signals)
        asset_id = payload.asset_id or ""
    overrides: dict[str, SignalState | str] = dict(payload.proposed_controls)
    legacy_changes = payload.changes.model_dump(exclude_none=True)
    for change, key in LEGACY_CHANGE_MAP.items():
        if change in legacy_changes and key not in overrides:
            overrides[key] = SignalState.ENABLED if legacy_changes[change] else SignalState.DISABLED
    try:
        proposed_inputs = apply_overrides(baseline_inputs, overrides)
        baseline: Assessment = evaluate(asset_id, baseline_inputs)
        proposed: Assessment = evaluate(asset_id, proposed_inputs, observed_at=baseline.assessed_at)
    except SignalValidationError as exc:
        raise _validation_error(exc) from exc
    comparison = compare(baseline, proposed)
    details = {"methodology_version": METHODOLOGY_VERSION, "risk_delta": comparison["risk_delta"], "security_delta": comparison["security_delta"],
               "changed_signals": comparison["changed_signals"], "recommendations": comparison["recommendations"],
               "baseline": baseline.to_dict(), "proposed": proposed.to_dict()}
    record = SimulationRecord(owner_id=user.id, asset_id=asset_id, device_id=device.id if device else None, before_risk_score=baseline.risk_score,
                              after_risk_score=proposed.risk_score, before_security_score=baseline.security_score, after_security_score=proposed.security_score,
                              removed_findings=json.dumps(comparison["resolved_findings"]), added_findings=json.dumps(comparison["introduced_findings"]),
                              explanation=comparison["explanation"], details=json.dumps(details))
    db.add(record)
    db.commit()
    db.refresh(record)
    return _simulation_read(record)


@app.get("/api/v1/simulations", response_model=list[SimulationRead])
def list_simulations(device_id: int | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[SimulationRead]:
    query = select(SimulationRecord).where(SimulationRecord.owner_id == user.id)
    if device_id is not None:
        query = query.where(SimulationRecord.device_id == device_id)
    rows = db.scalars(query.order_by(SimulationRecord.id.desc())).all()
    return [_simulation_read(row) for row in rows]

