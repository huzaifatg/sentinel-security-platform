import json
from dataclasses import asdict

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import create_access_token, get_current_user, hash_password, verify_password
from .config import get_settings
from .database import Base, engine, get_db
from .models import Device, TelemetryEvent, User
from .schemas import DeviceCreate, DeviceRead, TelemetryCreate, TelemetryRead, Token, UserCreate, UserRead
from .risk import assess
from .risk_schemas import RiskAssessmentRead, RiskAssessmentRequest

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

