from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Boolean, Float, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    devices: Mapped[list["Device"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    serial_number: Mapped[str] = mapped_column(String(120), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    owner: Mapped[User] = relationship(back_populates="devices")
    telemetry: Mapped[list["TelemetryEvent"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    features: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(20))
    is_anomaly: Mapped[bool] = mapped_column(Boolean)
    score: Mapped[float] = mapped_column(Float)
    explanation: Mapped[str] = mapped_column(Text)
    model_version: Mapped[str] = mapped_column(String(80))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SimulationRecord(Base):
    __tablename__ = "simulation_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str] = mapped_column(String(120))
    before_risk_score: Mapped[int] = mapped_column(Integer)
    after_risk_score: Mapped[int] = mapped_column(Integer)
    before_security_score: Mapped[int] = mapped_column(Integer)
    after_security_score: Mapped[int] = mapped_column(Integer)
    removed_findings: Mapped[str] = mapped_column(Text)
    added_findings: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(80))
    payload: Mapped[str] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    device: Mapped[Device] = relationship(back_populates="telemetry")
