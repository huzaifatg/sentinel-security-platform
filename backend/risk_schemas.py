from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .risk import Provenance, Severity, SignalState


class RiskAssessmentRequest(BaseModel):
    """Ad-hoc assessment (not persisted).

    Provide ``device_id`` to score the stored profile of an owned device, ``controls`` for explicit
    signal states, or legacy boolean ``signals`` (v1 clients). Missing signals are scored as unknown.
    """

    asset_id: str = Field(min_length=1, max_length=120)
    device_id: int | None = None
    controls: dict[str, SignalState] = Field(default_factory=dict)
    signals: dict[str, bool] = Field(default_factory=dict)


class FindingRead(BaseModel):
    rule: str
    signal: str
    label: str
    category: str
    affected_asset: str
    state: SignalState
    source: Provenance
    evidence: str
    weight: int
    risk_factor: float
    contribution: float
    severity: Severity
    timestamp: datetime
    recommended_action: str


class SignalResultRead(BaseModel):
    key: str
    label: str
    scope: str
    state: SignalState
    source: Provenance
    weight: int
    applicable: bool
    risk_factor: float
    contribution: float
    evidence: str


class RiskAssessmentRead(BaseModel):
    asset_id: str
    methodology_version: str
    risk_score: int
    security_score: int
    severity: Severity
    raw_risk: float
    applicable_weight: int
    coverage: int
    signals: list[SignalResultRead]
    findings: list[FindingRead]
    explanation: str
    recommendations: list[str]
    assessed_at: datetime


class StoredAssessmentRead(RiskAssessmentRead):
    id: int
    device_id: int
    created_at: datetime


class ControlStateRead(BaseModel):
    key: str
    label: str
    scope: str
    kind: str
    weight: int
    state: SignalState
    source: Provenance
    updated_at: datetime | None = None
    evidence: str = ""
    allowed_states: list[SignalState]


class SecurityProfileRead(BaseModel):
    device_id: int
    signals: list[ControlStateRead]
    evidence_window_days: int
    behavioral_evidence: dict[str, Any]


class SecurityProfileUpdate(BaseModel):
    controls: dict[str, SignalState] = Field(min_length=1)
    source: Provenance = Provenance.MANUAL
