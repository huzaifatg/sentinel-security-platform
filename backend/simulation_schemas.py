from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

from .risk import SignalState


class SimulationChange(BaseModel):
    """Legacy v1 change flags (kept for backwards compatibility)."""

    mfa_enabled: bool | None = None
    operating_system_updated: bool | None = None
    firewall_enabled: bool | None = None
    disk_encryption_enabled: bool | None = None
    remove_unknown_device: bool = False


class SimulationRequest(BaseModel):
    """Either ``device_id`` + ``proposed_controls`` (v2) or ``asset_id`` + legacy signals/changes (v1)."""

    device_id: int | None = None
    proposed_controls: dict[str, SignalState] = Field(default_factory=dict)
    asset_id: str | None = Field(default=None, min_length=1, max_length=120)
    current_signals: dict[str, bool] = Field(default_factory=dict)
    changes: SimulationChange = Field(default_factory=SimulationChange)

    @model_validator(mode="after")
    def require_target(self) -> "SimulationRequest":
        if self.device_id is None and not self.asset_id:
            raise ValueError("Provide device_id (preferred) or asset_id.")
        return self


class ChangedSignalRead(BaseModel):
    key: str
    label: str
    from_state: str
    to_state: str
    contribution_before: float
    contribution_after: float
    delta: float


class SimulationRead(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    asset_id: str
    device_id: int | None = None
    before_risk_score: int
    after_risk_score: int
    before_security_score: int
    after_security_score: int
    removed_findings: list[str]
    added_findings: list[str]
    explanation: str
    created_at: datetime
    methodology_version: str | None = None
    risk_delta: int | None = None
    security_delta: int | None = None
    changed_signals: list[ChangedSignalRead] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    baseline: dict[str, Any] | None = None
    proposed: dict[str, Any] | None = None
