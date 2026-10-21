from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SimulationChange(BaseModel):
    mfa_enabled: bool | None = None
    operating_system_updated: bool | None = None
    firewall_enabled: bool | None = None
    disk_encryption_enabled: bool | None = None
    remove_unknown_device: bool = False


class SimulationRequest(BaseModel):
    asset_id: str = Field(min_length=1, max_length=120)
    current_signals: dict[str, bool]
    changes: SimulationChange


class SimulationRead(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    asset_id: str
    before_risk_score: int
    after_risk_score: int
    before_security_score: int
    after_security_score: int
    removed_findings: list[str]
    added_findings: list[str]
    explanation: str
    created_at: datetime
