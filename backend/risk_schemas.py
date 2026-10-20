from datetime import datetime

from pydantic import BaseModel, Field

from .risk import Severity


class RiskAssessmentRequest(BaseModel):
    asset_id: str = Field(min_length=1, max_length=120)
    signals: dict[str, bool] = Field(default_factory=dict)


class FindingRead(BaseModel):
    rule: str
    label: str
    affected_asset: str
    evidence: str
    contribution: int
    severity: Severity
    timestamp: datetime
    recommended_action: str


class RiskAssessmentRead(BaseModel):
    risk_score: int
    security_score: int
    severity: Severity
    findings: list[FindingRead]
