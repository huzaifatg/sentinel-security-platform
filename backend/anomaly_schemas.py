from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .anomaly import FEATURE_NAMES


class AnomalyEventCreate(BaseModel):
    device_id: int
    features: dict[str, Any]
    source: str = Field(default="simulated", pattern="^(simulated|collected)$")


class AnomalyEventRead(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    device_id: int
    features: dict[str, Any]
    source: str
    is_anomaly: bool
    score: float
    explanation: str
    model_version: str
    observed_at: datetime


class AnomalyModelTrainRequest(BaseModel):
    events: list[dict[str, Any]] | None = None


class AnomalyModelTrainRead(BaseModel):
    model_version: str
    feature_names: tuple[str, ...] = FEATURE_NAMES
    training_data: str
    training_events: int
