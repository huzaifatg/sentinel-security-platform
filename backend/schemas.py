from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class DeviceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    serial_number: str = Field(min_length=1, max_length=120)


class DeviceRead(DeviceCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    owner_id: int
    created_at: datetime


class TelemetryCreate(BaseModel):
    event_type: str = Field(min_length=1, max_length=80)
    payload: dict[str, object] = Field(default_factory=dict)


class TelemetryRead(BaseModel):
    id: int
    device_id: int
    event_type: str
    payload: dict[str, object]
    observed_at: datetime
