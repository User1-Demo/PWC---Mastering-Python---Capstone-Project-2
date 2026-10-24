from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: str
    password: str = Field(min_length=12)
    role: Literal["admin", "cloud_engineer", "security_officer"]

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("A valid email address is required")
        return value


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    role: str
    is_active: bool


class SubscriptionCreate(BaseModel):
    subscription_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    environment: str = Field(default="unknown", max_length=80)


class SubscriptionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    environment: str | None = Field(default=None, min_length=1, max_length=80)
    enabled: bool | None = None


class SubscriptionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    subscription_id: str
    name: str
    environment: str
    enabled: bool


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    rule_type: str
    severity: Literal["low", "medium", "high", "critical"]
    parameters: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    auto_remediate: bool = False


class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    rule_type: str | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    parameters: dict[str, Any] | None = None
    enabled: bool | None = None
    auto_remediate: bool | None = None


class PolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    rule_type: str
    severity: str
    parameters: dict[str, Any]
    enabled: bool
    auto_remediate: bool


class ScanCreate(BaseModel):
    subscription_id: int
    trigger_source: Literal["api", "cli", "schedule"] = "api"


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    subscription_id: int
    trigger_source: str
    status: str
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    rule_id: int
    resource_id: str
    resource_name: str
    resource_type: str
    severity: str
    status: str
    title: str
    details: dict[str, Any]
    created_at: datetime


class ApprovalRequest(BaseModel):
    approved: bool
    reason: str = Field(min_length=3, max_length=2000)


class ExceptionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)
    expires_at: datetime


class AuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    event_type: str
    entity_type: str
    entity_id: str
    actor_id: int | None
    event_metadata: dict[str, Any]
    previous_hash: str
    event_hash: str
    created_at: datetime


class RemediationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    finding_id: int
    actor_id: int | None
    status: str
    attempt_count: int
    message: str | None
    created_at: datetime
    completed_at: datetime | None
