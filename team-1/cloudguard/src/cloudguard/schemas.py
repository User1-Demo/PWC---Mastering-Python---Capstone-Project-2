from datetime import datetime
from typing import Any, Optional, List, Dict
from pydantic import BaseModel, Field, field_validator

SUPPORTED_RULE_TYPES = {
    "tagging": {"resource_types": {"vm", "nsg", "disk"}, "fields": {"required_tags"}},
    "nsg": {"resource_types": {"nsg"}, "fields": {"risky_ports", "disallow_any_source"}},
    "idle_resource": {"resource_types": {"vm", "disk"}, "fields": {"cpu_threshold_percent", "idle_days"}},
    "secret_expiry": {"resource_types": {"keyvault_secret"}, "fields": {"warn_days"}},
}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserLogin(BaseModel):
    email: str
    password: str


class SubscriptionCreate(BaseModel):
    name: str
    azure_subscription_id: str
    tenant_id: str
    environment: str
    credential_ref: str = Field(..., description="Reference to K8s Secret / Key Vault entry")
    schedule_cron: Optional[str] = None


class SubscriptionOut(BaseModel):
    id: str
    name: str
    azure_subscription_id: str
    environment: str
    is_active: bool
    schedule_cron: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyRuleCreate(BaseModel):
    name: str
    rule_type: str
    resource_type: str
    condition: Dict[str, Any]
    severity: str
    auto_remediate: bool = False

    @field_validator("rule_type")
    @classmethod
    def valid_rule_type(cls, v):
        if v not in SUPPORTED_RULE_TYPES:
            raise ValueError(f"Unsupported rule_type '{v}'. Supported: {list(SUPPORTED_RULE_TYPES)}")
        return v

    @field_validator("condition")
    @classmethod
    def valid_condition_keys(cls, v, info):
        rule_type = info.data.get("rule_type")
        if rule_type and rule_type in SUPPORTED_RULE_TYPES:
            allowed = SUPPORTED_RULE_TYPES[rule_type]["fields"]
            unknown = set(v.keys()) - allowed
            if unknown:
                raise ValueError(f"Unknown condition fields for {rule_type}: {unknown}")
        return v

    @field_validator("resource_type")
    @classmethod
    def valid_resource_type(cls, v, info):
        rule_type = info.data.get("rule_type")
        if rule_type and rule_type in SUPPORTED_RULE_TYPES:
            allowed = SUPPORTED_RULE_TYPES[rule_type]["resource_types"]
            if v not in allowed:
                raise ValueError(f"resource_type '{v}' invalid for rule_type '{rule_type}'. Allowed: {allowed}")
        return v


class PolicyRuleOut(BaseModel):
    id: str
    name: str
    rule_type: str
    resource_type: str
    condition: Dict[str, Any]
    severity: str
    auto_remediate: bool
    is_active: bool

    class Config:
        from_attributes = True


class ScanTrigger(BaseModel):
    subscription_id: str


class ScanOut(BaseModel):
    id: str
    subscription_id: str
    status: str
    resource_count: int
    finding_count: int
    started_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]

    class Config:
        from_attributes = True


class FindingOut(BaseModel):
    id: str
    scan_id: str
    resource_id: str
    resource_type: str
    severity: str
    status: str
    details: Dict[str, Any]
    detected_at: datetime

    class Config:
        from_attributes = True


class ExceptionCreate(BaseModel):
    reason: str
    expiry_date: datetime


class AuditLogOut(BaseModel):
    id: str
    action: str
    entity_type: str
    entity_id: str
    actor: str
    timestamp: datetime
    metadata_json: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True