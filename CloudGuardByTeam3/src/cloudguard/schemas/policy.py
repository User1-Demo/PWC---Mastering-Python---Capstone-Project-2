from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, model_validator
from cloudguard.models import Severity
SUPPORTED = {"REQUIRED_TAGS", "NSG_RISKY_PORTS"}
class PolicyCreate(BaseModel):
    name: str = Field(min_length=3, max_length=150)
    rule_type: str
    description: str = Field(min_length=3)
    severity: Severity
    configuration: dict
    auto_remediate: bool = False
    @model_validator(mode="after")
    def validate_rule(self):
        if self.rule_type not in SUPPORTED:
            raise ValueError(f"rule_type must be one of {sorted(SUPPORTED)}")
        if self.rule_type == "REQUIRED_TAGS" and not self.configuration.get("required_tags"):
            raise ValueError("REQUIRED_TAGS requires configuration.required_tags")
        if self.rule_type == "NSG_RISKY_PORTS" and not self.configuration.get("ports"):
            raise ValueError("NSG_RISKY_PORTS requires configuration.ports")
        if self.auto_remediate and self.severity in {Severity.HIGH, Severity.CRITICAL}:
            raise ValueError("High/Critical policies cannot be auto-remediated")
        return self
class PolicyRead(PolicyCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str; is_active: bool; created_by_id: str; created_at: datetime
