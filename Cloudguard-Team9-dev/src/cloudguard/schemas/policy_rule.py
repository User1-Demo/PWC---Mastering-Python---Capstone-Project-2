from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class PolicyRuleCreate(BaseModel):
    name: str
    rule_type: Literal["required_tag", "risky_nsg"]
    severity: Literal["low", "medium", "high", "critical"]
    description: str
    enabled: bool = True


class PolicyRuleResponse(BaseModel):
    id: int
    name: str
    rule_type: str
    severity: str
    description: str
    enabled: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)