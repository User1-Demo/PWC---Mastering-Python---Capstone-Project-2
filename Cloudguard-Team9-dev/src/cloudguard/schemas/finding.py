from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    policy_rule_id: int
    resource_id: str
    resource_name: str
    resource_type: str
    severity: str
    status: str
    message: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)