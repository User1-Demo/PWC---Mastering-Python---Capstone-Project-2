from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RemediationResponse(BaseModel):
    id: int
    finding_id: int
    action_type: str
    status: str
    requested_by: str
    approved_by: str | None
    result_message: str | None
    requested_at: datetime
    approved_at: datetime | None
    completed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)