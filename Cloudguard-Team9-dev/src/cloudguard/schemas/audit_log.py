from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    id: int
    event_type: str
    entity_type: str
    entity_id: int | None
    actor: str
    action: str
    details: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)