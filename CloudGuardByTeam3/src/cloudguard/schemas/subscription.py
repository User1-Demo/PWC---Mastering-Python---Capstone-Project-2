from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
class SubscriptionCreate(BaseModel):
    azure_subscription_id: str = Field(min_length=36, max_length=36)
    name: str = Field(min_length=2, max_length=150)
    environment: str = Field(min_length=2, max_length=50)
    tenant_id: str = Field(min_length=36, max_length=36)
    credential_reference: str | None = None
class SubscriptionRead(SubscriptionCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str; is_active: bool; created_at: datetime
