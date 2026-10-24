from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SubscriptionCreate(BaseModel):
    subscription_id: str
    name: str
    environment: str


class SubscriptionResponse(BaseModel):
    id: int
    subscription_id: str
    name: str
    environment: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)