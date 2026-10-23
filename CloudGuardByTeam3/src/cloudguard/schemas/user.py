from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from cloudguard.models import UserRole
class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=150)
    password: str = Field(min_length=8, max_length=128)
    role: UserRole = UserRole.CLOUD_ENGINEER
class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str; email: EmailStr; full_name: str; role: UserRole; is_active: bool; created_at: datetime
