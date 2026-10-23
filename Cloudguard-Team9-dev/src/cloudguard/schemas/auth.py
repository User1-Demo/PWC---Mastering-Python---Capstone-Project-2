from typing import Literal

from pydantic import BaseModel, ConfigDict

UserRole = Literal[
    "admin",
    "cloud_engineer",
    "security_officer",
]

class UserCreate(BaseModel):
    username: str
    password: str
    role: UserRole


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"