from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4
from sqlalchemy import Boolean, DateTime, Enum as SAEnum, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from cloudguard.db.base import Base

def now_utc(): return datetime.now(timezone.utc)
def new_id(): return str(uuid4())

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    CLOUD_ENGINEER = "CLOUD_ENGINEER"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(150))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.CLOUD_ENGINEER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    azure_subscription_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(150))
    environment: Mapped[str] = mapped_column(String(50))
    tenant_id: Mapped[str] = mapped_column(String(36))
    credential_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class PolicyRule(Base):
    __tablename__ = "policy_rules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    rule_type: Mapped[str] = mapped_column(String(50), index=True)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity))
    configuration: Mapped[dict] = mapped_column(JSON, default=dict)
    auto_remediate: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_by: Mapped[User] = relationship()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
