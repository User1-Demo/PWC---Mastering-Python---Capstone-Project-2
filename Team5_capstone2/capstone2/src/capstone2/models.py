from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from capstone2.database import Base

def now(): return datetime.now(timezone.utc)
class Role(str, Enum):
    ADMIN="admin"; CLOUD_ENGINEER="cloud_engineer"; SECURITY_OFFICER="security_officer"; SERVICE="service"
class ScanStatus(str, Enum):
    PENDING="pending"; RUNNING="running"; COMPLETED="completed"; FAILED="failed"
class FindingStatus(str, Enum):
    OPEN="open"; PENDING_APPROVAL="pending_approval"; REMEDIATED="remediated"; EXCEPTED="excepted"; REJECTED="rejected"
class Severity(str, Enum):
    LOW="low"; MEDIUM="medium"; HIGH="high"; CRITICAL="critical"
class User(Base):
    __tablename__="users"
    id: Mapped[int]=mapped_column(primary_key=True)
    username: Mapped[str]=mapped_column(String(200), unique=True, index=True)
    password_hash: Mapped[str]=mapped_column(String(255))
    role: Mapped[str]=mapped_column(String(50), default=Role.CLOUD_ENGINEER.value)
    is_active: Mapped[bool]=mapped_column(Boolean, default=True)
class Subscription(Base):
    __tablename__="subscriptions"
    id: Mapped[int]=mapped_column(primary_key=True)
    name: Mapped[str]=mapped_column(String(120))
    azure_subscription_id: Mapped[str]=mapped_column(String(100), unique=True)
    environment: Mapped[str]=mapped_column(String(30))
    credential_ref: Mapped[str | None]=mapped_column(String(255), nullable=True)
    is_active: Mapped[bool]=mapped_column(Boolean, default=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
class PolicyRule(Base):
    __tablename__="policy_rules"
    id: Mapped[int]=mapped_column(primary_key=True)
    name: Mapped[str]=mapped_column(String(120), unique=True)
    rule_type: Mapped[str]=mapped_column(String(50))
    severity: Mapped[str]=mapped_column(String(20))
    config: Mapped[dict]=mapped_column(JSON, default=dict)
    auto_remediate: Mapped[bool]=mapped_column(Boolean, default=False)
    enabled: Mapped[bool]=mapped_column(Boolean, default=True)
class Scan(Base):
    __tablename__="scans"
    id: Mapped[int]=mapped_column(primary_key=True)
    subscription_id: Mapped[int]=mapped_column(ForeignKey("subscriptions.id"))
    trigger_source: Mapped[str]=mapped_column(String(30), default="api")
    status: Mapped[str]=mapped_column(String(30), default=ScanStatus.PENDING.value)
    started_at: Mapped[datetime | None]=mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None]=mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None]=mapped_column(Text, nullable=True)
class Finding(Base):
    __tablename__="findings"
    id: Mapped[int]=mapped_column(primary_key=True)
    scan_id: Mapped[int]=mapped_column(ForeignKey("scans.id"))
    policy_rule_id: Mapped[int]=mapped_column(ForeignKey("policy_rules.id"))
    resource_id: Mapped[str]=mapped_column(String(500))
    resource_type: Mapped[str]=mapped_column(String(100))
    title: Mapped[str]=mapped_column(String(255))
    details: Mapped[dict]=mapped_column(JSON, default=dict)
    severity: Mapped[str]=mapped_column(String(20))
    status: Mapped[str]=mapped_column(String(30), default=FindingStatus.OPEN.value)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
class RemediationAction(Base):
    __tablename__="remediation_actions"
    id: Mapped[int]=mapped_column(primary_key=True)
    finding_id: Mapped[int]=mapped_column(ForeignKey("findings.id"))
    requested_by: Mapped[int]=mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[int | None]=mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[str]=mapped_column(String(30), default="requested")
    result: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
class ApprovedException(Base):
    __tablename__="exceptions"
    id: Mapped[int]=mapped_column(primary_key=True)
    finding_id: Mapped[int]=mapped_column(ForeignKey("findings.id"), unique=True)
    reason: Mapped[str]=mapped_column(Text)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True))
    approved_by: Mapped[int]=mapped_column(ForeignKey("users.id"))
class AuditLog(Base):
    __tablename__="audit_logs"
    id: Mapped[int]=mapped_column(primary_key=True)
    action: Mapped[str]=mapped_column(String(100), index=True)
    entity_type: Mapped[str]=mapped_column(String(60))
    entity_id: Mapped[str]=mapped_column(String(100))
    actor_id: Mapped[int | None]=mapped_column(ForeignKey("users.id"), nullable=True)
    data: Mapped[dict]=mapped_column(JSON, default=dict)
    previous_hash: Mapped[str]=mapped_column(String(64), default="")
    event_hash: Mapped[str]=mapped_column(String(64), index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
