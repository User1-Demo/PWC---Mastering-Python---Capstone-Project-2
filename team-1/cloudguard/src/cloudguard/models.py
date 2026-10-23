import enum
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, DateTime, Boolean, ForeignKey, Integer, Enum, JSON, Text
)
from sqlalchemy.orm import relationship
from .database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class RoleEnum(str, enum.Enum):
    ADMIN = "admin"
    CLOUD_ENGINEER = "cloud_engineer"
    SECURITY_OFFICER = "security_officer"
    SERVICE_ACCOUNT = "service_account"


class SeverityEnum(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatusEnum(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


class FindingStatusEnum(str, enum.Enum):
    OPEN = "open"
    PENDING_APPROVAL = "pending_approval"
    REMEDIATED = "remediated"
    EXCEPTION = "exception"
    CLOSED = "closed"


class RemediationStatusEnum(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    REJECTED = "rejected"


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_uuid)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(RoleEnum), nullable=False, default=RoleEnum.CLOUD_ENGINEER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    azure_subscription_id = Column(String, nullable=False, unique=True)
    tenant_id = Column(String, nullable=False)
    environment = Column(String, nullable=False)        # dev/staging/prod
    credential_ref = Column(String, nullable=False)     # K8s secret / KeyVault ref ONLY
    schedule_cron = Column(String, nullable=True)        # e.g. "0 2 * * *"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="subscription")


class PolicyRule(Base):
    __tablename__ = "policy_rules"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    rule_type = Column(String, nullable=False)     # tagging | nsg | idle_resource | secret_expiry
    resource_type = Column(String, nullable=False)  # vm | disk | nsg | keyvault_secret
    condition = Column(JSON, nullable=False)         # rule-specific config, validated on save
    severity = Column(Enum(SeverityEnum), nullable=False)
    auto_remediate = Column(Boolean, default=False)   # pre-approved low-risk only
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=gen_uuid)
    subscription_id = Column(String, ForeignKey("subscriptions.id"), nullable=False)
    triggered_by = Column(String, nullable=False)
    trigger_source = Column(String, nullable=False)    # api | cli | schedule
    status = Column(Enum(ScanStatusEnum), default=ScanStatusEnum.PENDING)
    resource_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    subscription = relationship("Subscription", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    subscription_id = Column(String, ForeignKey("subscriptions.id"), nullable=False)
    rule_id = Column(String, ForeignKey("policy_rules.id"), nullable=False)
    resource_id = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    severity = Column(Enum(SeverityEnum), nullable=False)
    status = Column(Enum(FindingStatusEnum), default=FindingStatusEnum.OPEN)
    details = Column(JSON, nullable=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="findings")
    remediation_actions = relationship("RemediationAction", back_populates="finding")
    exception = relationship("Exception", back_populates="finding", uselist=False)


class RemediationAction(Base):
    __tablename__ = "remediation_actions"
    id = Column(String, primary_key=True, default=gen_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    action_type = Column(String, nullable=False)
    status = Column(Enum(RemediationStatusEnum), default=RemediationStatusEnum.PENDING)
    triggered_by = Column(String, nullable=False)       # user id or "service_account"
    attempt_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    result = Column(JSON, nullable=True)
    requires_approval = Column(Boolean, default=False)
    approved_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    finding = relationship("Finding", back_populates="remediation_actions")


class Exception(Base):
    __tablename__ = "exceptions"
    id = Column(String, primary_key=True, default=gen_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False, unique=True)
    approved_by = Column(String, nullable=False)
    reason = Column(Text, nullable=False)
    expiry_date = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="exception")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=gen_uuid)
    action = Column(String, nullable=False)          # e.g. SCAN_STARTED, FINDING_REMEDIATED
    entity_type = Column(String, nullable=False)     # Scan|Finding|RemediationAction|Policy...
    entity_id = Column(String, nullable=False)
    actor = Column(String, nullable=False)           # user id / service account
    timestamp = Column(DateTime, default=datetime.utcnow)
    metadata_json = Column(JSON, nullable=True)
    prev_hash = Column(String, nullable=True)         # hash chain -> tamper-evidence
    record_hash = Column(String, nullable=False)