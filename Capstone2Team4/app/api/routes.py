from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.audit import record_event, verify_chain
from app.database import get_db
from app.models import (
    AuditLog,
    Finding,
    FindingException,
    PolicyRule,
    RemediationAction,
    Scan,
    Subscription,
    User,
)
from app.rules.engine import validate_rule
from app.schemas import (
    ApprovalRequest,
    AuditRead,
    ExceptionRequest,
    FindingRead,
    LoginRequest,
    PolicyCreate,
    PolicyRead,
    PolicyUpdate,
    RemediationRead,
    ScanCreate,
    ScanRead,
    SubscriptionCreate,
    SubscriptionRead,
    SubscriptionUpdate,
    TokenResponse,
    UserCreate,
    UserRead,
)
from app.security import create_access_token, hash_password, verify_password
from app.services.dispatcher import DispatchError, dispatch_remediation, dispatch_scan
from app.services.remediation import queue_remediation

router = APIRouter(prefix="/api/v1")


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email.strip().lower()))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return TokenResponse(access_token=create_access_token(user.id, user.role))


@router.get("/users", response_model=list[UserRead])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
):
    return list(db.scalars(select(User).order_by(User.id)))


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles("admin")),
):
    user = User(email=payload.email, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    try:
        db.flush()
        record_event(
            db,
            event_type="user.created",
            entity_type="user",
            entity_id=user.id,
            actor_id=actor.id,
            metadata={"role": user.role},
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A user with this email already exists") from None
    db.refresh(user)
    return user


@router.get("/subscriptions", response_model=list[SubscriptionRead])
def list_subscriptions(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return list(db.scalars(select(Subscription).order_by(Subscription.id)))


@router.post("/subscriptions", response_model=SubscriptionRead, status_code=status.HTTP_201_CREATED)
def create_subscription(
    payload: SubscriptionCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles("admin")),
):
    subscription = Subscription(**payload.model_dump())
    db.add(subscription)
    try:
        db.flush()
        record_event(
            db,
            event_type="subscription.created",
            entity_type="subscription",
            entity_id=subscription.id,
            actor_id=actor.id,
            metadata={"subscription_id": subscription.subscription_id},
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Subscription is already registered") from None
    db.refresh(subscription)
    return subscription


@router.patch("/subscriptions/{subscription_pk}", response_model=SubscriptionRead)
def update_subscription(
    subscription_pk: int,
    payload: SubscriptionUpdate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles("admin")),
):
    subscription = db.get(Subscription, subscription_pk)
    if subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide at least one field to update")
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="Updated fields cannot be null")
    for field, value in changes.items():
        setattr(subscription, field, value)
    record_event(
        db,
        event_type="subscription.updated",
        entity_type="subscription",
        entity_id=subscription.id,
        actor_id=actor.id,
        metadata={"fields": sorted(changes)},
    )
    db.commit()
    db.refresh(subscription)
    return subscription


@router.get("/policies", response_model=list[PolicyRead])
def list_policies(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return list(db.scalars(select(PolicyRule).order_by(PolicyRule.id)))


@router.post("/policies", response_model=PolicyRead, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles("admin")),
):
    try:
        validate_rule(payload.rule_type, payload.severity, payload.parameters, payload.auto_remediate)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    policy = PolicyRule(**payload.model_dump())
    db.add(policy)
    try:
        db.flush()
        record_event(
            db,
            event_type="policy.created",
            entity_type="policy",
            entity_id=policy.id,
            actor_id=actor.id,
            metadata={"rule_type": policy.rule_type, "severity": policy.severity},
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Policy name is already in use") from None
    db.refresh(policy)
    return policy


@router.patch("/policies/{policy_id}", response_model=PolicyRead)
def update_policy(
    policy_id: int,
    payload: PolicyUpdate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles("admin")),
):
    policy = db.get(PolicyRule, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide at least one field to update")
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="Updated fields cannot be null")
    merged = {
        "rule_type": changes.get("rule_type", policy.rule_type),
        "severity": changes.get("severity", policy.severity),
        "parameters": changes.get("parameters", policy.parameters),
        "auto_remediate": changes.get("auto_remediate", policy.auto_remediate),
    }
    try:
        validate_rule(
            merged["rule_type"],
            merged["severity"],
            merged["parameters"],
            merged["auto_remediate"],
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    for field, value in changes.items():
        setattr(policy, field, value)
    try:
        record_event(
            db,
            event_type="policy.updated",
            entity_type="policy",
            entity_id=policy.id,
            actor_id=actor.id,
            metadata={"fields": sorted(changes)},
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Policy name is already in use") from None
    db.refresh(policy)
    return policy


@router.post("/scans", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    subscription = db.get(Subscription, payload.subscription_id)
    if subscription is None or not subscription.enabled:
        raise HTTPException(status_code=404, detail="Enabled subscription not found")
    scan = Scan(subscription_id=subscription.id, trigger_source=payload.trigger_source)
    db.add(scan)
    db.flush()
    record_event(
        db,
        event_type="scan.queued",
        entity_type="scan",
        entity_id=scan.id,
        actor_id=actor.id,
        metadata={"trigger_source": payload.trigger_source},
    )
    db.commit()
    db.refresh(scan)
    try:
        dispatch_scan(scan.id, background_tasks)
    except DispatchError as error:
        scan.status = "failed"
        scan.error_message = f"{type(error).__name__}: {error}"[:2000]
        scan.completed_at = datetime.now(timezone.utc)
        record_event(
            db,
            event_type="scan.dispatch_failed",
            entity_type="scan",
            entity_id=scan.id,
            actor_id=actor.id,
            metadata={"error_type": type(error).__name__},
        )
        db.commit()
        raise HTTPException(status_code=503, detail="Could not dispatch scan worker") from error
    return scan


@router.get("/scans", response_model=list[ScanRead])
def list_scans(
    subscription_id: int | None = None,
    scan_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(Scan).order_by(Scan.id.desc())
    if subscription_id is not None:
        query = query.where(Scan.subscription_id == subscription_id)
    if scan_status:
        query = query.where(Scan.status == scan_status)
    return list(db.scalars(query.offset(offset).limit(limit)))


@router.get("/scans/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/findings", response_model=list[FindingRead])
def list_findings(
    finding_status: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    subscription_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(Finding).join(Scan, Finding.scan_id == Scan.id).order_by(Finding.id.desc())
    if finding_status:
        query = query.where(Finding.status == finding_status)
    if severity:
        query = query.where(Finding.severity == severity.lower())
    if subscription_id is not None:
        query = query.where(Scan.subscription_id == subscription_id)
    return list(db.scalars(query.offset(offset).limit(limit)))


@router.get("/remediations", response_model=list[RemediationRead])
def list_remediations(
    finding_id: int | None = None,
    remediation_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(RemediationAction).order_by(RemediationAction.id.desc())
    if finding_id is not None:
        query = query.where(RemediationAction.finding_id == finding_id)
    if remediation_status:
        query = query.where(RemediationAction.status == remediation_status)
    return list(db.scalars(query.offset(offset).limit(limit)))


@router.post("/findings/{finding_id}/remediate", status_code=status.HTTP_202_ACCEPTED)
def remediate_finding(
    finding_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.status == "remediated":
        return {"status": "already_compliant", "finding_id": finding.id}
    if finding.status in {"exception", "remediating", "pending_approval", "approved"}:
        raise HTTPException(status_code=409, detail=f"Finding is currently {finding.status}")
    if finding.rule.rule_type == "required_tags":
        missing_tags = finding.details.get("missing_tags", [])
        configured_tags = finding.rule.parameters.get("tag_values", {})
        if any(tag not in configured_tags for tag in missing_tags):
            raise HTTPException(
                status_code=422,
                detail="Configure explicit tag_values in the policy before requesting remediation",
            )
    elif not (
        finding.rule.rule_type == "nsg_open_ports"
        and finding.rule.parameters.get("remediation_action") == "deny_exposed_rules"
        and finding.severity in {"high", "critical"}
    ):
        raise HTTPException(status_code=422, detail="No remediation is available for this finding")
    if finding.severity in {"high", "critical"}:
        finding.status = "pending_approval"
        action = RemediationAction(finding_id=finding.id, actor_id=actor.id, status="pending_approval")
        db.add(action)
        db.flush()
        record_event(
            db,
            event_type="remediation.approval_requested",
            entity_type="finding",
            entity_id=finding.id,
            actor_id=actor.id,
            metadata={"action_id": action.id},
        )
        db.commit()
        return {"action_id": action.id, "status": "pending_approval"}
    action = queue_remediation(db, finding, actor.id)
    db.commit()
    try:
        dispatch_remediation(action.id, background_tasks)
    except DispatchError as error:
        action.status = "failed"
        action.message = f"Dispatch error: {error}"[:2000]
        finding.status = "remediation_failed"
        record_event(
            db,
            event_type="remediation.dispatch_failed",
            entity_type="finding",
            entity_id=finding.id,
            actor_id=actor.id,
            metadata={"action_id": action.id},
        )
        db.commit()
        raise HTTPException(status_code=503, detail="Could not dispatch remediation worker") from error
    return {"action_id": action.id, "status": action.status}


@router.post("/findings/{finding_id}/approve", status_code=status.HTTP_202_ACCEPTED)
def approve_remediation(
    finding_id: int,
    payload: ApprovalRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles("admin", "security_officer")),
):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.status != "pending_approval" or finding.severity not in {"high", "critical"}:
        raise HTTPException(status_code=409, detail="Finding has no pending high-risk approval")
    action = db.scalar(
        select(RemediationAction)
        .where(
            RemediationAction.finding_id == finding.id,
            RemediationAction.status == "pending_approval",
        )
        .order_by(RemediationAction.id.desc())
        .limit(1)
    )
    if action is None:
        raise HTTPException(status_code=409, detail="Pending approval action not found")
    record_event(
        db,
        event_type="remediation.approval_decided",
        entity_type="finding",
        entity_id=finding.id,
        actor_id=actor.id,
        metadata={"approved": payload.approved, "reason": payload.reason},
    )
    if not payload.approved:
        action.status = "rejected"
        action.message = payload.reason
        finding.status = "open"
        db.commit()
        return {"action_id": action.id, "status": "rejected"}
    action.status = "queued"
    finding.status = "approved"
    db.commit()
    try:
        dispatch_remediation(action.id, background_tasks)
    except DispatchError as error:
        action.status = "failed"
        action.message = f"Dispatch error: {error}"[:2000]
        finding.status = "remediation_failed"
        record_event(
            db,
            event_type="remediation.dispatch_failed",
            entity_type="finding",
            entity_id=finding.id,
            actor_id=actor.id,
            metadata={"action_id": action.id},
        )
        db.commit()
        raise HTTPException(status_code=503, detail="Could not dispatch remediation worker") from error
    return {"action_id": action.id, "status": action.status}


@router.post("/findings/{finding_id}/exception", status_code=status.HTTP_201_CREATED)
def create_exception(
    finding_id: int,
    payload: ExceptionRequest,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles("admin", "cloud_engineer")),
):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    expires_at = payload.expires_at
    if expires_at.tzinfo is None:
        raise HTTPException(status_code=422, detail="expires_at must include a timezone")
    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=422, detail="expires_at must be in the future")
    if finding.status in {"remediated", "remediating", "pending_approval", "approved"}:
        raise HTTPException(status_code=409, detail=f"A finding in state {finding.status} cannot be excepted")
    exception = FindingException(
        finding_id=finding.id,
        actor_id=actor.id,
        reason=payload.reason,
        expires_at=expires_at,
    )
    finding.status = "exception"
    db.add(exception)
    db.flush()
    record_event(
        db,
        event_type="finding.exception_created",
        entity_type="finding",
        entity_id=finding.id,
        actor_id=actor.id,
        metadata={"exception_id": exception.id, "expires_at": expires_at.isoformat()},
    )
    db.commit()
    return {"exception_id": exception.id, "finding_id": finding.id, "expires_at": expires_at}


@router.get("/audit-logs", response_model=list[AuditRead])
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
):
    return list(db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).offset(offset).limit(limit)))


@router.get("/audit-logs/verify")
def check_audit_chain(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
):
    valid, invalid_event_id = verify_chain(db)
    return {"valid": valid, "invalid_event_id": invalid_event_id}
