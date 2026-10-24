from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from capstone2.audit import write_audit
from capstone2.database import get_db
from capstone2.models import ApprovedException, AuditLog, Finding, FindingStatus, PolicyRule, Role, Scan, Subscription, User
from capstone2.schemas import *
from capstone2.security import create_token, current_user, require_roles, verify_password
from capstone2.services import remediate, run_scan
router=APIRouter(prefix="/api/v1")
@router.post("/auth/login",response_model=Token)
def login(body:LoginRequest,db:Session=Depends(get_db)):
    user=db.scalar(select(User).where(User.username==body.username))
    if not user or not verify_password(body.password,user.password_hash): raise HTTPException(401,"Invalid credentials")
    return Token(access_token=create_token(user))
@router.get("/health")
def health(): return {"status":"ok"}
@router.get("/subscriptions",response_model=list[SubscriptionRead])
def list_subscriptions(db:Session=Depends(get_db),_:User=Depends(current_user)): return db.scalars(select(Subscription)).all()
@router.post("/subscriptions",response_model=SubscriptionRead,status_code=201)
def create_subscription(body:SubscriptionCreate,db:Session=Depends(get_db),user:User=Depends(require_roles(Role.ADMIN.value))):
    item=Subscription(**body.model_dump()); db.add(item); db.flush(); write_audit(db,"subscription.created","subscription",item.id,user.id); db.commit(); db.refresh(item); return item
@router.get("/policies",response_model=list[PolicyRead])
def list_policies(db:Session=Depends(get_db),_:User=Depends(current_user)): return db.scalars(select(PolicyRule)).all()
@router.post("/policies",response_model=PolicyRead,status_code=201)
def create_policy(body:PolicyCreate,db:Session=Depends(get_db),user:User=Depends(require_roles(Role.ADMIN.value))):
    item=PolicyRule(**body.model_dump()); db.add(item); db.flush(); write_audit(db,"policy.created","policy",item.id,user.id); db.commit(); db.refresh(item); return item
@router.post("/scans",response_model=ScanRead,status_code=201)
def create_scan(body:ScanCreate,db:Session=Depends(get_db),user:User=Depends(require_roles(Role.ADMIN.value,Role.CLOUD_ENGINEER.value,Role.SERVICE.value))):
    if not db.get(Subscription,body.subscription_id): raise HTTPException(404,"Subscription not found")
    scan=Scan(subscription_id=body.subscription_id,trigger_source="api"); db.add(scan); db.flush(); write_audit(db,"scan.started","scan",scan.id,user.id); db.commit(); return run_scan(db,scan,user.id)
@router.get("/scans",response_model=list[ScanRead])
def list_scans(db:Session=Depends(get_db),_:User=Depends(current_user)): return db.scalars(select(Scan).order_by(Scan.id.desc())).all()
@router.get("/scans/{scan_id}",response_model=ScanRead)
def get_scan(scan_id:int,db:Session=Depends(get_db),_:User=Depends(current_user)):
    item=db.get(Scan,scan_id)
    if not item: raise HTTPException(404,"Scan not found")
    return item
@router.get("/findings",response_model=list[FindingRead])
def findings(status:str|None=None,severity:str|None=None,db:Session=Depends(get_db),_:User=Depends(current_user)):
    q=select(Finding).order_by(Finding.id.desc())
    if status: q=q.where(Finding.status==status)
    if severity: q=q.where(Finding.severity==severity)
    return db.scalars(q).all()
@router.post("/findings/{finding_id}/remediate")
def request_remediation(finding_id:int,db:Session=Depends(get_db),user:User=Depends(require_roles(Role.ADMIN.value,Role.CLOUD_ENGINEER.value))):
    item=db.get(Finding,finding_id)
    if not item: raise HTTPException(404,"Finding not found")
    return remediate(db,item,user.id)
@router.post("/findings/{finding_id}/approve")
def approve(finding_id:int,db:Session=Depends(get_db),user:User=Depends(require_roles(Role.SECURITY_OFFICER.value,Role.ADMIN.value))):
    item=db.get(Finding,finding_id)
    if not item: raise HTTPException(404,"Finding not found")
    return remediate(db,item,user.id,approved=True)
@router.post("/findings/{finding_id}/exception")
def create_exception(finding_id:int,body:ExceptionCreate,db:Session=Depends(get_db),user:User=Depends(require_roles(Role.ADMIN.value,Role.CLOUD_ENGINEER.value,Role.SECURITY_OFFICER.value))):
    if body.expires_at<=datetime.now(timezone.utc): raise HTTPException(422,"Expiry must be in the future")
    item=db.get(Finding,finding_id)
    if not item: raise HTTPException(404,"Finding not found")
    ex=ApprovedException(finding_id=item.id,reason=body.reason,expires_at=body.expires_at,approved_by=user.id); db.add(ex); item.status=FindingStatus.EXCEPTED.value; write_audit(db,"exception.created","finding",item.id,user.id,{"expires_at":body.expires_at.isoformat()}); db.commit(); return {"status":"excepted"}
@router.get("/audit-logs",response_model=list[AuditRead])
def audit_logs(db:Session=Depends(get_db),_:User=Depends(require_roles(Role.ADMIN.value,Role.SECURITY_OFFICER.value))): return db.scalars(select(AuditLog).order_by(AuditLog.id.desc())).all()
