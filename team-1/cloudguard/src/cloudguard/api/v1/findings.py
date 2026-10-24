from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List

from ...database import get_db
from ... import models, schemas, audit
from ...security import get_current_user, require_roles
from ...remediation.executor import RemediationExecutor
from ...k8s_dispatcher import dispatch_remediation_job

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=List[schemas.FindingOut])
def list_findings(
    status_: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    subscription_id: Optional[str] = None,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    q = db.query(models.Finding)
    if status_:
        q = q.filter(models.Finding.status == status_)
    if severity:
        q = q.filter(models.Finding.severity == severity)
    if subscription_id:
        q = q.filter(models.Finding.subscription_id == subscription_id)
    return q.all()


@router.post("/{finding_id}/remediate")
def remediate_finding(finding_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    job_name = dispatch_remediation_job(finding_id, actor=user.id, approved=False)
    audit.write_audit(db, action="REMEDIATION_REQUESTED", entity_type="Finding",
                       entity_id=finding.id, actor=user.id)
    return {"job": job_name, "status": "dispatched"}


@router.post("/{finding_id}/approve")
def approve_finding(finding_id: str, db: Session = Depends(get_db),
                     user=Depends(require_roles("security_officer"))):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    job_name = dispatch_remediation_job(finding_id, actor=user.id, approved=True)
    audit.write_audit(db, action="REMEDIATION_APPROVED", entity_type="Finding",
                       entity_id=finding.id, actor=user.id)
    return {"job": job_name, "status": "approved_and_dispatched"}


@router.post("/{finding_id}/exception")
def create_exception(finding_id: str, payload: schemas.ExceptionCreate,
                      db: Session = Depends(get_db),
                      user=Depends(require_roles("cloud_engineer", "security_officer", "admin"))):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if payload.expiry_date <= datetime.utcnow():
        raise HTTPException(400, "expiry_date must be in the future")   # BR-004
    exc = models.Exception(finding_id=finding.id, approved_by=user.id,
                            reason=payload.reason, expiry_date=payload.expiry_date)
    finding.status = models.FindingStatusEnum.EXCEPTION
    db.add(exc)
    db.commit()
    audit.write_audit(db, action="EXCEPTION_APPROVED", entity_type="Finding",
                       entity_id=finding.id, actor=user.id,
                       metadata={"expiry": payload.expiry_date.isoformat()})
    return {"status": "exception_created", "expiry_date": payload.expiry_date}