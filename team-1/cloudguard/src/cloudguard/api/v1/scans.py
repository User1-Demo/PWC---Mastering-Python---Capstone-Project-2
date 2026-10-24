from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ...database import get_db
from ... import models, schemas, audit
from ...security import get_current_user
from ...k8s_dispatcher import dispatch_scan_job

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=schemas.ScanOut)
def trigger_scan(payload: schemas.ScanTrigger, db: Session = Depends(get_db),
                  user=Depends(get_current_user)):
    sub = db.query(models.Subscription).filter(models.Subscription.id == payload.subscription_id).first()
    if not sub:
        raise HTTPException(404, "Subscription not found")
    scan = models.Scan(subscription_id=sub.id, triggered_by=user.id, trigger_source="api")
    db.add(scan)
    db.commit()
    audit.write_audit(db, action="SCAN_TRIGGERED", entity_type="Scan", entity_id=scan.id, actor=user.id)
    dispatch_scan_job(scan.id)
    db.refresh(scan)
    return scan


@router.get("/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan