from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from ...database import get_db
from ... import models, schemas
from ...security import require_roles

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=List[schemas.AuditLogOut])
def list_audit_logs(db: Session = Depends(get_db), user=Depends(require_roles("admin"))):
    return db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(500).all()