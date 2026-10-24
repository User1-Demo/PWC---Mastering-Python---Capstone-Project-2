from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from ...database import get_db
from ... import models, schemas, audit
from ...security import require_roles, get_current_user

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=List[schemas.PolicyRuleOut])
def list_policies(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return db.query(models.PolicyRule).all()


@router.post("", response_model=schemas.PolicyRuleOut)
def create_policy(
    payload: schemas.PolicyRuleCreate,     # Pydantic validates condition/resource_type (FR data req.)
    db: Session = Depends(get_db),
    user=Depends(require_roles("admin")),
):
    rule = models.PolicyRule(**payload.model_dump())
    db.add(rule)
    db.commit()
    audit.write_audit(db, action="POLICY_CREATED", entity_type="PolicyRule",
                       entity_id=rule.id, actor=user.id, metadata={"name": rule.name})
    return rule