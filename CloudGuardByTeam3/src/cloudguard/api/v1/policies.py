from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from cloudguard.api.dependencies import get_current_user, require_roles
from cloudguard.db.session import get_db
from cloudguard.models import PolicyRule, User, UserRole
from cloudguard.schemas.policy import PolicyCreate, PolicyRead
router = APIRouter(prefix="/policies", tags=["Policies"])
@router.get("", response_model=list[PolicyRead])
def list_policies(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return list(db.scalars(select(PolicyRule).order_by(PolicyRule.name)).all())
@router.post("", response_model=PolicyRead, status_code=status.HTTP_201_CREATED)
def create_policy(payload: PolicyCreate, user: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    if db.scalar(select(PolicyRule).where(PolicyRule.name == payload.name)):
        raise HTTPException(409, "Policy name already exists")
    item = PolicyRule(**payload.model_dump(), created_by_id=user.id); db.add(item); db.commit(); db.refresh(item); return item
