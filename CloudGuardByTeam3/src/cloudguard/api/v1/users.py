from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from cloudguard.api.dependencies import get_current_user, require_roles
from cloudguard.core.security import hash_password
from cloudguard.db.session import get_db
from cloudguard.models import User, UserRole
from cloudguard.schemas.user import UserCreate, UserRead
router = APIRouter(prefix="/users", tags=["Users"])
@router.get("/me", response_model=UserRead)
def me(user: User = Depends(get_current_user)): return user
@router.get("", response_model=list[UserRead])
def list_users(_: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    return list(db.scalars(select(User).order_by(User.email)).all())
@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, _: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == payload.email)):
        raise HTTPException(409, "Email already exists")
    user = User(email=payload.email, full_name=payload.full_name, hashed_password=hash_password(payload.password), role=payload.role)
    db.add(user); db.commit(); db.refresh(user); return user
