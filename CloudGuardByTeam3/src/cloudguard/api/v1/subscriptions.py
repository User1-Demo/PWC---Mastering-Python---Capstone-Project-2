from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from cloudguard.api.dependencies import get_current_user, require_roles
from cloudguard.db.session import get_db
from cloudguard.models import Subscription, User, UserRole
from cloudguard.schemas.subscription import SubscriptionCreate, SubscriptionRead
router = APIRouter(prefix="/subscriptions", tags=["Subscriptions"])
@router.get("", response_model=list[SubscriptionRead])
def list_subscriptions(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return list(db.scalars(select(Subscription).order_by(Subscription.name)).all())
@router.post("", response_model=SubscriptionRead, status_code=status.HTTP_201_CREATED)
def create_subscription(payload: SubscriptionCreate, _: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    if db.scalar(select(Subscription).where(Subscription.azure_subscription_id == payload.azure_subscription_id)):
        raise HTTPException(409, "Azure subscription already registered")
    item = Subscription(**payload.model_dump()); db.add(item); db.commit(); db.refresh(item); return item
