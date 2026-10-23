from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from cloudguard.core.auth import require_role
from cloudguard.core.database import get_db
from cloudguard.models.subscription import Subscription
from cloudguard.models.user import User
from cloudguard.schemas.subscription import (
    SubscriptionCreate,
    SubscriptionResponse,
)

router = APIRouter(
    prefix="/api/v1/subscriptions",
    tags=["Subscriptions"],
)


@router.post("", response_model=SubscriptionResponse, status_code=201)
def create_subscription(
    subscription: SubscriptionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin")
    ),
):
    db_subscription = Subscription(
        subscription_id=subscription.subscription_id,
        name=subscription.name,
        environment=subscription.environment,
    )

    db.add(db_subscription)
    db.commit()
    db.refresh(db_subscription)

    return db_subscription


@router.get("", response_model=list[SubscriptionResponse])
def list_subscriptions(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "admin",
            "cloud_engineer",
            "security_officer",
        )
    ),
):
    return db.query(Subscription).all()