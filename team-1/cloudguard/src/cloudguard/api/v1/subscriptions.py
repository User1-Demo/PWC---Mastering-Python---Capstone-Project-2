from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from ...database import get_db
from ... import models, schemas, audit
from ...security import require_roles, get_current_user

router = APIRouter(prefix="/subscriptions", tags=["subscriptions"])


@router.get("", response_model=List[schemas.SubscriptionOut])
def list_subscriptions(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return db.query(models.Subscription).all()


@router.post("", response_model=schemas.SubscriptionOut)
def create_subscription(
    payload: schemas.SubscriptionCreate,
    db: Session = Depends(get_db),
    user=Depends(require_roles("admin")),
):
    sub = models.Subscription(**payload.model_dump())
    db.add(sub)
    db.commit()
    audit.write_audit(db, action="SUBSCRIPTION_CREATED", entity_type="Subscription",
                       entity_id=sub.id, actor=user.id, metadata={"name": sub.name})
    return sub