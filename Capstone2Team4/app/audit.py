import hashlib
import json
from datetime import timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditChainHead, AuditLog


def record_event(
    db: Session,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str | int,
    actor_id: int | None,
    metadata: dict | None = None,
) -> AuditLog:
    head = db.scalar(
        select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update()
    )
    if head is None:
        raise RuntimeError("Audit chain is not initialized; initialize the database first")
    previous_hash = head.event_hash
    event = AuditLog(
        event_type=event_type,
        entity_type=entity_type,
        entity_id=str(entity_id),
        actor_id=actor_id,
        event_metadata=metadata or {},
        previous_hash=previous_hash,
        event_hash="0" * 64,
    )
    db.add(event)
    db.flush()
    created_at = event.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    payload = {
        "id": event.id,
        "event_type": event.event_type,
        "entity_type": event.entity_type,
        "entity_id": event.entity_id,
        "actor_id": event.actor_id,
        "event_metadata": event.event_metadata,
        "previous_hash": event.previous_hash,
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
    }
    event.event_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    head.event_hash = event.event_hash
    return event


def verify_chain(db: Session) -> tuple[bool, int | None]:
    previous_hash = "0" * 64
    for event in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        if event.previous_hash != previous_hash:
            return False, event.id
        created_at = event.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        payload = {
            "id": event.id,
            "event_type": event.event_type,
            "entity_type": event.entity_type,
            "entity_id": event.entity_id,
            "actor_id": event.actor_id,
            "event_metadata": event.event_metadata,
            "previous_hash": event.previous_hash,
            "created_at": created_at.astimezone(timezone.utc).isoformat(),
        }
        calculated = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        if calculated != event.event_hash:
            return False, event.id
        previous_hash = event.event_hash
    head = db.get(AuditChainHead, 1)
    if head is None or head.event_hash != previous_hash:
        return False, None
    return True, None
