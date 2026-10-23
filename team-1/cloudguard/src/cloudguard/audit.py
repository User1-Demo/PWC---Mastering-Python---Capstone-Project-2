import hashlib
import json
from datetime import datetime
from sqlalchemy.orm import Session
from . import models


def _hash_record(prev_hash: str | None, payload: dict) -> str:
    base = json.dumps(payload, sort_keys=True, default=str) + (prev_hash or "")
    return hashlib.sha256(base.encode()).hexdigest()


def write_audit(
    db: Session,
    *,
    action: str,
    entity_type: str,
    entity_id: str,
    actor: str,
    metadata: dict | None = None,
) -> models.AuditLog:
    last = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).first()
    prev_hash = last.record_hash if last else None

    payload = {
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "actor": actor,
        "metadata": metadata or {},
        "timestamp": datetime.utcnow().isoformat(),
    }
    record_hash = _hash_record(prev_hash, payload)

    log = models.AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        metadata_json=metadata or {},
        prev_hash=prev_hash,
        record_hash=record_hash,
    )
    db.add(log)
    db.commit()
    return log


def verify_chain(db: Session) -> bool:
    """Replays the hash chain to detect tampering."""
    logs = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.asc()).all()
    prev_hash = None
    for log in logs:
        payload = {
            "action": log.action,
            "entity_type": log.entity_type,
            "entity_id": log.entity_id,
            "actor": log.actor,
            "metadata": log.metadata_json or {},
            "timestamp": log.timestamp.isoformat(),
        }
        expected = _hash_record(prev_hash, payload)
        if expected != log.record_hash:
            return False
        prev_hash = log.record_hash
    return True