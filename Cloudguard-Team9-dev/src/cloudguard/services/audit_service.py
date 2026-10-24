from sqlalchemy.orm import Session

from cloudguard.models.audit_log import AuditLog


def create_audit_log(
    db: Session,
    *,
    event_type: str,
    entity_type: str,
    actor: str,
    action: str,
    entity_id: int | None = None,
    details: str | None = None,
) -> AuditLog:
    audit_log = AuditLog(
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        action=action,
        details=details,
    )

    db.add(audit_log)

    return audit_log