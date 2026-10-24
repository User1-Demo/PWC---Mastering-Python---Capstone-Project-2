from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudguard.core.auth import require_role
from cloudguard.core.database import get_db
from cloudguard.models.audit_log import AuditLog
from cloudguard.models.user import User
from cloudguard.schemas.audit_log import AuditLogResponse

router = APIRouter(
    prefix="/api/v1/audit-logs",
    tags=["Audit Logs"],
)


@router.get(
    "",
    response_model=list[AuditLogResponse],
)
def list_audit_logs(
    event_type: str | None = Query(default=None),
    entity_type: str | None = Query(default=None),
    entity_id: int | None = Query(default=None),
    actor: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "admin",
            "security_officer",
        )
    ),
) -> list[AuditLog]:
    statement = select(AuditLog)

    if event_type:
        statement = statement.where(
            AuditLog.event_type == event_type
        )

    if entity_type:
        statement = statement.where(
            AuditLog.entity_type == entity_type
        )

    if entity_id is not None:
        statement = statement.where(
            AuditLog.entity_id == entity_id
        )

    if actor:
        statement = statement.where(
            AuditLog.actor == actor
        )

    statement = statement.order_by(
        AuditLog.created_at.desc()
    )

    return list(db.scalars(statement).all())