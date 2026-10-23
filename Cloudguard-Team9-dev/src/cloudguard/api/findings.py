from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudguard.core.auth import require_role
from cloudguard.core.database import get_db
from cloudguard.models.finding import Finding
from cloudguard.models.user import User
from cloudguard.schemas.finding import FindingResponse
from cloudguard.schemas.remediation import RemediationResponse
from cloudguard.services.remediation_service import (
    approve_remediation,
    request_remediation,
)

router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
)


@router.get(
    "",
    response_model=list[FindingResponse],
)
def list_findings(
    severity: str | None = Query(default=None),
    finding_status: str | None = Query(default=None, alias="status"),
    scan_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "admin",
            "cloud_engineer",
            "security_officer",
        )
    ),
) -> list[Finding]:
    statement = select(Finding)

    if severity:
        statement = statement.where(Finding.severity == severity)

    if finding_status:
        statement = statement.where(Finding.status == finding_status)

    if scan_id:
        statement = statement.where(Finding.scan_id == scan_id)

    statement = statement.order_by(Finding.created_at.desc())

    return list(db.scalars(statement).all())


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "admin",
            "cloud_engineer",
            "security_officer",
        )
    ),
) -> Finding:
    finding = db.get(Finding, finding_id)

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return finding

@router.post(
    "/{finding_id}/remediate",
    response_model=RemediationResponse,
)
def remediate_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "admin",
            "cloud_engineer",
        )
    ),
):
    try:
        return request_remediation(
            db=db,
            finding_id=finding_id,
            requested_by=current_user.username,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

@router.post(
    "/{finding_id}/approve",
    response_model=RemediationResponse,
)
def approve_finding_remediation(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("security_officer")
    ),
):
    try:
        return approve_remediation(
            db=db,
            finding_id=finding_id,
            approved_by=current_user.username,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
