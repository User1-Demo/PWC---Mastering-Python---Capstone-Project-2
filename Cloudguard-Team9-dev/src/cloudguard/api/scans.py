from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudguard.core.auth import require_role
from cloudguard.core.database import get_db
from cloudguard.models.scan import Scan
from cloudguard.models.user import User
from cloudguard.schemas.scan import ScanCreate, ScanResponse
from cloudguard.services.scan_service import run_scan

router = APIRouter(
    prefix="/api/v1/scans",
    tags=["Scans"],
)


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_scan(
    scan_request: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "admin",
            "cloud_engineer",
        )
    ),
) -> Scan:
    try:
        return run_scan(
            db=db,
            subscription_db_id=scan_request.subscription_id,
            actor=current_user.username,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error


@router.get(
    "",
    response_model=list[ScanResponse],
)
def list_scans(
    db: Session = Depends(get_db),
) -> list[Scan]:
    return list(
        db.scalars(
            select(Scan).order_by(Scan.created_at.desc())
        ).all()
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
) -> Scan:
    scan = db.get(Scan, scan_id)

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return scan