import typer
from sqlalchemy import select

from cloudguard.azure.mock_inventory import MockInventoryProvider
from cloudguard.core.database import SessionLocal
from cloudguard.models.finding import Finding
from cloudguard.services.remediation_service import request_remediation
from cloudguard.services.scan_service import run_scan

app = typer.Typer(
    name="cloudguard",
    help="CloudGuard compliance and remediation CLI",
)


@app.callback()
def main() -> None:
    """CloudGuard compliance and remediation CLI."""


@app.command()
def health() -> None:
    """Check whether the CloudGuard CLI is working."""
    typer.echo("CloudGuard CLI is healthy")


@app.command()
def scan(
    subscription_id: int = typer.Option(
        ...,
        "--subscription-id",
        help="CloudGuard database ID of the subscription to scan",
    ),
) -> None:
    """Run a compliance scan."""

    db = SessionLocal()

    try:
        scan_result = run_scan(
            db=db,
            subscription_db_id=subscription_id,
            actor="cli",
            inventory_provider=MockInventoryProvider(),
        )

        typer.echo(
            f"Scan {scan_result.id} completed "
            f"with status: {scan_result.status}"
        )

    except ValueError as error:
        typer.echo(f"Error: {error}")
        raise typer.Exit(code=1) from error

    finally:
        db.close()

@app.command()
def findings(
    scan_id: int | None = typer.Option(
        None,
        "--scan-id",
        help="Show findings for a specific scan",
    ),
) -> None:
    """List compliance findings."""

    db = SessionLocal()

    try:
        statement = select(Finding)

        if scan_id is not None:
            statement = statement.where(
                Finding.scan_id == scan_id
            )

        statement = statement.order_by(Finding.id)

        results = list(
            db.scalars(statement).all()
        )

        if not results:
            typer.echo("No findings found")
            return

        for finding in results:
            typer.echo(
                f"[{finding.id}] "
                f"{finding.resource_name} | "
                f"{finding.severity} | "
                f"{finding.status} | "
                f"{finding.message}"
            )

    finally:
        db.close()

@app.command()
def remediate(
    finding_id: int = typer.Option(
        ...,
        "--finding-id",
        help="Finding ID to remediate",
    ),
) -> None:
    """Request remediation for a finding."""

    db = SessionLocal()

    try:
        remediation = request_remediation(
            db=db,
            finding_id=finding_id,
            requested_by="cli",
        )

        typer.echo(
            f"Remediation {remediation.id} | "
            f"finding={remediation.finding_id} | "
            f"status={remediation.status} | "
            f"action={remediation.action_type}"
        )

    except ValueError as error:
        typer.echo(f"Error: {error}")
        raise typer.Exit(code=1) from error

    finally:
        db.close()



if __name__ == "__main__":
    app()