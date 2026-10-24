
import typer
from sqlalchemy import select

from app.audit import record_event, verify_chain
from app.config import get_settings
from app.database import SessionLocal, engine, initialize_database
from app.models import PolicyRule, Scan, Subscription, User
from app.security import hash_password
from app.services.dispatcher import dispatch_scan

app = typer.Typer(help="CloudGuard administration and operations CLI.")


def _initialize() -> None:
    import app.models  # noqa: F401

    initialize_database(engine)


@app.command("create-admin")
def create_admin(
    email: str = typer.Option(..., prompt=True),
    password: str = typer.Option(
        ..., prompt=True, confirmation_prompt=True, hide_input=True, envvar="BOOTSTRAP_ADMIN_PASSWORD"
    ),
):
    """Create the first administrator account."""
    _initialize()
    db = SessionLocal()
    try:
        normalized = email.strip().lower()
        if db.scalar(select(User).where(User.email == normalized)):
            raise typer.BadParameter("This email already has an account")
        user = User(email=normalized, password_hash=hash_password(password), role="admin")
        db.add(user)
        db.flush()
        record_event(
            db,
            event_type="user.bootstrap_admin_created",
            entity_type="user",
            entity_id=user.id,
            actor_id=user.id,
            metadata={"role": "admin"},
        )
        db.commit()
        typer.echo(f"Administrator created: {user.email}")
    finally:
        db.close()


@app.command("seed-defaults")
def seed_defaults():
    """Create the starter Azure compliance rules; safe to run repeatedly."""
    _initialize()
    settings = get_settings()
    starter = [
        (
            "Required resource tags",
            "required_tags",
            "low",
            {"required_tags": settings.required_tags},
            False,
        ),
        (
            "Public SSH/RDP NSG exposure",
            "nsg_open_ports",
            "high",
            {"blocked_ports": [22, 3389]},
            False,
        ),
        (
            "Idle virtual machines",
            "idle_vm",
            "low",
            {"cpu_threshold_percent": settings.idle_cpu_threshold_percent},
            False,
        ),
        ("Unattached managed disks", "unattached_disk", "low", {}, False),
        (
            "Expiring Key Vault secrets",
            "expiring_secret",
            "high",
            {"days": settings.key_vault_expiry_days},
            False,
        ),
    ]
    db = SessionLocal()
    try:
        existing = set(db.scalars(select(PolicyRule.name)))
        added = 0
        for name, rule_type, severity, parameters, auto_remediate in starter:
            if name not in existing:
                policy = PolicyRule(
                    name=name,
                    rule_type=rule_type,
                    severity=severity,
                    parameters=parameters,
                    auto_remediate=auto_remediate,
                )
                db.add(policy)
                db.flush()
                record_event(
                    db,
                    event_type="policy.seeded",
                    entity_type="policy",
                    entity_id=policy.id,
                    actor_id=None,
                    metadata={"rule_type": rule_type, "severity": severity},
                )
                added += 1
        db.commit()
        typer.echo(f"Seeded {added} policy rule(s); {len(starter) - added} already existed.")
    finally:
        db.close()


@app.command()
def scan(subscription_id: int):
    """Run a scan immediately for a registered subscription's database ID."""
    _initialize()
    db = SessionLocal()
    try:
        subscription = db.get(Subscription, subscription_id)
        if subscription is None or not subscription.enabled:
            raise typer.BadParameter("Enabled subscription not found")
        scan_record = Scan(subscription_id=subscription.id, trigger_source="cli")
        db.add(scan_record)
        db.flush()
        record_event(
            db,
            event_type="scan.queued",
            entity_type="scan",
            entity_id=scan_record.id,
            actor_id=None,
            metadata={"trigger_source": "cli"},
        )
        db.commit()
        scan_record_id = scan_record.id
    finally:
        db.close()
    dispatch_scan(scan_record_id)
    typer.echo(f"Scan {scan_record_id} dispatched.")


@app.command("schedule-all")
def schedule_all():
    """Create and dispatch scans for all enabled subscriptions (CronJob entrypoint)."""
    _initialize()
    db = SessionLocal()
    try:
        subscriptions = list(
            db.scalars(select(Subscription).where(Subscription.enabled.is_(True)))
        )
        scan_ids = []
        for subscription in subscriptions:
            scan_record = Scan(subscription_id=subscription.id, trigger_source="schedule")
            db.add(scan_record)
            db.flush()
            scan_ids.append(scan_record.id)
            record_event(
                db,
                event_type="scan.queued",
                entity_type="scan",
                entity_id=scan_record.id,
                actor_id=None,
                metadata={"trigger_source": "schedule"},
            )
        db.commit()
    finally:
        db.close()
    for scan_id in scan_ids:
        dispatch_scan(scan_id)
    typer.echo(f"Dispatched scans for {len(scan_ids)} enabled subscription(s).")


@app.command("verify-audit")
def verify_audit():
    """Check the hash-linked audit log for unexpected modifications."""
    _initialize()
    db = SessionLocal()
    try:
        valid, invalid_id = verify_chain(db)
        if not valid:
            typer.echo(f"Audit chain invalid at event {invalid_id}.", err=True)
            raise typer.Exit(code=1)
        typer.echo("Audit chain is valid.")
    finally:
        db.close()


if __name__ == "__main__":
    app()
