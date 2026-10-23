from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudguard.azure.inventory import InventoryProvider
from cloudguard.azure.mock_inventory import MockInventoryProvider
from cloudguard.models.finding import Finding
from cloudguard.models.policy_rule import PolicyRule
from cloudguard.models.scan import Scan
from cloudguard.models.subscription import Subscription
from cloudguard.policies.required_tag import evaluate_required_tag
from cloudguard.policies.risky_nsg import evaluate_risky_nsg
from cloudguard.services.audit_service import create_audit_log


def run_scan(
    db: Session,
    subscription_db_id: int,
    actor: str,
    inventory_provider: InventoryProvider | None = None,
) -> Scan:
    if inventory_provider is None:
        inventory_provider = MockInventoryProvider()
    subscription = db.get(Subscription, subscription_db_id)

    if subscription is None:
        raise ValueError("Subscription not found")

    scan = Scan(
        subscription_id=subscription.id,
        trigger_source="api",
        status="running",
        started_at=datetime.utcnow(),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    create_audit_log(
        db,
        event_type="scan_started",
        entity_type="scan",
        entity_id=scan.id,
        actor=actor,
        action="run_scan",
        details=f"Compliance scan started for subscription {subscription.id}",
    )

    db.commit()
    try:
        resources = inventory_provider.list_resources()

        policies = list(
            db.scalars(
                select(PolicyRule).where(
                    PolicyRule.enabled.is_(True)
                )
            ).all()
        )
        for policy in policies:
            if policy.rule_type == "required_tag":
                required_tag = "Environment"

                for resource in resources:
                    violation = evaluate_required_tag(
                        resource=resource,
                        required_tag=required_tag,
                    )

                    if violation is None:
                        continue

                    finding = Finding(
                        scan_id=scan.id,
                        policy_rule_id=policy.id,
                        resource_id=violation.resource_id,
                        resource_name=violation.resource_name,
                        resource_type=violation.resource_type,
                        severity=policy.severity,
                        status="open",
                        message=violation.message,
                    )
                    db.add(finding)
                    db.flush()

                    create_audit_log(
                        db,
                        event_type="finding_created",
                        entity_type="finding",
                        entity_id=finding.id,
                        actor="system",
                        action="create_finding",
                        details=finding.message,
                    )

            elif policy.rule_type == "risky_nsg":
                for resource in resources:
                    violations = evaluate_risky_nsg(resource)

                    for violation in violations:
                        finding = Finding(
                            scan_id=scan.id,
                            policy_rule_id=policy.id,
                            resource_id=violation.resource_id,
                            resource_name=violation.resource_name,
                            resource_type=violation.resource_type,
                            severity=policy.severity,
                            status="open",
                            message=violation.message,
                        )

                        db.add(finding)
                        db.flush()

                        create_audit_log(
                            db,
                            event_type="finding_created",
                            entity_type="finding",
                            entity_id=finding.id,
                            actor=actor,
                            action="create_finding",
                            details=finding.message,
                        )

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()

        create_audit_log(
            db,
            event_type="scan_completed",
            entity_type="scan",
            entity_id=scan.id,
            actor=actor,
            action="complete_scan",
            details="Compliance scan completed successfully",
        )

        db.commit()
        db.refresh(scan)

        return scan

    except Exception:
        db.rollback()

        # Reload because rollback expires/reverts pending session state.
        scan = db.get(Scan, scan.id)

        if scan is not None:
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            create_audit_log(
                db,
                event_type="scan_failed",
                entity_type="scan",
                entity_id=scan.id,
                actor=actor,
                action="fail_scan",
                details="Compliance scan failed",
            )
            db.commit()

        raise