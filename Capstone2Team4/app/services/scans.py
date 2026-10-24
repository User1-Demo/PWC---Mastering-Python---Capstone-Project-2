from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.audit import record_event
from app.config import get_settings
from app.database import SessionLocal
from app.models import (
    Finding,
    FindingException,
    PolicyRule,
    RemediationAction,
    Scan,
    Subscription,
    utcnow,
)
from app.providers.base import ProviderError
from app.providers.factory import get_provider
from app.rules.engine import evaluate_resource


def execute_scan(scan_id: int) -> None:
    db = SessionLocal()
    action_ids: list[int] = []
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} does not exist")
        subscription = db.get(Subscription, scan.subscription_id)
        if subscription is None:
            raise ValueError(f"Subscription for scan {scan_id} does not exist")
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        record_event(
            db,
            event_type="scan.started",
            entity_type="scan",
            entity_id=scan.id,
            actor_id=None,
            metadata={"subscription_id": subscription.subscription_id},
        )
        db.commit()

        provider = get_provider()
        resources = provider.list_resources(subscription.subscription_id)
        rules = list(db.scalars(select(PolicyRule).where(PolicyRule.enabled.is_(True))))
        settings = get_settings()
        for resource in resources:
            for result in evaluate_resource(resource, rules):
                rule = result["rule"]
                resource_id = resource.get("id") or resource.get("name") or "unknown"
                active_exception = db.scalar(
                    select(FindingException)
                    .join(Finding, FindingException.finding_id == Finding.id)
                    .where(
                        Finding.resource_id == resource_id,
                        Finding.rule_id == rule.id,
                        FindingException.expires_at > utcnow(),
                    )
                    .limit(1)
                )
                if active_exception:
                    continue

                expired = db.scalars(
                    select(FindingException)
                    .join(Finding, FindingException.finding_id == Finding.id)
                    .where(
                        Finding.resource_id == resource_id,
                        Finding.rule_id == rule.id,
                        FindingException.expires_at <= utcnow(),
                        Finding.status == "exception",
                    )
                )
                for old_exception in expired:
                    old_finding = db.get(Finding, old_exception.finding_id)
                    if old_finding is None:
                        continue
                    old_finding.status = "open"
                    record_event(
                        db,
                        event_type="finding.exception_expired",
                        entity_type="finding",
                        entity_id=old_finding.id,
                        actor_id=None,
                        metadata={"exception_id": old_exception.id},
                    )

                finding = Finding(
                    scan_id=scan.id,
                    rule_id=rule.id,
                    resource_id=resource_id,
                    resource_name=resource.get("name") or resource_id,
                    resource_type=resource.get("type") or "unknown",
                    severity=rule.severity,
                    status="open",
                    title=result["title"],
                    details=result["details"],
                )
                db.add(finding)
                db.flush()
                record_event(
                    db,
                    event_type="finding.created",
                    entity_type="finding",
                    entity_id=finding.id,
                    actor_id=None,
                    metadata={"rule_id": rule.id, "severity": rule.severity},
                )
                if (
                    rule.rule_type == "required_tags"
                    and rule.auto_remediate
                    and rule.severity == "low"
                    and settings.auto_remediate_low_risk
                    and all(
                        tag in (rule.parameters.get("tag_values") or {})
                        for tag in result["details"]["missing_tags"]
                    )
                ):
                    action = RemediationAction(finding_id=finding.id, actor_id=None, status="queued")
                    db.add(action)
                    db.flush()
                    action_ids.append(action.id)
                    record_event(
                        db,
                        event_type="remediation.queued",
                        entity_type="finding",
                        entity_id=finding.id,
                        actor_id=None,
                        metadata={"action_id": action.id, "source": "auto"},
                    )

        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        record_event(
            db,
            event_type="scan.completed",
            entity_type="scan",
            entity_id=scan.id,
            actor_id=None,
            metadata={"resources_scanned": len(resources)},
        )
        db.commit()
    except (ProviderError, SQLAlchemyError, ValueError, TypeError, KeyError, AttributeError) as error:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.error_message = f"{type(error).__name__}: {error}"[:2000]
            scan.completed_at = datetime.now(timezone.utc)
            record_event(
                db,
                event_type="scan.failed",
                entity_type="scan",
                entity_id=scan.id,
                actor_id=None,
                metadata={"error_type": type(error).__name__},
            )
            db.commit()
        raise
    finally:
        db.close()

    from app.services.dispatcher import DispatchError, dispatch_remediation

    for action_id in action_ids:
        try:
            dispatch_remediation(action_id)
        except DispatchError as error:
            failure_db = SessionLocal()
            try:
                failed_action = failure_db.get(RemediationAction, action_id)
                if failed_action is not None:
                    failed_finding = failure_db.get(Finding, failed_action.finding_id)
                    failed_action.status = "failed"
                    failed_action.message = f"Dispatch error: {error}"[:2000]
                    failed_action.completed_at = datetime.now(timezone.utc)
                    if failed_finding is not None:
                        failed_finding.status = "remediation_failed"
                        record_event(
                            failure_db,
                            event_type="remediation.dispatch_failed",
                            entity_type="finding",
                            entity_id=failed_finding.id,
                            actor_id=None,
                            metadata={"action_id": failed_action.id},
                        )
                    failure_db.commit()
            finally:
                failure_db.close()
