import time
from datetime import datetime, timezone

from app.audit import record_event
from app.config import get_settings
from app.database import SessionLocal
from app.models import Finding, RemediationAction, Scan, Subscription
from app.providers.base import ProviderError
from app.providers.factory import get_provider


def execute_remediation(action_id: int) -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        action = db.get(RemediationAction, action_id)
        if action is None:
            raise ValueError(f"Remediation action {action_id} does not exist")
        finding = db.get(Finding, action.finding_id)
        if finding is None:
            raise ValueError(f"Finding for remediation action {action_id} does not exist")
        scan = db.get(Scan, finding.scan_id)
        if scan is None:
            raise ValueError(f"Scan for remediation action {action_id} does not exist")
        subscription = db.get(Subscription, scan.subscription_id)
        if subscription is None:
            raise ValueError(f"Subscription for remediation action {action_id} does not exist")
        rule = finding.rule
        if finding.status == "remediated":
            action.status = "succeeded"
            action.message = "Already compliant; no change was needed."
            action.completed_at = datetime.now(timezone.utc)
            db.commit()
            return
        if rule.rule_type not in {"required_tags", "nsg_open_ports"}:
            raise ValueError(f"No remediation implementation is available for {rule.rule_type}")
        if finding.severity in {"high", "critical"} and finding.status != "approved":
            raise PermissionError("High-risk remediation requires explicit approval")

        action.status = "running"
        finding.status = "remediating"
        db.commit()
        resource = {"id": finding.resource_id, "name": finding.resource_name}
        last_error: Exception | None = None
        for attempt in range(1, settings.remediation_max_retries + 1):
            action.attempt_count = attempt
            db.commit()
            try:
                if rule.rule_type == "required_tags":
                    configured_tags = rule.parameters.get("tag_values", {})
                    tags = {
                        tag: configured_tags[tag]
                        for tag in finding.details.get("missing_tags", [])
                        if tag in configured_tags
                    }
                    if not tags:
                        raise ValueError(
                            "No explicit remediation values are configured for the missing tags"
                        )
                    changed = get_provider().ensure_tags(
                        subscription.subscription_id, resource, tags
                    )
                else:
                    if rule.parameters.get("remediation_action") != "deny_exposed_rules":
                        raise ValueError("No approved NSG remediation action is configured")
                    rule_names = list(
                        {
                            item["rule"]
                            for item in finding.details.get("exposed_rules", [])
                            if item.get("rule")
                        }
                    )
                    if not rule_names:
                        raise ValueError("Finding does not identify an NSG rule to remediate")
                    changed = get_provider().deny_nsg_rules(
                        subscription.subscription_id, resource, rule_names
                    )
                last_error = None
                if rule.rule_type == "required_tags":
                    message = (
                        "Required tags applied."
                        if changed
                        else "Already compliant; no change was needed."
                    )
                else:
                    message = (
                        "Exposed NSG rules denied."
                        if changed
                        else "NSG rules were already denied; no change was needed."
                    )
                break
            except (ProviderError, TimeoutError, ConnectionError) as error:
                last_error = error
                if attempt < settings.remediation_max_retries:
                    time.sleep(settings.remediation_retry_base_seconds * (2 ** (attempt - 1)))

        completed_action = db.get(RemediationAction, action_id)
        completed_finding = db.get(Finding, finding.id)
        if completed_action is None or completed_finding is None:
            raise ValueError(f"Remediation action {action_id} or its finding was removed")
        action = completed_action
        finding = completed_finding
        now = datetime.now(timezone.utc)
        if last_error is not None:
            action.status = "failed"
            action.message = f"{type(last_error).__name__}: {last_error}"[:2000]
            finding.status = "remediation_failed"
            record_event(
                db,
                event_type="remediation.failed",
                entity_type="finding",
                entity_id=finding.id,
                actor_id=action.actor_id,
                metadata={"action_id": action.id, "attempts": action.attempt_count},
            )
            action.completed_at = now
            db.commit()
            raise RuntimeError(f"Remediation failed after {action.attempt_count} attempts") from last_error

        action.status = "succeeded"
        action.message = message
        action.completed_at = now
        finding.status = "remediated"
        record_event(
            db,
            event_type="remediation.succeeded",
            entity_type="finding",
            entity_id=finding.id,
            actor_id=action.actor_id,
            metadata={"action_id": action.id, "attempts": action.attempt_count, "message": message},
        )
        db.commit()
    finally:
        db.close()


def queue_remediation(db, finding: Finding, actor_id: int | None) -> RemediationAction:
    action = RemediationAction(finding_id=finding.id, actor_id=actor_id, status="queued")
    finding.status = "approved" if finding.severity in {"high", "critical"} else "open"
    db.add(action)
    db.flush()
    record_event(
        db,
        event_type="remediation.queued",
        entity_type="finding",
        entity_id=finding.id,
        actor_id=actor_id,
        metadata={"action_id": action.id},
    )
    return action
