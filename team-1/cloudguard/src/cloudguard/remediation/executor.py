import time
from datetime import datetime
from sqlalchemy.orm import Session
from tenacity import retry, stop_after_attempt, wait_exponential, RetryError

from .. import models, audit
from ..config import get_settings
from ..azure_client import AzureClient
from .actions import ACTION_REGISTRY, RULE_TYPE_TO_ACTION

settings = get_settings()


class RemediationExecutor:
    def __init__(self, db: Session):
        self.db = db

    def _client_for(self, subscription: models.Subscription) -> AzureClient:
        return AzureClient(subscription.azure_subscription_id, subscription.tenant_id)

    def determine_action_type(self, finding: models.Finding) -> str:
        rule = self.db.query(models.PolicyRule).filter(models.PolicyRule.id == finding.rule_id).first()
        return RULE_TYPE_TO_ACTION[rule.rule_type]

    def execute(self, finding: models.Finding, actor: str, approved: bool = False) -> models.RemediationAction:
        action_type = self.determine_action_type(finding)
        action_cls = ACTION_REGISTRY[action_type]
        subscription = self.db.query(models.Subscription).filter(
            models.Subscription.id == finding.subscription_id).first()
        client = self._client_for(subscription)
        action_instance = action_cls(client)

        if action_instance.is_high_risk and not approved:
            ra = models.RemediationAction(
                finding_id=finding.id, action_type=action_type,
                status=models.RemediationStatusEnum.PENDING,
                triggered_by=actor, requires_approval=True,
            )
            self.db.add(ra)
            finding.status = models.FindingStatusEnum.PENDING_APPROVAL
            self.db.commit()
            audit.write_audit(self.db, action="REMEDIATION_QUEUED_FOR_APPROVAL",
                               entity_type="Finding", entity_id=finding.id, actor=actor)
            return ra

        ra = models.RemediationAction(
            finding_id=finding.id, action_type=action_type,
            status=models.RemediationStatusEnum.RUNNING,
            triggered_by=actor, requires_approval=action_instance.is_high_risk,
            approved_by=actor if approved else None,
        )
        self.db.add(ra)
        self.db.commit()

        try:
            result = self._run_with_backoff(action_instance, finding.details)
            ra.status = models.RemediationStatusEnum.SUCCESS
            ra.result = result
            ra.completed_at = datetime.utcnow()
            finding.status = models.FindingStatusEnum.REMEDIATED
            finding.closed_at = datetime.utcnow()
            audit.write_audit(self.db, action="REMEDIATION_SUCCEEDED", entity_type="Finding",
                               entity_id=finding.id, actor=actor, metadata=result)
        except RetryError as e:
            ra.status = models.RemediationStatusEnum.FAILED
            ra.last_error = str(e)
            finding.status = models.FindingStatusEnum.OPEN
            audit.write_audit(self.db, action="REMEDIATION_FAILED", entity_type="Finding",
                               entity_id=finding.id, actor=actor, metadata={"error": str(e)})
        self.db.commit()
        return ra

    def _run_with_backoff(self, action_instance, finding_details):
        max_attempts = settings.remediation_max_retries
        base = settings.remediation_backoff_base_seconds

        @retry(stop=stop_after_attempt(max_attempts),
               wait=wait_exponential(multiplier=base, max=60))
        def _inner():
            return action_instance.apply(finding_details)

        return _inner()