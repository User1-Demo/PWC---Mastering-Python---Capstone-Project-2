import pytest

from app.audit import verify_chain
from app.models import (
    AuditLog,
    Finding,
    PolicyRule,
    RemediationAction,
    Scan,
    Subscription,
)
from app.providers.base import ProviderError
from app.services.remediation import execute_remediation, queue_remediation


class Provider:
    def __init__(self, *, result=True, error=None):
        self.result = result
        self.error = error
        self.calls = 0

    def ensure_tags(self, subscription_id, resource, tags):
        self.calls += 1
        if self.error:
            raise self.error
        assert tags == {"owner": "platform"}
        return self.result


def create_action(session_factory, *, status="open", rule_type="required_tags"):
    with session_factory() as db:
        subscription = Subscription(subscription_id="remediation-sub", name="test")
        rule = PolicyRule(
            name=f"remediation-{rule_type}",
            rule_type=rule_type,
            severity="low",
            parameters={"required_tags": ["owner"], "tag_values": {"owner": "platform"}},
        )
        db.add_all([subscription, rule])
        db.flush()
        scan = Scan(subscription_id=subscription.id, trigger_source="test", status="completed")
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id,
            rule_id=rule.id,
            resource_id="/subscriptions/remediation-sub/resourceGroups/test/providers/Microsoft.Compute/virtualMachines/vm",
            resource_name="vm",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="low",
            status=status,
            title="Missing owner tag",
            details={"missing_tags": ["owner"]},
        )
        db.add(finding)
        db.flush()
        action = RemediationAction(finding_id=finding.id, status="queued")
        db.add(action)
        db.commit()
        return action.id, finding.id


def test_remediation_noop_is_idempotent(client, monkeypatch):
    _, session_factory = client
    action_id, finding_id = create_action(session_factory, status="remediated")
    provider = Provider()
    monkeypatch.setattr("app.services.remediation.get_provider", lambda: provider)
    execute_remediation(action_id)
    assert provider.calls == 0
    with session_factory() as db:
        action = db.get(RemediationAction, action_id)
        assert action.status == "succeeded"
        assert action.message == "Already compliant; no change was needed."
        assert db.get(Finding, finding_id).status == "remediated"


def test_remediation_retries_then_records_failure(client, monkeypatch):
    _, session_factory = client
    action_id, finding_id = create_action(session_factory)
    provider = Provider(error=ProviderError("provider unavailable"))
    settings = __import__("app.config", fromlist=["get_settings"]).get_settings()
    monkeypatch.setattr(settings, "remediation_max_retries", 2)
    monkeypatch.setattr(settings, "remediation_retry_base_seconds", 0)
    monkeypatch.setattr("app.services.remediation.get_provider", lambda: provider)
    with pytest.raises(RuntimeError, match="failed after 2 attempts"):
        execute_remediation(action_id)
    assert provider.calls == 2
    with session_factory() as db:
        assert db.get(RemediationAction, action_id).status == "failed"
        assert db.get(RemediationAction, action_id).attempt_count == 2
        assert db.get(Finding, finding_id).status == "remediation_failed"
        assert db.query(AuditLog).filter_by(event_type="remediation.failed").count() == 1
        assert verify_chain(db)[0]


def test_remediation_refuses_unimplemented_rule(client):
    _, session_factory = client
    action_id, _ = create_action(session_factory, rule_type="idle_vm")
    with pytest.raises(ValueError, match="No remediation implementation"):
        execute_remediation(action_id)


def test_queue_remediation_tracks_actor_and_audit(client):
    _, session_factory = client
    action_id, finding_id = create_action(session_factory)
    with session_factory() as db:
        finding = db.get(Finding, finding_id)
        action = queue_remediation(db, finding, actor_id=None)
        db.commit()
        assert action.status == "queued"
        assert action.finding_id == finding_id
        assert action_id != action.id
        assert db.query(AuditLog).filter_by(event_type="remediation.queued").count() == 1
