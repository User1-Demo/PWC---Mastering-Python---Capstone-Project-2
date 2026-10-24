from unittest.mock import MagicMock

import pytest

from cloudguard.models.audit_log import AuditLog
from cloudguard.models.finding import Finding
from cloudguard.models.policy_rule import PolicyRule
from cloudguard.models.remediation_action import RemediationAction
from cloudguard.services.remediation_service import (
    approve_remediation,
    request_remediation,
    requires_approval,
)


def test_medium_finding_does_not_require_approval() -> None:
    assert requires_approval("medium") is False


def test_high_finding_requires_approval() -> None:
    assert requires_approval("high") is True


def test_critical_finding_requires_approval() -> None:
    assert requires_approval("critical") is True


def test_severity_check_is_case_insensitive() -> None:
    assert requires_approval("HIGH") is True

def test_request_remediation_fails_when_finding_not_found() -> None:
    db = MagicMock()
    db.get.return_value = None

    with pytest.raises(
        ValueError,
        match="Finding not found",
    ):
        request_remediation(
            db=db,
            finding_id=999,
            requested_by="test-user",
        )

def test_closed_finding_cannot_be_remediated() -> None:
    db = MagicMock()

    finding = Finding(
        id=1,
        scan_id=1,
        policy_rule_id=1,
        resource_id="/resources/test",
        resource_name="test-resource",
        resource_type="Microsoft.Compute/virtualMachines",
        severity="medium",
        status="closed",
        message="Missing Environment tag",
    )

    db.get.return_value = finding

    with pytest.raises(
        ValueError,
        match="Finding is already closed",
    ):
        request_remediation(
            db=db,
            finding_id=1,
            requested_by="test-user",
        )

def test_required_tag_remediation_completes() -> None:
    db = MagicMock()

    finding = Finding(
        id=1,
        scan_id=1,
        policy_rule_id=1,
        resource_id="/resources/test-vm",
        resource_name="test-vm",
        resource_type="Microsoft.Compute/virtualMachines",
        severity="medium",
        status="open",
        message="Missing Environment tag",
    )

    policy = PolicyRule(
        id=1,
        name="Require Environment Tag",
        rule_type="required_tag",
        severity="medium",
        description="Environment tag required",
        enabled=True,
    )

    db.get.side_effect = [finding, policy]

    remediation = request_remediation(
        db=db,
        finding_id=1,
        requested_by="cloud-engineer",
    )

    assert remediation.status == "completed"
    assert remediation.action_type == "add_missing_tag"
    assert remediation.requested_by == "cloud-engineer"
    assert remediation.completed_at is not None

    assert finding.status == "closed"

    added_objects = [
        call.args[0]
        for call in db.add.call_args_list
    ]

    assert any(
        isinstance(obj, RemediationAction)
        for obj in added_objects
    )

    assert any(
        isinstance(obj, AuditLog)
        and obj.event_type == "remediation_completed"
        for obj in added_objects
    )

    db.commit.assert_called()

def test_high_risk_remediation_waits_for_approval() -> None:
    db = MagicMock()

    finding = Finding(
        id=2,
        scan_id=1,
        policy_rule_id=2,
        resource_id="/resources/test-nsg",
        resource_name="test-nsg",
        resource_type="Microsoft.Network/networkSecurityGroups",
        severity="high",
        status="open",
        message="Public SSH exposure",
    )

    policy = PolicyRule(
        id=2,
        name="Block Public Management Ports",
        rule_type="risky_nsg",
        severity="high",
        description="No public management ports",
        enabled=True,
    )

    db.get.side_effect = [finding, policy]

    remediation = request_remediation(
        db=db,
        finding_id=2,
        requested_by="cloud-engineer",
    )

    assert remediation.status == "awaiting_approval"
    assert remediation.action_type == "manual_approval_required"

    # Important: requesting approval must not close the finding.
    assert finding.status == "open"

    added_objects = [
        call.args[0]
        for call in db.add.call_args_list
    ]

    assert any(
        isinstance(obj, AuditLog)
        and obj.event_type == "remediation_requested"
        for obj in added_objects
    )

    db.commit.assert_called()

def test_unsupported_policy_type_fails() -> None:
    db = MagicMock()

    finding = Finding(
        id=3,
        scan_id=1,
        policy_rule_id=3,
        resource_id="/resources/test",
        resource_name="test-resource",
        resource_type="Unknown",
        severity="medium",
        status="open",
        message="Test finding",
    )

    policy = PolicyRule(
        id=3,
        name="Unsupported Rule",
        rule_type="unsupported",
        severity="medium",
        description="Test",
        enabled=True,
    )

    db.get.side_effect = [finding, policy]

    with pytest.raises(
        ValueError,
        match="No remediation is implemented",
    ):
        request_remediation(
            db=db,
            finding_id=3,
            requested_by="test-user",
        )

def test_approve_high_risk_remediation() -> None:
    db = MagicMock()

    finding = Finding(
        id=4,
        scan_id=1,
        policy_rule_id=2,
        resource_id="/resources/test-nsg",
        resource_name="test-nsg",
        resource_type="Microsoft.Network/networkSecurityGroups",
        severity="high",
        status="open",
        message="Public SSH exposure",
    )

    remediation = RemediationAction(
        id=1,
        finding_id=4,
        action_type="manual_approval_required",
        status="awaiting_approval",
        requested_by="cloud-engineer",
    )

    db.get.return_value = finding

    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = (
        remediation
    )

    result = approve_remediation(
        db=db,
        finding_id=4,
        approved_by="security-officer",
    )

    assert result.status == "completed"
    assert result.approved_by == "security-officer"
    assert result.approved_at is not None
    assert result.completed_at is not None

    assert finding.status == "closed"

    added_objects = [
        call.args[0]
        for call in db.add.call_args_list
    ]

    assert any(
        isinstance(obj, AuditLog)
        and obj.event_type == "remediation_approved"
        and obj.actor == "security-officer"
        for obj in added_objects
    )

    db.commit.assert_called()

def test_approve_fails_when_no_remediation_awaits_approval() -> None:
    db = MagicMock()

    finding = Finding(
        id=5,
        scan_id=1,
        policy_rule_id=2,
        resource_id="/resources/test-nsg",
        resource_name="test-nsg",
        resource_type="Microsoft.Network/networkSecurityGroups",
        severity="high",
        status="open",
        message="Public SSH exposure",
    )

    db.get.return_value = finding

    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = (
        None
    )

    with pytest.raises(
        ValueError,
        match="No remediation is awaiting approval",
    ):
        approve_remediation(
            db=db,
            finding_id=5,
            approved_by="security-officer",
        )