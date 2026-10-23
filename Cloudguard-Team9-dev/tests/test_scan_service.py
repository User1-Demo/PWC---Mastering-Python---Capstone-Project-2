from unittest.mock import MagicMock

import pytest

from cloudguard.azure.inventory import InventoryProvider
from cloudguard.models.audit_log import AuditLog
from cloudguard.models.finding import Finding
from cloudguard.models.policy_rule import PolicyRule
from cloudguard.models.subscription import Subscription
from cloudguard.schemas.azure_resource import AzureResource
from cloudguard.services.scan_service import run_scan


def test_scan_fails_when_subscription_does_not_exist() -> None:
    db = MagicMock()

    db.get.return_value = None

    with pytest.raises(
        ValueError,
        match="Subscription not found",
    ):
        run_scan(
            db=db,
            subscription_db_id=999,
            actor="test-user",
        )


def test_scan_uses_requested_subscription() -> None:
    db = MagicMock()

    subscription = Subscription(
        id=1,
        subscription_id="11111111-1111-1111-1111-111111111111",
        name="cloudguard-test",
        environment="test",
    )

    db.get.return_value = subscription

    # Force an exception immediately after subscription validation.
    db.add.side_effect = RuntimeError("stop-test")

    with pytest.raises(
        RuntimeError,
        match="stop-test",
    ):
        run_scan(
            db=db,
            subscription_db_id=1,
            actor="test-user",
        )

    db.get.assert_called_once_with(
        Subscription,
        1,
    )

def test_successful_scan_creates_findings_and_audit_logs() -> None:
    db = MagicMock()

    subscription = Subscription(
        id=1,
        subscription_id="11111111-1111-1111-1111-111111111111",
        name="cloudguard-test",
        environment="test",
    )

    required_tag_policy = PolicyRule(
        id=1,
        name="Require Environment Tag",
        rule_type="required_tag",
        severity="medium",
        description="Environment tag required",
        enabled=True,
    )

    risky_nsg_policy = PolicyRule(
        id=2,
        name="Block Public Management Ports",
        rule_type="risky_nsg",
        severity="high",
        description="Public management ports must not be exposed",
        enabled=True,
    )

    db.get.return_value = subscription
    db.scalars.return_value.all.return_value = [
        required_tag_policy,
        risky_nsg_policy,
    ]

    resources = [
        AzureResource(
            id="/resources/compliant-vm",
            name="compliant-vm",
            type="Microsoft.Compute/virtualMachines",
            location="centralindia",
            tags={
                "Environment": "test",
            },
        ),
        AzureResource(
            id="/resources/noncompliant-vm",
            name="noncompliant-vm",
            type="Microsoft.Compute/virtualMachines",
            location="centralindia",
            tags={},
        ),
        AzureResource(
            id="/resources/test-nsg",
            name="test-nsg",
            type="Microsoft.Network/networkSecurityGroups",
            location="centralindia",
            tags={
                "Environment": "test",
            },
            security_rules=[
                {
                    "name": "Allow-SSH",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source_address_prefix": "*",
                    "destination_port_range": "22",
                    "priority": 100,
                }
            ],
        ),
    ]

    inventory_provider = MagicMock(
        spec=InventoryProvider
    )
    inventory_provider.list_resources.return_value = resources

    result = run_scan(
        db=db,
        subscription_db_id=1,
        actor="test-user",
        inventory_provider=inventory_provider,
    )

    assert result.status == "completed"
    assert result.subscription_id == 1
    assert result.started_at is not None
    assert result.completed_at is not None

    inventory_provider.list_resources.assert_called_once()

    added_objects = [
        call.args[0]
        for call in db.add.call_args_list
    ]

    findings = [
        obj
        for obj in added_objects
        if isinstance(obj, Finding)
    ]

    assert len(findings) == 2

    resource_names = {
        finding.resource_name
        for finding in findings
    }

    assert resource_names == {
        "noncompliant-vm",
        "test-nsg",
    }

    audit_logs = [
        obj
        for obj in added_objects
        if isinstance(obj, AuditLog)
    ]

    event_types = {
        audit.event_type
        for audit in audit_logs
    }

    assert "scan_started" in event_types
    assert "finding_created" in event_types
    assert "scan_completed" in event_types

    db.commit.assert_called()
