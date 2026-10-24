from types import SimpleNamespace

import pytest

from app.rules.engine import evaluate_resource, validate_rule


def rule(rule_type, parameters, severity="low", auto_remediate=False):
    return SimpleNamespace(
        id=1,
        name="test rule",
        rule_type=rule_type,
        parameters=parameters,
        severity=severity,
        enabled=True,
        auto_remediate=auto_remediate,
    )


def test_required_tags_finding_contains_only_missing_tags():
    result = evaluate_resource(
        {"id": "r1", "name": "vm", "type": "Microsoft.Compute/virtualMachines", "tags": {"owner": "team"}},
        [rule("required_tags", {"required_tags": ["owner", "environment"]})],
    )
    assert len(result) == 1
    assert result[0]["details"]["missing_tags"] == ["environment"]


def test_nsg_finds_public_ssh_but_not_private_rule():
    resource = {
        "id": "nsg",
        "name": "nsg",
        "type": "Microsoft.Network/networkSecurityGroups",
        "properties": {
            "securityRules": [
                {
                    "name": "public-ssh",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "22",
                },
                {
                    "name": "private-ssh",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "10.0.0.0/8",
                    "destinationPortRange": "22",
                },
            ]
        },
    }
    result = evaluate_resource(resource, [rule("nsg_open_ports", {"blocked_ports": [22]}, "high")])
    assert result[0]["details"]["exposed_rules"] == [{"rule": "public-ssh", "port": "22"}]


def test_nsg_checks_address_and_port_range_lists():
    resource = {
        "id": "nsg",
        "name": "nsg",
        "type": "Microsoft.Network/networkSecurityGroups",
        "properties": {
            "securityRules": [
                {
                    "name": "listed-exposure",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefixes": ["Internet", "10.0.0.0/8"],
                    "destinationPortRanges": ["20-24", "8080"],
                }
            ]
        },
    }
    result = evaluate_resource(resource, [rule("nsg_open_ports", {"blocked_ports": [22]}, "high")])
    assert result[0]["details"]["exposed_rules"] == [{"rule": "listed-exposure", "port": "20-24"}]


@pytest.mark.parametrize(
    "resource,rule_type,parameters",
    [
        (
            {"id": "vm", "name": "vm", "type": "Microsoft.Compute/virtualMachines", "properties": {"average_cpu_percent": 1}},
            "idle_vm",
            {"cpu_threshold_percent": 5},
        ),
        (
            {"id": "disk", "name": "disk", "type": "Microsoft.Compute/disks", "properties": {"diskState": "Unattached"}},
            "unattached_disk",
            {},
        ),
        (
            {"id": "secret", "name": "secret", "type": "Microsoft.KeyVault/vaults/secrets", "properties": {"expires_on": "2026-10-23T00:00:00+00:00"}},
            "expiring_secret",
            {"days": 365},
        ),
    ],
)
def test_optional_inventory_checks(resource, rule_type, parameters):
    assert evaluate_resource(resource, [rule(rule_type, parameters)])


def test_auto_remediation_requires_explicit_values():
    with pytest.raises(ValueError, match="tag_values"):
        validate_rule("required_tags", "low", {"required_tags": ["owner"]}, True)
    validate_rule(
        "required_tags",
        "low",
        {"required_tags": ["owner"], "tag_values": {"owner": "platform"}},
        True,
    )


def test_high_risk_rule_cannot_be_auto_remediated():
    with pytest.raises(ValueError, match="Only low-severity"):
        validate_rule(
            "required_tags",
            "high",
            {"required_tags": ["owner"], "tag_values": {"owner": "platform"}},
            True,
        )


def test_invalid_rule_type_and_parameters_are_rejected():
    with pytest.raises(ValueError, match="Unsupported"):
        validate_rule("shell_command", "low", {}, False)
    with pytest.raises(ValueError, match="blocked_ports"):
        validate_rule("nsg_open_ports", "high", {"blocked_ports": [70000]}, False)


def test_disabled_rule_is_skipped():
    disabled = rule("required_tags", {"required_tags": ["owner"]})
    disabled.enabled = False
    assert evaluate_resource({"id": "vm", "tags": {}}, [disabled]) == []
