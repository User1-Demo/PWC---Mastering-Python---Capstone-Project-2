from cloudguard.azure.mock_inventory import load_mock_resources
from cloudguard.policies.risky_nsg import evaluate_risky_nsg
from cloudguard.schemas.azure_resource import AzureResource


def test_non_nsg_resource_returns_no_violations() -> None:
    resource = AzureResource(
        id="/resources/web-server-01",
        name="web-server-01",
        type="Microsoft.Compute/virtualMachines",
        location="centralindia",
        tags={},
    )

    violations = evaluate_risky_nsg(resource)

    assert violations == []


def test_public_ssh_rule_returns_violation() -> None:
    resource = AzureResource(
        id="/resources/web-nsg",
        name="web-nsg",
        type="Microsoft.Network/networkSecurityGroups",
        location="centralindia",
        tags={},
        security_rules=[
            {
                "name": "Allow-SSH-From-Internet",
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "source_address_prefix": "*",
                "destination_port_range": "22",
                "priority": 110,
            }
        ],
    )

    violations = evaluate_risky_nsg(resource)

    assert len(violations) == 1
    assert violations[0].resource_name == "web-nsg"
    assert violations[0].rule_name == "Allow-SSH-From-Internet"
    assert violations[0].exposed_port == "22"


def test_https_rule_is_not_flagged() -> None:
    resource = AzureResource(
        id="/resources/web-nsg",
        name="web-nsg",
        type="Microsoft.Network/networkSecurityGroups",
        location="centralindia",
        tags={},
        security_rules=[
            {
                "name": "Allow-HTTPS",
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "source_address_prefix": "Internet",
                "destination_port_range": "443",
                "priority": 100,
            }
        ],
    )

    violations = evaluate_risky_nsg(resource)

    assert violations == []


def test_mock_inventory_has_one_nsg_violation() -> None:
    resources = load_mock_resources()

    violations = [
        violation
        for resource in resources
        for violation in evaluate_risky_nsg(resource)
    ]

    assert len(violations) == 1
    assert violations[0].resource_name == "web-nsg"
    assert violations[0].exposed_port == "22"