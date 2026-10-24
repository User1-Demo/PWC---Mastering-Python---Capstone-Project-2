from dataclasses import dataclass

from cloudguard.schemas.azure_resource import (
    AzureResource,
    AzureSecurityRule,
)

NSG_RESOURCE_TYPE = "Microsoft.Network/networkSecurityGroups"

PUBLIC_SOURCE_PREFIXES = {
    "*",
    "0.0.0.0/0",
    "Internet",
}

RISKY_PORTS = {
    "22",
    "3389",
}


@dataclass(frozen=True)
class NsgViolation:
    resource_id: str
    resource_name: str
    resource_type: str
    rule_name: str
    exposed_port: str
    message: str


def is_risky_rule(rule: AzureSecurityRule) -> bool:
    return (
        rule.direction.casefold() == "inbound"
        and rule.access.casefold() == "allow"
        and rule.source_address_prefix.casefold()
        in {prefix.casefold() for prefix in PUBLIC_SOURCE_PREFIXES}
        and rule.destination_port_range in RISKY_PORTS
    )


def evaluate_risky_nsg(
    resource: AzureResource,
) -> list[NsgViolation]:
    if resource.type.casefold() != NSG_RESOURCE_TYPE.casefold():
        return []

    violations: list[NsgViolation] = []

    for rule in resource.security_rules:
        if not is_risky_rule(rule):
            continue

        violations.append(
            NsgViolation(
                resource_id=resource.id,
                resource_name=resource.name,
                resource_type=resource.type,
                rule_name=rule.name,
                exposed_port=rule.destination_port_range,
                message=(
                    f"NSG '{resource.name}' rule '{rule.name}' allows "
                    f"inbound access to port "
                    f"'{rule.destination_port_range}' from a public source"
                ),
            )
        )

    return violations