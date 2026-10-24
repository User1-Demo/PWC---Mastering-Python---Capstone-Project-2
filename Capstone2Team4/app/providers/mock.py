from copy import deepcopy
from datetime import datetime, timedelta, timezone

from app.providers.base import ProviderError


class MockAzureProvider:
    """Deterministic local provider; mutations are retained for the process lifetime."""

    def __init__(self):
        self.resources: dict[str, list[dict]] = {}

    def list_resources(self, subscription_id: str) -> list[dict]:
        if subscription_id not in self.resources:
            expiry = (datetime.now(timezone.utc) + timedelta(days=12)).isoformat()
            self.resources[subscription_id] = [
                {
                    "id": f"/subscriptions/{subscription_id}/resourceGroups/demo/providers/Microsoft.Compute/virtualMachines/demo-vm",
                    "name": "demo-vm",
                    "type": "Microsoft.Compute/virtualMachines",
                    "tags": {"environment": "demo"},
                    "properties": {"average_cpu_percent": 2.0},
                },
                {
                    "id": f"/subscriptions/{subscription_id}/resourceGroups/demo/providers/Microsoft.Network/networkSecurityGroups/demo-nsg",
                    "name": "demo-nsg",
                    "type": "Microsoft.Network/networkSecurityGroups",
                    "tags": {"owner": "platform", "environment": "demo", "cost-center": "training"},
                    "properties": {
                        "securityRules": [
                            {
                                "name": "allow-ssh-from-anywhere",
                                "direction": "Inbound",
                                "access": "Allow",
                                "protocol": "Tcp",
                                "sourceAddressPrefix": "*",
                                "destinationPortRange": "22",
                            }
                        ]
                    },
                },
                {
                    "id": f"/subscriptions/{subscription_id}/resourceGroups/demo/providers/Microsoft.Compute/disks/orphan-disk",
                    "name": "orphan-disk",
                    "type": "Microsoft.Compute/disks",
                    "tags": {"owner": "platform", "environment": "demo", "cost-center": "training"},
                    "properties": {"diskState": "Unattached"},
                },
                {
                    "id": f"/subscriptions/{subscription_id}/resourceGroups/demo/providers/Microsoft.KeyVault/vaults/demo/secrets/old-secret",
                    "name": "old-secret",
                    "type": "Microsoft.KeyVault/vaults/secrets",
                    "tags": {},
                    "properties": {"expires_on": expiry},
                },
            ]
        return deepcopy(self.resources[subscription_id])

    def ensure_tags(self, subscription_id: str, resource: dict, tags: dict[str, str]) -> bool:
        inventory = self.list_resources(subscription_id)
        current = next((item for item in inventory if item["id"] == resource["id"]), None)
        if current is None:
            raise ProviderError(f"Resource no longer exists: {resource['id']}")
        mutable = next(item for item in self.resources[subscription_id] if item["id"] == resource["id"])
        current_tags = mutable.setdefault("tags", {})
        changed = any(current_tags.get(key) != value for key, value in tags.items())
        current_tags.update(tags)
        return changed

    def deny_nsg_rules(self, subscription_id: str, resource: dict, rule_names: list[str]) -> bool:
        inventory = self.list_resources(subscription_id)
        current = next((item for item in inventory if item["id"] == resource["id"]), None)
        if current is None:
            raise ProviderError(f"Resource no longer exists: {resource['id']}")
        mutable = next(item for item in self.resources[subscription_id] if item["id"] == resource["id"])
        rules = mutable.get("properties", {}).get("securityRules", [])
        matches = [rule for rule in rules if rule.get("name") in rule_names]
        if len(matches) != len(set(rule_names)):
            raise ProviderError("One or more NSG rules no longer exist")
        changed = any(rule.get("access", "").lower() != "deny" for rule in matches)
        for security_rule in matches:
            security_rule["access"] = "Deny"
        return changed
