from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

from app.providers.base import ProviderError


class AzureProvider:
    """Azure Resource Manager inventory with optional Key Vault secret metadata."""

    def __init__(self):
        self.credential = DefaultAzureCredential()

    def list_resources(self, subscription_id: str) -> list[dict]:
        try:
            client = ResourceManagementClient(self.credential, subscription_id)
            normalized: list[dict] = []
            for resource in client.resources.list():
                resource_type = resource.type or ""
                properties = resource.properties or {}
                item = {
                    "id": resource.id,
                    "name": resource.name,
                    "type": resource_type,
                    "tags": resource.tags or {},
                    "properties": properties,
                }
                normalized.append(item)
                if resource_type.lower() == "microsoft.keyvault/vaults":
                    vault_uri = (
                        properties.get("vaultUri") or properties.get("vault_uri")
                        if isinstance(properties, dict)
                        else getattr(properties, "vault_uri", None)
                    )
                    if vault_uri:
                        secret_client = SecretClient(vault_url=vault_uri, credential=self.credential)
                        for secret in secret_client.list_properties_of_secrets():
                            normalized.append(
                                {
                                    "id": f"{resource.id}/secrets/{secret.name}",
                                    "name": secret.name,
                                    "type": "Microsoft.KeyVault/vaults/secrets",
                                    "tags": resource.tags or {},
                                    "properties": {
                                        "expires_on": secret.expires_on.isoformat()
                                        if secret.expires_on
                                        else None
                                    },
                                }
                            )
            return normalized
        except AzureError as error:
            raise ProviderError(f"Azure inventory request failed: {error}") from error

    def ensure_tags(self, subscription_id: str, resource: dict, tags: dict[str, str]) -> bool:
        try:
            client = ResourceManagementClient(self.credential, subscription_id)
            latest = client.resources.get_by_id(
                resource_id=resource["id"],
                api_version="2021-04-01",
            )
            current_tags = latest.tags or {}
            merged = {**current_tags, **tags}
            if merged == current_tags:
                return False
            client.resources.begin_update_by_id(
                resource_id=resource["id"],
                api_version="2021-04-01",
                parameters={"tags": merged},
            ).result()
            return True
        except AzureError as error:
            raise ProviderError(f"Azure tag update failed: {error}") from error

    def deny_nsg_rules(self, subscription_id: str, resource: dict, rule_names: list[str]) -> bool:
        try:
            segments = resource["id"].strip("/").split("/")
            lower_segments = [segment.lower() for segment in segments]
            group_index = lower_segments.index("resourcegroups")
            provider_index = lower_segments.index("providers")
            if (
                lower_segments[provider_index + 1] != "microsoft.network"
                or lower_segments[provider_index + 2] != "networksecuritygroups"
            ):
                raise ValueError("Resource is not a Microsoft.Network/networkSecurityGroups resource")
            resource_group = segments[group_index + 1]
            nsg_name = segments[provider_index + 3]
            client = NetworkManagementClient(self.credential, subscription_id)
            nsg = client.network_security_groups.get(resource_group, nsg_name)
            rules = nsg.security_rules or []
            names = set(rule_names)
            matches = [rule for rule in rules if rule.name in names]
            if {rule.name for rule in matches} != names:
                raise ProviderError("One or more NSG rules no longer exist")
            changed = False
            for rule in matches:
                if (rule.direction or "").lower() != "inbound":
                    raise ProviderError(f"NSG rule {rule.name} is no longer inbound")
                if (rule.access or "").lower() == "deny":
                    continue
                if (rule.access or "").lower() != "allow":
                    raise ProviderError(f"NSG rule {rule.name} is no longer an inbound allow rule")
                rule.access = "Deny"
                changed = True
            if changed:
                client.network_security_groups.begin_create_or_update(
                    resource_group_name=resource_group,
                    network_security_group_name=nsg_name,
                    parameters=nsg,
                ).result()
            return changed
        except AzureError as error:
            raise ProviderError(f"Azure NSG update failed: {error}") from error

    def close(self) -> None:
        self.credential.close()
