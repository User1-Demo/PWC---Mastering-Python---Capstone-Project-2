from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from azure.core.exceptions import AzureError

from app.providers.azure import AzureProvider
from app.providers.base import ProviderError


def test_azure_inventory_reads_resources_and_secret_expiry_metadata(monkeypatch):
    expires_on = datetime(2026, 11, 10, tzinfo=timezone.utc)
    vault = SimpleNamespace(
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/demo",
        name="demo",
        type="Microsoft.KeyVault/vaults",
        tags={"environment": "test"},
        properties={"vaultUri": "https://demo.vault.azure.net/"},
    )
    resource_client = SimpleNamespace(
        resources=SimpleNamespace(list=lambda: [vault])
    )
    secret_client = SimpleNamespace(
        list_properties_of_secrets=lambda: [
            SimpleNamespace(name="sample-secret", expires_on=expires_on)
        ]
    )
    monkeypatch.setattr("app.providers.azure.DefaultAzureCredential", lambda: "credential")
    monkeypatch.setattr(
        "app.providers.azure.ResourceManagementClient",
        lambda credential, subscription_id: resource_client,
    )
    monkeypatch.setattr(
        "app.providers.azure.SecretClient",
        lambda vault_url, credential: secret_client,
    )

    resources = AzureProvider().list_resources("sub")
    assert resources[0]["type"] == "Microsoft.KeyVault/vaults"
    assert resources[1]["name"] == "sample-secret"
    assert resources[1]["properties"]["expires_on"] == expires_on.isoformat()
    assert "value" not in resources[1]["properties"]


def test_azure_tag_write_merges_live_tags_and_skips_noop(monkeypatch):
    latest = SimpleNamespace(tags={"environment": "test"})
    calls = []
    resource_ops = SimpleNamespace(
        get_by_id=lambda **kwargs: latest,
        begin_update_by_id=lambda **kwargs: calls.append(kwargs) or SimpleNamespace(result=lambda: None),
    )
    monkeypatch.setattr("app.providers.azure.DefaultAzureCredential", lambda: "credential")
    monkeypatch.setattr(
        "app.providers.azure.ResourceManagementClient",
        lambda credential, subscription_id: SimpleNamespace(resources=resource_ops),
    )
    provider = AzureProvider()

    assert provider.ensure_tags("sub", {"id": "/resource"}, {"owner": "platform"})
    assert calls[0]["parameters"]["tags"] == {
        "environment": "test",
        "owner": "platform",
    }
    assert not provider.ensure_tags("sub", {"id": "/resource"}, {"environment": "test"})


def test_azure_sdk_errors_are_reported_as_provider_errors(monkeypatch):
    def fail_request(credential, subscription_id):
        raise AzureError("authentication unavailable")

    monkeypatch.setattr("app.providers.azure.DefaultAzureCredential", lambda: "credential")
    monkeypatch.setattr("app.providers.azure.ResourceManagementClient", fail_request)
    with pytest.raises(ProviderError, match="inventory request failed"):
        AzureProvider().list_resources("sub")


def test_azure_nsg_remediation_denies_only_the_approved_rule(monkeypatch):
    security_rule = SimpleNamespace(name="allow-ssh", direction="Inbound", access="Allow")
    nsg = SimpleNamespace(security_rules=[security_rule])
    updates = []
    nsg_ops = SimpleNamespace(
        get=lambda resource_group, nsg_name: nsg,
        begin_create_or_update=lambda **kwargs: updates.append(kwargs)
        or SimpleNamespace(result=lambda: None),
    )
    monkeypatch.setattr("app.providers.azure.DefaultAzureCredential", lambda: "credential")
    monkeypatch.setattr(
        "app.providers.azure.NetworkManagementClient",
        lambda credential, subscription_id: SimpleNamespace(network_security_groups=nsg_ops),
    )
    provider = AzureProvider()
    resource = {
        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/demo"
    }

    assert provider.deny_nsg_rules("sub", resource, ["allow-ssh"])
    assert security_rule.access == "Deny"
    assert updates[0]["resource_group_name"] == "rg"
    assert not provider.deny_nsg_rules("sub", resource, ["allow-ssh"])
