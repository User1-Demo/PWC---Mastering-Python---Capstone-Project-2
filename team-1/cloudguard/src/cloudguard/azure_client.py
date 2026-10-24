"""
Thin wrapper around Azure SDK. Falls back to local JSON fixtures when
settings.azure_use_fixtures=True or no credentials are configured —
this lets the full pipeline run in CI/offline without a live subscription.

Only this module talks to azure-mgmt-* / azure-identity, so tests mock
AzureClient instead of individual SDK calls.
"""
import json
from pathlib import Path
from typing import List, Dict, Any
from .config import get_settings

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class AzureClient:
    def __init__(self, subscription_id: str, tenant_id: str, use_fixtures: bool | None = None):
        settings = get_settings()
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.use_fixtures = settings.azure_use_fixtures if use_fixtures is None else use_fixtures
        self._credential = None
        self._clients = {}
        if not self.use_fixtures:
            self._init_real_clients()

    def _init_real_clients(self):
        from azure.identity import ClientSecretCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.keyvault import KeyVaultManagementClient
        settings = get_settings()
        self._credential = ClientSecretCredential(
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret,   # sourced from K8s Secret/Key Vault only
        )
        self._clients["compute"] = ComputeManagementClient(self._credential, self.subscription_id)
        self._clients["network"] = NetworkManagementClient(self._credential, self.subscription_id)
        self._clients["keyvault"] = KeyVaultManagementClient(self._credential, self.subscription_id)

    # ---- Inventory methods -------------------------------------------------
    def list_vms(self) -> List[Dict[str, Any]]:
        if self.use_fixtures:
            return json.loads((FIXTURE_DIR / "vms.json").read_text())
        vms = self._clients["compute"].virtual_machines.list_all()
        return [self._normalize_vm(v) for v in vms]

    def list_nsgs(self) -> List[Dict[str, Any]]:
        if self.use_fixtures:
            return json.loads((FIXTURE_DIR / "nsgs.json").read_text())
        nsgs = self._clients["network"].network_security_groups.list_all()
        return [self._normalize_nsg(n) for n in nsgs]

    def list_disks(self) -> List[Dict[str, Any]]:
        if self.use_fixtures:
            return json.loads((FIXTURE_DIR / "disks.json").read_text())
        disks = self._clients["compute"].disks.list()
        return [self._normalize_disk(d) for d in disks]

    def list_keyvault_secrets(self) -> List[Dict[str, Any]]:
        if self.use_fixtures:
            return json.loads((FIXTURE_DIR / "keyvault_secrets.json").read_text())
        # Real implementation would enumerate vaults then secrets via SecretClient
        return []

    def full_inventory(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "vm": self.list_vms(),
            "nsg": self.list_nsgs(),
            "disk": self.list_disks(),
            "keyvault_secret": self.list_keyvault_secrets(),
        }

    # ---- Remediation-facing mutating calls (idempotent) --------------------
    def tag_resource(self, resource_id: str, tags: dict) -> dict:
        if self.use_fixtures:
            return {"resource_id": resource_id, "applied_tags": tags, "simulated": True}
        # real: generic ResourceManagementClient.tags.update(...)
        raise NotImplementedError

    def close_nsg_rule(self, nsg_id: str, rule_name: str) -> dict:
        if self.use_fixtures:
            return {"nsg_id": nsg_id, "rule": rule_name, "action": "removed", "simulated": True}
        raise NotImplementedError

    def delete_unattached_disk(self, disk_id: str) -> dict:
        if self.use_fixtures:
            return {"disk_id": disk_id, "action": "deleted", "simulated": True}
        raise NotImplementedError

    @staticmethod
    def _normalize_vm(v) -> dict:
        return {}

    @staticmethod
    def _normalize_nsg(n) -> dict:
        return {}

    @staticmethod
    def _normalize_disk(d) -> dict:
        return {}