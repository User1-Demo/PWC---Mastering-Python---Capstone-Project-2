from typing import Protocol


class ProviderError(RuntimeError):
    """A cloud-provider operation failed and may be safe to retry."""


class CloudProvider(Protocol):
    def list_resources(self, subscription_id: str) -> list[dict]: ...

    def ensure_tags(self, subscription_id: str, resource: dict, tags: dict[str, str]) -> bool: ...

    def deny_nsg_rules(
        self, subscription_id: str, resource: dict, rule_names: list[str]
    ) -> bool: ...
