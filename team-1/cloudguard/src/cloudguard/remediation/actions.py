from abc import ABC, abstractmethod
from typing import Dict, Any
from ..azure_client import AzureClient

ACTION_REGISTRY: Dict[str, type] = {}


def register_action(action_type: str):
    def wrapper(cls):
        ACTION_REGISTRY[action_type] = cls
        return cls
    return wrapper


class BaseAction(ABC):
    is_high_risk: bool = False

    def __init__(self, client: AzureClient):
        self.client = client

    @abstractmethod
    def is_compliant(self, finding_details: Dict[str, Any]) -> bool:
        """Idempotency check — if already compliant, apply() is a no-op."""
        ...

    @abstractmethod
    def apply(self, finding_details: Dict[str, Any]) -> Dict[str, Any]:
        ...


@register_action("add_missing_tags")
class AddMissingTagsAction(BaseAction):
    is_high_risk = False  # low-risk: pre-approved for auto-remediation

    def is_compliant(self, finding_details):
        resource = finding_details["resource"]
        missing = set(finding_details.get("missing_tags", []))
        return not (missing - set((resource.get("tags") or {}).keys()))

    def apply(self, finding_details):
        if self.is_compliant(finding_details):
            return {"no_op": True, "reason": "already_compliant"}
        resource = finding_details["resource"]
        default_tags = {tag: "UNSET" for tag in finding_details["missing_tags"]}
        return self.client.tag_resource(resource["id"], default_tags)


@register_action("close_open_nsg_rule")
class CloseOpenNSGRuleAction(BaseAction):
    is_high_risk = True  # network change => requires Security Officer approval

    def is_compliant(self, finding_details):
        # Re-check: does the risky rule still exist with source "*"?
        resource = finding_details["resource"]
        rule_name = finding_details["rule_name"]
        for r in resource.get("rules", []):
            if r["name"] == rule_name and r.get("source_address_prefix") == "*":
                return False
        return True

    def apply(self, finding_details):
        if self.is_compliant(finding_details):
            return {"no_op": True, "reason": "already_compliant"}
        resource = finding_details["resource"]
        return self.client.close_nsg_rule(resource["id"], finding_details["rule_name"])


@register_action("delete_unattached_disk")
class DeleteUnattachedDiskAction(BaseAction):
    is_high_risk = True  # destructive => requires approval

    def is_compliant(self, finding_details):
        return finding_details["resource"].get("disk_state") != "Unattached"

    def apply(self, finding_details):
        if self.is_compliant(finding_details):
            return {"no_op": True, "reason": "already_compliant"}
        resource = finding_details["resource"]
        return self.client.delete_unattached_disk(resource["id"])


RULE_TYPE_TO_ACTION = {
    "tagging": "add_missing_tags",
    "nsg": "close_open_nsg_rule",
    "idle_resource": "delete_unattached_disk",
}