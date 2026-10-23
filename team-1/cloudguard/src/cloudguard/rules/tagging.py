from .base import BaseRule, register_rule


@register_rule("tagging")
class TaggingRule(BaseRule):
    """condition: {"required_tags": ["environment", "owner"]}"""

    def evaluate(self, resources):
        required = set(self.condition.get("required_tags", []))
        findings = []
        for r in resources:
            tags = set((r.get("tags") or {}).keys())
            missing = required - tags
            if missing:
                findings.append({
                    "resource_id": r["id"],
                    "details": {"missing_tags": sorted(missing), "resource": r},
                })
        return findings