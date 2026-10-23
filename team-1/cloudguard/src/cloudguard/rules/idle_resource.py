from datetime import datetime, timedelta
from .base import BaseRule, register_rule


@register_rule("idle_resource")
class IdleResourceRule(BaseRule):
    """condition: {"cpu_threshold_percent": 2.0, "idle_days": 30} applies to vm|disk"""

    def evaluate(self, resources):
        cpu_threshold = self.condition.get("cpu_threshold_percent", 2.0)
        findings = []
        for r in resources:
            if r["resource_type"] == "vm":
                if r.get("power_state") == "running" and r.get("cpu_avg_percent_14d", 100) < cpu_threshold:
                    findings.append({"resource_id": r["id"],
                                      "details": {"reason": "low_cpu_utilization", "resource": r}})
            elif r["resource_type"] == "disk":
                if r.get("disk_state") == "Unattached":
                    findings.append({"resource_id": r["id"],
                                      "details": {"reason": "unattached_disk", "resource": r}})
        return findings