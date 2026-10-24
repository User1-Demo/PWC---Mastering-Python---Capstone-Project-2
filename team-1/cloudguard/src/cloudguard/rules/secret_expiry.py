from datetime import datetime, timedelta
from .base import BaseRule, register_rule


@register_rule("secret_expiry")
class SecretExpiryRule(BaseRule):
    """condition: {"warn_days": 30}"""

    def evaluate(self, resources):
        warn_days = self.condition.get("warn_days", 30)
        threshold = datetime.utcnow() + timedelta(days=warn_days)
        findings = []
        for s in resources:
            expires_on = s.get("expires_on")
            if not expires_on:
                continue
            exp = datetime.fromisoformat(expires_on.replace("Z", "+00:00")).replace(tzinfo=None)
            if exp <= threshold:
                findings.append({
                    "resource_id": s["id"],
                    "details": {"expires_on": expires_on, "resource": s},
                })
        return findings