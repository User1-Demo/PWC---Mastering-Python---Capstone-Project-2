from .base import BaseRule, register_rule

RISKY_PORTS = {"22", "3389", "3306", "1433", "5432"}


@register_rule("nsg")
class NSGOpenPortRule(BaseRule):
    """condition: {"risky_ports": ["22","3389"], "disallow_any_source": true}"""

    def evaluate(self, resources):
        risky_ports = set(self.condition.get("risky_ports", RISKY_PORTS))
        disallow_any = self.condition.get("disallow_any_source", True)
        findings = []
        for nsg in resources:
            for rule in nsg.get("rules", []):
                if rule.get("direction") != "Inbound" or rule.get("access") != "Allow":
                    continue
                port = str(rule.get("destination_port_range"))
                src = rule.get("source_address_prefix")
                if port in risky_ports and (not disallow_any or src == "*"):
                    findings.append({
                        "resource_id": nsg["id"],
                        "details": {"rule_name": rule["name"], "port": port,
                                     "source": src, "resource": nsg},
                    })
        return findings