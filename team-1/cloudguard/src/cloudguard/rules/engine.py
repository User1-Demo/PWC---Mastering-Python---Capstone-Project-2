from typing import List, Dict, Any
from sqlalchemy.orm import Session
from .. import models
from .base import RULE_REGISTRY
from . import tagging, nsg, idle_resource, secret_expiry  # noqa: ensures registration


class RuleEngine:
    def __init__(self, db: Session):
        self.db = db

    def active_rules(self) -> List[models.PolicyRule]:
        return self.db.query(models.PolicyRule).filter(models.PolicyRule.is_active == True).all()  # noqa

    def evaluate_inventory(self, inventory: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Returns raw finding dicts: {rule, resource_id, details, severity}"""
        all_findings = []
        for rule_def in self.active_rules():
            rule_cls = RULE_REGISTRY.get(rule_def.rule_type)
            if rule_cls is None:
                continue
            resources = inventory.get(rule_def.resource_type, [])
            rule_instance = rule_cls(condition=rule_def.condition, severity=rule_def.severity.value)
            for f in rule_instance.evaluate(resources):
                all_findings.append({
                    "rule": rule_def,
                    "resource_id": f["resource_id"],
                    "resource_type": rule_def.resource_type,
                    "details": f["details"],
                    "severity": rule_def.severity,
                })
        return all_findings