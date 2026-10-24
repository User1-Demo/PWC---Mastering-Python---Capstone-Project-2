from abc import ABC, abstractmethod
from typing import Any, Dict, List

RULE_REGISTRY: Dict[str, type] = {}


def register_rule(rule_type: str):
    def wrapper(cls):
        RULE_REGISTRY[rule_type] = cls
        return cls
    return wrapper


class BaseRule(ABC):
    """New policy checks are added by subclassing BaseRule and registering
    with @register_rule('<rule_type>') — the evaluator never changes."""

    resource_type: str

    def __init__(self, condition: Dict[str, Any], severity: str):
        self.condition = condition
        self.severity = severity

    @abstractmethod
    def evaluate(self, resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return list of finding dicts: {resource_id, details}"""
        ...