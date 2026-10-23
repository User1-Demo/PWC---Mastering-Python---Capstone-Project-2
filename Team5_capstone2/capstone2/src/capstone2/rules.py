from abc import ABC, abstractmethod
from capstone2.azure_client import Resource
from capstone2.models import PolicyRule
class Rule(ABC):
    @abstractmethod
    def evaluate(self,r:Resource,p:PolicyRule)->dict|None: ...
class RequiredTagsRule(Rule):
    def evaluate(self,r,p):
        missing=[x for x in p.config["required_tags"] if not r.tags.get(x)]
        return {"missing_tags":missing} if missing else None
class OpenNSGPortRule(Rule):
    def evaluate(self,r,p):
        if "networkSecurityGroups" not in r.type: return None
        risky=[]
        for rule in r.properties.get("security_rules",[]):
            if rule.get("access")=="Allow" and rule.get("source") in {"*","0.0.0.0/0","Internet"} and rule.get("port") in p.config["ports"]: risky.append(rule)
        return {"risky_rules":risky} if risky else None
RULES={"required_tags":RequiredTagsRule(),"open_nsg_port":OpenNSGPortRule()}
