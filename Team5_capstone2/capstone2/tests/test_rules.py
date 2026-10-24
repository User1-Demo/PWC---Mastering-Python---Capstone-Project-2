from capstone2.azure_client import Resource
from capstone2.models import PolicyRule
from capstone2.rules import RequiredTagsRule,OpenNSGPortRule
def test_missing_tag():
 p=PolicyRule(config={"required_tags":["owner"]}); r=Resource("1","vm","vm",{},{}); assert RequiredTagsRule().evaluate(r,p)=={"missing_tags":["owner"]}
def test_open_port():
 p=PolicyRule(config={"ports":[22]}); r=Resource("1","nsg","Microsoft.Network/networkSecurityGroups",{}, {"security_rules":[{"access":"Allow","source":"*","port":22}]}); assert OpenNSGPortRule().evaluate(r,p)
