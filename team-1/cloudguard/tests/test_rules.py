from cloudguard.rules.tagging import TaggingRule
from cloudguard.rules.nsg import NSGOpenPortRule
from cloudguard.rules.idle_resource import IdleResourceRule
from cloudguard.rules.secret_expiry import SecretExpiryRule


def test_tagging_rule_flags_missing_tags():
    rule = TaggingRule({"required_tags": ["environment", "owner"]}, "medium")
    resources = [{"id": "r1", "tags": {"environment": "prod"}}]
    findings = rule.evaluate(resources)
    assert len(findings) == 1
    assert "owner" in findings[0]["details"]["missing_tags"]


def test_tagging_rule_compliant_resource_no_finding():
    rule = TaggingRule({"required_tags": ["environment"]}, "medium")
    resources = [{"id": "r1", "tags": {"environment": "prod"}}]
    assert rule.evaluate(resources) == []


def test_nsg_rule_flags_open_risky_port():
    rule = NSGOpenPortRule({"risky_ports": ["22"], "disallow_any_source": True}, "high")
    nsgs = [{"id": "nsg1", "rules": [
        {"name": "r1", "direction": "Inbound", "access": "Allow",
         "destination_port_range": "22", "source_address_prefix": "*"}]}]
    findings = rule.evaluate(nsgs)
    assert len(findings) == 1


def test_idle_resource_flags_unattached_disk():
    rule = IdleResourceRule({}, "low")
    disks = [{"id": "d1", "resource_type": "disk", "disk_state": "Unattached"}]
    assert len(rule.evaluate(disks)) == 1


def test_secret_expiry_flags_near_expiry():
    from datetime import datetime, timedelta
    soon = (datetime.utcnow() + timedelta(days=5)).isoformat() + "Z"
    rule = SecretExpiryRule({"warn_days": 30}, "medium")
    secrets = [{"id": "s1", "expires_on": soon}]
    assert len(rule.evaluate(secrets)) == 1