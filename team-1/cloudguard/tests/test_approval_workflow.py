from cloudguard import models


def _seed_high_risk_finding(db_session):
    sub = models.Subscription(name="s", azure_subscription_id="sub-x", tenant_id="t",
                               environment="prod", credential_ref="ref")
    db_session.add(sub); db_session.commit()
    rule = models.PolicyRule(name="nsg-check", rule_type="nsg", resource_type="nsg",
                              condition={"risky_ports": ["22"]}, severity=models.SeverityEnum.HIGH,
                              auto_remediate=False)
    db_session.add(rule); db_session.commit()
    scan = models.Scan(subscription_id=sub.id, triggered_by="tester", trigger_source="api")
    db_session.add(scan); db_session.commit()
    finding = models.Finding(
        scan_id=scan.id, subscription_id=sub.id, rule_id=rule.id, resource_id="nsg-1",
        resource_type="nsg", severity=models.SeverityEnum.HIGH,
        details={"rule_name": "allow-ssh-any",
                 "resource": {"id": "nsg-1", "rules": [
                     {"name": "allow-ssh-any", "source_address_prefix": "*"}]}})
    db_session.add(finding); db_session.commit()
    return finding


def test_high_risk_remediation_requires_approval(client, db_session, auth_header):
    finding = _seed_high_risk_finding(db_session)
    resp = client.post(f"/api/v1/findings/{finding.id}/remediate", headers=auth_header)
    assert resp.status_code == 200
    db_session.refresh(finding)
    assert finding.status == models.FindingStatusEnum.PENDING_APPROVAL


def test_unauthorized_role_cannot_approve(client, db_session, auth_header):
    finding = _seed_high_risk_finding(db_session)
    resp = client.post(f"/api/v1/findings/{finding.id}/approve", headers=auth_header)  # admin, not sec-officer
    assert resp.status_code == 403


def test_security_officer_can_approve(client, db_session, secoff_header):
    finding = _seed_high_risk_finding(db_session)
    resp = client.post(f"/api/v1/findings/{finding.id}/approve", headers=secoff_header)
    assert resp.status_code == 200


def test_exception_requires_future_expiry(client, db_session, auth_header):
    finding = _seed_high_risk_finding(db_session)
    resp = client.post(f"/api/v1/findings/{finding.id}/exception",
                        json={"reason": "temp", "expiry_date": "2000-01-01T00:00:00"},
                        headers=auth_header)
    assert resp.status_code == 400