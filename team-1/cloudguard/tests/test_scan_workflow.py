from unittest.mock import patch
from cloudguard import models


def test_trigger_scan_and_run_inprocess(client, db_session, auth_header):
    sub_resp = client.post("/api/v1/subscriptions", json={
        "name": "test-sub", "azure_subscription_id": "11111111-1111-1111-1111-111111111111",
        "tenant_id": "tenant-1", "environment": "dev", "credential_ref": "k8s-secret/test"
    }, headers=auth_header)
    assert sub_resp.status_code == 200
    sub_id = sub_resp.json()["id"]

    policy_resp = client.post("/api/v1/policies", json={
        "name": "require-tags", "rule_type": "tagging", "resource_type": "vm",
        "condition": {"required_tags": ["environment", "owner"]}, "severity": "medium",
        "auto_remediate": True,
    }, headers=auth_header)
    assert policy_resp.status_code == 200

    with patch("cloudguard.api.v1.scans.dispatch_scan_job") as mock_dispatch:
        mock_dispatch.side_effect = lambda scan_id: __import__(
            "cloudguard.workers.scan_worker", fromlist=["run_scan"]).run_scan(scan_id)
        resp = client.post("/api/v1/scans", json={"subscription_id": sub_id}, headers=auth_header)
        assert resp.status_code == 200

    findings = db_session.query(models.Finding).all()
    assert len(findings) > 0


def test_invalid_policy_condition_rejected(client, auth_header):
    resp = client.post("/api/v1/policies", json={
        "name": "bad-rule", "rule_type": "tagging", "resource_type": "vm",
        "condition": {"not_a_real_field": True}, "severity": "medium",
    }, headers=auth_header)
    assert resp.status_code == 422