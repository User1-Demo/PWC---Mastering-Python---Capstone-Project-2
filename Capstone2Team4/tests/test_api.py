from datetime import datetime, timedelta, timezone


def test_auth_rbac_subscription_policy_and_audit(client, admin_headers):
    test_client, _ = client
    assert test_client.get("/api/v1/health").json() == {"status": "ok"}
    assert test_client.get("/api/v1/subscriptions").status_code == 401
    assert test_client.post(
        "/api/v1/subscriptions",
        json={"subscription_id": "sub-001", "name": "training", "environment": "dev"},
    ).status_code == 401
    created = test_client.post(
        "/api/v1/subscriptions",
        headers=admin_headers,
        json={"subscription_id": "sub-001", "name": "training", "environment": "dev"},
    )
    assert created.status_code == 201
    policy_response = test_client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "required tags",
            "rule_type": "required_tags",
            "severity": "low",
            "parameters": {"required_tags": ["owner"]},
        },
    )
    assert policy_response.status_code == 201
    policy = policy_response.json()
    updated_subscription = test_client.patch(
        f"/api/v1/subscriptions/{created.json()['id']}",
        headers=admin_headers,
        json={"environment": "test"},
    )
    assert updated_subscription.status_code == 200
    updated_policy = test_client.patch(
        f"/api/v1/policies/{policy['id']}",
        headers=admin_headers,
        json={"enabled": False},
    )
    assert updated_policy.status_code == 200
    assert updated_policy.json()["enabled"] is False
    assert test_client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "bad policy",
            "rule_type": "arbitrary",
            "severity": "low",
            "parameters": {},
        },
    ).status_code == 422
    logs = test_client.get("/api/v1/audit-logs", headers=admin_headers)
    assert logs.status_code == 200
    assert len(logs.json()) == 4
    assert test_client.get("/api/v1/audit-logs/verify", headers=admin_headers).json()["valid"]


def test_scan_finds_and_auto_remediates_explicit_tag_values(client, admin_headers, monkeypatch):
    from app.config import get_settings

    test_client, TestingSession = client
    subscription = test_client.post(
        "/api/v1/subscriptions",
        headers=admin_headers,
        json={"subscription_id": "sub-scan", "name": "local", "environment": "dev"},
    ).json()
    test_client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "owner tag",
            "rule_type": "required_tags",
            "severity": "low",
            "parameters": {"required_tags": ["owner"], "tag_values": {"owner": "platform"}},
            "auto_remediate": True,
        },
    )
    scan = test_client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={"subscription_id": subscription["id"]},
    )
    assert scan.status_code == 202
    scans = test_client.get("/api/v1/scans", headers=admin_headers).json()
    assert scans[0]["status"] == "completed"
    findings = test_client.get("/api/v1/findings", headers=admin_headers).json()
    assert findings
    assert any(finding["status"] == "remediated" for finding in findings)
    assert get_settings().azure_provider == "mock"


def test_high_risk_finding_requires_security_officer_approval(client, admin_headers):
    test_client, TestingSession = client
    user = test_client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "security@test.local",
            "password": "SecurityPassword123!",
            "role": "security_officer",
        },
    )
    assert user.status_code == 201
    engineer = test_client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "engineer@test.local",
            "password": "EngineerPassword123!",
            "role": "cloud_engineer",
        },
    )
    assert engineer.status_code == 201
    token = test_client.post(
        "/api/v1/auth/login",
        json={"email": "security@test.local", "password": "SecurityPassword123!"},
    ).json()["access_token"]
    officer_headers = {"Authorization": f"Bearer {token}"}
    engineer_token = test_client.post(
        "/api/v1/auth/login",
        json={"email": "engineer@test.local", "password": "EngineerPassword123!"},
    ).json()["access_token"]
    engineer_headers = {"Authorization": f"Bearer {engineer_token}"}

    subscription = test_client.post(
        "/api/v1/subscriptions",
        headers=admin_headers,
        json={"subscription_id": "sub-high", "name": "live-like", "environment": "dev"},
    ).json()
    test_client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "high-risk nsg",
            "rule_type": "nsg_open_ports",
            "severity": "high",
            "parameters": {"blocked_ports": [22], "remediation_action": "deny_exposed_rules"},
        },
    )
    test_client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={"subscription_id": subscription["id"]},
    )
    finding = test_client.get(
        "/api/v1/findings",
        headers=admin_headers,
        params={"severity": "high"},
    ).json()[0]
    request = test_client.post(
        f"/api/v1/findings/{finding['id']}/remediate",
        headers=admin_headers,
    )
    assert request.status_code == 202
    assert request.json()["status"] == "pending_approval"
    assert test_client.get(
        "/api/v1/remediations",
        headers=admin_headers,
        params={"finding_id": finding["id"]},
    ).json()[0]["status"] == "pending_approval"
    assert test_client.post(
        f"/api/v1/findings/{finding['id']}/approve",
        headers=engineer_headers,
        json={"approved": True, "reason": "Not authorized"},
    ).status_code == 403
    assert test_client.post(
        f"/api/v1/findings/{finding['id']}/approve",
        headers=officer_headers,
        json={"approved": True, "reason": "Reviewed and accepted"},
    ).status_code == 202
    assert test_client.get(
        "/api/v1/findings",
        headers=admin_headers,
        params={"status": "remediated"},
    ).status_code == 200


def test_time_limited_exception_expires_and_audit_chain_detects_mutation(client, admin_headers):
    from app.audit import verify_chain
    from app.models import AuditLog

    test_client, TestingSession = client
    subscription = test_client.post(
        "/api/v1/subscriptions",
        headers=admin_headers,
        json={"subscription_id": "sub-exception", "name": "exception", "environment": "dev"},
    ).json()
    test_client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "tag exception rule",
            "rule_type": "required_tags",
            "severity": "medium",
            "parameters": {"required_tags": ["owner"]},
        },
    ).json()
    test_client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={"subscription_id": subscription["id"]},
    )
    finding = test_client.get("/api/v1/findings", headers=admin_headers).json()[0]
    response = test_client.post(
        f"/api/v1/findings/{finding['id']}/exception",
        headers=admin_headers,
        json={
            "reason": "Temporary waiver pending rollout",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
        },
    )
    assert response.status_code == 201
    test_client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={"subscription_id": subscription["id"]},
    )
    same_resource = [
        item
        for item in test_client.get("/api/v1/findings", headers=admin_headers).json()
        if item["resource_id"] == finding["resource_id"]
    ]
    assert len(same_resource) == 1
    with TestingSession() as db:
        from app.models import FindingException

        exception = db.query(FindingException).filter_by(finding_id=finding["id"]).one()
        exception.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    test_client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={"subscription_id": subscription["id"]},
    )
    same_resource = [
        item
        for item in test_client.get("/api/v1/findings", headers=admin_headers).json()
        if item["resource_id"] == finding["resource_id"]
    ]
    assert len(same_resource) == 2
    assert any(item["status"] == "open" for item in same_resource)
    assert test_client.get("/api/v1/audit-logs/verify", headers=admin_headers).json()["valid"]
    with TestingSession() as db:
        event = db.query(AuditLog).first()
        event.event_metadata = {"tampered": True}
        db.commit()
        valid, invalid_id = verify_chain(db)
        assert not valid
        assert invalid_id == event.id
