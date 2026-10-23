from cloudguard import security


def test_login_success(client, admin_user):
    resp = client.post("/api/v1/auth/login",
                        data={"username": "admin@test.com", "password": "pass123"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_invalid_credentials(client, admin_user):
    resp = client.post("/api/v1/auth/login",
                        data={"username": "admin@test.com", "password": "wrong"})
    assert resp.status_code == 401


def test_policy_creation_requires_admin_role(client, db_session):
    from cloudguard import models
    user = models.User(email="eng@test.com",
                        hashed_password=security.hash_password("x"),
                        role=models.RoleEnum.CLOUD_ENGINEER)
    db_session.add(user)
    db_session.commit()
    token = security.create_access_token(user.id, user.role.value)
    resp = client.post("/api/v1/policies",
                        json={"name": "tag-check", "rule_type": "tagging", "resource_type": "vm",
                              "condition": {"required_tags": ["environment"]}, "severity": "medium"},
                        headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403