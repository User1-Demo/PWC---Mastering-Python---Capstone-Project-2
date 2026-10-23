def test_health(client):
    r=client.get("/api/v1/health"); assert r.status_code == 200; assert r.json()["status"] == "healthy"
def test_login_and_me(client, headers):
    r=client.get("/api/v1/users/me", headers=headers); assert r.status_code == 200; assert r.json()["role"] == "ADMIN"
def test_create_subscription(client, headers):
    payload={"azure_subscription_id":"11111111-1111-1111-1111-111111111111","name":"Team3 Dev","environment":"DEV","tenant_id":"22222222-2222-2222-2222-222222222222"}
    r=client.post("/api/v1/subscriptions", json=payload, headers=headers); assert r.status_code == 201
    assert client.get("/api/v1/subscriptions", headers=headers).json()[0]["name"] == "Team3 Dev"
def test_create_policy(client, headers):
    payload={"name":"Mandatory Tags","rule_type":"REQUIRED_TAGS","description":"Require governance tags","severity":"LOW","configuration":{"required_tags":["Environment","Owner","CostCenter"]},"auto_remediate":True}
    r=client.post("/api/v1/policies", json=payload, headers=headers); assert r.status_code == 201
def test_reject_high_risk_auto_remediation(client, headers):
    payload={"name":"Risky ports","rule_type":"NSG_RISKY_PORTS","description":"Detect public management ports","severity":"HIGH","configuration":{"ports":[22,3389]},"auto_remediate":True}
    assert client.post("/api/v1/policies", json=payload, headers=headers).status_code == 422
