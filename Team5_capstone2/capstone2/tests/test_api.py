def test_end_to_end(client,auth):
 s=client.post("/api/v1/subscriptions",headers=auth,json={"name":"Demo","azure_subscription_id":"00000000-demo","environment":"dev"}); assert s.status_code==201
 p=client.post("/api/v1/policies",headers=auth,json={"name":"Owner tag","rule_type":"required_tags","severity":"low","config":{"required_tags":["owner"]},"auto_remediate":True}); assert p.status_code==201
 p=client.post("/api/v1/policies",headers=auth,json={"name":"No public SSH","rule_type":"open_nsg_port","severity":"high","config":{"ports":[22]},"auto_remediate":False}); assert p.status_code==201
 scan=client.post("/api/v1/scans",headers=auth,json={"subscription_id":s.json()["id"]}); assert scan.status_code==201 and scan.json()["status"]=="completed"
 findings=client.get("/api/v1/findings",headers=auth).json(); assert len(findings)>=2
 high=next(x for x in findings if x["severity"]=="high")
 req=client.post(f"/api/v1/findings/{high['id']}/remediate",headers=auth); assert req.json()["status"]=="pending_approval"
def test_validation_blocks_high_auto_remediation(client,auth):
 r=client.post("/api/v1/policies",headers=auth,json={"name":"Bad","rule_type":"open_nsg_port","severity":"high","config":{"ports":[22]},"auto_remediate":True}); assert r.status_code==422
