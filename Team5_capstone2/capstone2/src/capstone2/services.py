from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from capstone2.audit import write_audit
from capstone2.azure_client import AzureInventoryClient
from capstone2.models import Finding, FindingStatus, PolicyRule, RemediationAction, Scan, ScanStatus, Subscription
from capstone2.rules import RULES

def run_scan(db:Session, scan:Scan, actor_id:int|None=None):
    scan.status=ScanStatus.RUNNING.value; scan.started_at=datetime.now(timezone.utc); db.flush()
    try:
        sub=db.get(Subscription,scan.subscription_id)
        if not sub: raise ValueError("Subscription not found")
        resources=AzureInventoryClient().list_resources(sub.azure_subscription_id)
        policies=db.scalars(select(PolicyRule).where(PolicyRule.enabled.is_(True))).all()
        for resource in resources:
            for policy in policies:
                details=RULES[policy.rule_type].evaluate(resource,policy)
                if not details: continue
                finding=Finding(scan_id=scan.id,policy_rule_id=policy.id,resource_id=resource.id,resource_type=resource.type,title=f"{policy.name}: {resource.name}",details=details,severity=policy.severity,status=FindingStatus.OPEN.value)
                db.add(finding); db.flush(); write_audit(db,"finding.created","finding",finding.id,actor_id,details)
                if policy.auto_remediate and policy.severity in {"low","medium"}: remediate(db,finding,actor_id,approved=True)
        scan.status=ScanStatus.COMPLETED.value; scan.completed_at=datetime.now(timezone.utc); write_audit(db,"scan.completed","scan",scan.id,actor_id)
    except Exception as exc:
        scan.status=ScanStatus.FAILED.value; scan.error=str(exc); scan.completed_at=datetime.now(timezone.utc); write_audit(db,"scan.failed","scan",scan.id,actor_id,{"error":str(exc)})
    db.commit(); db.refresh(scan); return scan

def remediate(db:Session,finding:Finding,actor_id:int,approved:bool=False):
    if finding.status==FindingStatus.REMEDIATED.value:
        return {"status":"no_op","reason":"already compliant"}
    if finding.severity in {"high","critical"} and not approved:
        finding.status=FindingStatus.PENDING_APPROVAL.value
        action=RemediationAction(finding_id=finding.id,requested_by=actor_id,status="pending_approval")
        db.add(action); write_audit(db,"remediation.requested","finding",finding.id,actor_id); db.commit()
        return {"status":"pending_approval"}
    policy=db.get(PolicyRule,finding.policy_rule_id)
    # Training MVP: result records the safe intended change. Plug live Azure update calls here after sandbox validation.
    result={"mode":getattr(__import__('capstone2.config',fromlist=['get_settings']).get_settings(), 'azure_mode'),"rule_type":policy.rule_type,"changed":True}
    action=RemediationAction(finding_id=finding.id,requested_by=actor_id,approved_by=actor_id if approved else None,status="completed",result=result)
    db.add(action); finding.status=FindingStatus.REMEDIATED.value; write_audit(db,"remediation.completed","finding",finding.id,actor_id,result); db.commit()
    return {"status":"completed","result":result}
