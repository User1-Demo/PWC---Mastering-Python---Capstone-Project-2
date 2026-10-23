"""
Entry point executed inside the scan-worker container / K8s Job.
Usage: python -m cloudguard.workers.scan_worker --scan-id <id>
"""
import argparse
import logging
from datetime import datetime

from ..database import SessionLocal, init_db
from .. import models, audit
from ..azure_client import AzureClient
from ..rules.engine import RuleEngine
from ..remediation.executor import RemediationExecutor

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scan_worker")


def run_scan(scan_id: str):
    init_db()
    db = SessionLocal()
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        log.error("Scan %s not found", scan_id)
        return

    scan.status = models.ScanStatusEnum.RUNNING
    db.commit()
    audit.write_audit(db, action="SCAN_STARTED", entity_type="Scan",
                       entity_id=scan.id, actor=scan.triggered_by)

    try:
        subscription = db.query(models.Subscription).filter(
            models.Subscription.id == scan.subscription_id).first()
        client = AzureClient(subscription.azure_subscription_id, subscription.tenant_id)
        inventory = client.full_inventory()
        resource_count = sum(len(v) for v in inventory.values())

        engine = RuleEngine(db)
        raw_findings = engine.evaluate_inventory(inventory)

        executor = RemediationExecutor(db)
        for rf in raw_findings:
            finding = models.Finding(
                scan_id=scan.id,
                subscription_id=scan.subscription_id,
                rule_id=rf["rule"].id,
                resource_id=rf["resource_id"],
                resource_type=rf["resource_type"],
                severity=rf["severity"],
                details=rf["details"],
            )
            db.add(finding)
            db.commit()
            audit.write_audit(db, action="FINDING_DETECTED", entity_type="Finding",
                               entity_id=finding.id, actor="system",
                               metadata={"rule": rf["rule"].name})

            if rf["rule"].auto_remediate:
                executor.execute(finding, actor="service_account", approved=False)

        scan.resource_count = resource_count
        scan.finding_count = len(raw_findings)
        scan.status = models.ScanStatusEnum.SUCCESS
        scan.completed_at = datetime.utcnow()
        db.commit()
        audit.write_audit(db, action="SCAN_COMPLETED", entity_type="Scan",
                           entity_id=scan.id, actor=scan.triggered_by,
                           metadata={"resources": resource_count, "findings": len(raw_findings)})
    except Exception as e:
        log.exception("Scan failed")
        scan.status = models.ScanStatusEnum.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
        audit.write_audit(db, action="SCAN_FAILED", entity_type="Scan",
                           entity_id=scan.id, actor=scan.triggered_by, metadata={"error": str(e)})
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-id", required=True)
    args = parser.parse_args()
    run_scan(args.scan_id)