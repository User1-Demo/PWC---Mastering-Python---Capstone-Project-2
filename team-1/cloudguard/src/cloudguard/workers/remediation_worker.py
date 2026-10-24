"""Entry point for remediation K8s Job (approved high-risk actions)."""
import argparse
import logging
from ..database import SessionLocal, init_db
from .. import models
from ..remediation.executor import RemediationExecutor

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("remediation_worker")


def run_remediation(finding_id: str, actor: str, approved: bool):
    init_db()
    db = SessionLocal()
    try:
        finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
        if not finding:
            log.error("Finding %s not found", finding_id)
            return
        executor = RemediationExecutor(db)
        executor.execute(finding, actor=actor, approved=approved)
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--approved", action="store_true")
    args = parser.parse_args()
    run_remediation(args.finding_id, args.actor, args.approved)