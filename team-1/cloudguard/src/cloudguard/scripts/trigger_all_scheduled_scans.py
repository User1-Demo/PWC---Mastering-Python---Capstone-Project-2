"""Invoked by the K8s CronJob to kick off scans for all active subscriptions."""
from ..database import SessionLocal, init_db
from .. import models
from ..k8s_dispatcher import dispatch_scan_job


def main():
    init_db()
    db = SessionLocal()
    subs = db.query(models.Subscription).filter(models.Subscription.is_active == True).all()  # noqa
    for sub in subs:
        scan = models.Scan(subscription_id=sub.id, triggered_by="cronjob", trigger_source="schedule")
        db.add(scan)
        db.commit()
        dispatch_scan_job(scan.id)
    db.close()


if __name__ == "__main__":
    main()