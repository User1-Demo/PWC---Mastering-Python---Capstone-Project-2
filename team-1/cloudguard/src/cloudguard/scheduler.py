import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .database import SessionLocal
from . import models
from .k8s_dispatcher import dispatch_scan_job

log = logging.getLogger("scheduler")
scheduler = BackgroundScheduler()


def _trigger_scan(subscription_id: str):
    db = SessionLocal()
    try:
        scan = models.Scan(subscription_id=subscription_id, triggered_by="scheduler",
                            trigger_source="schedule")
        db.add(scan)
        db.commit()
        dispatch_scan_job(scan.id)
    finally:
        db.close()


def start_scheduler():
    db = SessionLocal()
    subs = db.query(models.Subscription).filter(
        models.Subscription.schedule_cron.isnot(None), models.Subscription.is_active == True  # noqa
    ).all()
    for sub in subs:
        try:
            trigger = CronTrigger.from_crontab(sub.schedule_cron)
            scheduler.add_job(_trigger_scan, trigger, args=[sub.id], id=f"scan-{sub.id}",
                               replace_existing=True)
        except Exception as e:
            log.error("Invalid cron for subscription %s: %s", sub.id, e)
    db.close()
    scheduler.start()