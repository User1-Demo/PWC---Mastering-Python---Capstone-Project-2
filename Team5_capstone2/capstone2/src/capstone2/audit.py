import hashlib, json
from sqlalchemy import select
from sqlalchemy.orm import Session
from capstone2.models import AuditLog

def write_audit(db:Session, action:str, entity_type:str, entity_id:str|int, actor_id:int|None, data:dict|None=None):
    previous=db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    previous_hash=previous.event_hash if previous else ""
    payload={"action":action,"entity_type":entity_type,"entity_id":str(entity_id),"actor_id":actor_id,"data":data or {},"previous_hash":previous_hash}
    event_hash=hashlib.sha256(json.dumps(payload,sort_keys=True,default=str).encode()).hexdigest()
    event=AuditLog(**payload,event_hash=event_hash); db.add(event); db.flush(); return event
