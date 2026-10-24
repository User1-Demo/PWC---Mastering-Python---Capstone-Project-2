from contextlib import asynccontextmanager
from fastapi import FastAPI
from sqlalchemy import select
from capstone2.api import router
from capstone2.config import get_settings
from capstone2.database import Base, SessionLocal, engine
from capstone2.models import User
from capstone2.security import hash_password
@asynccontextmanager
async def lifespan(app:FastAPI):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        s=get_settings()
        if not db.scalar(select(User).where(User.username==s.default_admin_username)):
            db.add(User(username=s.default_admin_username,password_hash=hash_password(s.default_admin_password),role="admin")); db.commit()
    yield
app=FastAPI(title="Team5 CloudRemedy API",version="0.1.0",lifespan=lifespan)
app.include_router(router)
