from contextlib import asynccontextmanager
from fastapi import FastAPI
from cloudguard.api.v1.router import api_router
from cloudguard.core.config import settings
from cloudguard.db.base import Base
from cloudguard.db.session import engine
@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)
    yield
app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.include_router(api_router)
@app.get("/", tags=["Root"])
def root(): return {"name": settings.app_name, "docs": "/docs", "phase": "Phase 1 Foundation"}
