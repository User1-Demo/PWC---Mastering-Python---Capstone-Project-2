from fastapi import FastAPI
from .database import init_db
from .api.v1.router import api_router
from .config import get_settings

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")
app.include_router(api_router, prefix="/api/v1")


@app.on_event("startup")
def on_startup():
    init_db()
    # scheduler intentionally optional: enabled per-deployment
    # from .scheduler import start_scheduler; start_scheduler()