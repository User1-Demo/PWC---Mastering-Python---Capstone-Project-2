from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import models as _models  # noqa: F401
from app.api.routes import router
from app.database import engine, initialize_database


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database(engine)
    yield


app = FastAPI(
    title="CloudGuard",
    description="Azure compliance scanning, approval-gated remediation, and audit API.",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(router)
