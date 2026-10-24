from fastapi import APIRouter
from . import auth, subscriptions, policies, scans, findings, audit_logs, health

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(subscriptions.router)
api_router.include_router(policies.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(audit_logs.router)