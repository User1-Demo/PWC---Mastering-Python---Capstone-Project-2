from fastapi import APIRouter
from cloudguard.api.v1 import auth, health, policies, subscriptions, users
api_router = APIRouter(prefix="/api/v1")
for router in [health.router, auth.router, users.router, subscriptions.router, policies.router]:
    api_router.include_router(router)
