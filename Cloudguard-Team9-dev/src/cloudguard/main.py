from fastapi import FastAPI

from cloudguard.api.audit_logs import router as audit_logs_router
from cloudguard.api.auth import router as auth_router
from cloudguard.api.findings import router as findings_router
from cloudguard.api.policies import router as policies_router
from cloudguard.api.scans import router as scans_router
from cloudguard.api.subscriptions import router as subscriptions_router

app = FastAPI(
    title="CloudGuard API",
    description="Cloud infrastructure compliance and remediation platform",
    version="0.1.0",
)

app.include_router(auth_router)
app.include_router(subscriptions_router)
app.include_router(policies_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(audit_logs_router)

@app.get("/api/v1/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "cloudguard-api",
        "version": "0.1.0",
    }