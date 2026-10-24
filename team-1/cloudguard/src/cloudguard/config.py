from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    app_name: str = "CloudGuard"
    env: str = "dev"

    database_url: str = "sqlite:///./cloudguard.db"

    jwt_secret: str = "CHANGE_ME_IN_PROD"       # inject via K8s Secret
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    azure_use_fixtures: bool = True              # True => simulated JSON data
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None       # never logged, never persisted raw

    remediation_max_retries: int = 3
    remediation_backoff_base_seconds: int = 2

    scan_resource_concurrency: int = 10

    k8s_namespace: str = "cloudguard"
    k8s_in_cluster: bool = False
    scan_worker_image: str = "cloudguard/scan-worker:latest"
    remediation_worker_image: str = "cloudguard/remediation-worker:latest"

    class Config:
        env_file = ".env"
        env_prefix = "CLOUDGUARD_"


@lru_cache
def get_settings() -> Settings:
    return Settings()