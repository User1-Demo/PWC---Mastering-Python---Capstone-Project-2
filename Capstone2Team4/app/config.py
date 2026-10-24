from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    app_env: str = "development"
    database_url: str = "sqlite:///./cloudguard.db"
    jwt_secret: str = "local-only-change-me-before-deployment"
    jwt_expire_minutes: int = 60
    azure_provider: str = "mock"
    execution_mode: str = "inline"
    worker_image: str = "cloudguard:latest"
    kubernetes_namespace: str = "cloudguard"
    kubernetes_secret_name: str = "cloudguard-secrets"
    kubernetes_scan_service_account: str = "cloudguard-scan-worker"
    kubernetes_remediation_service_account: str = "cloudguard-remediation-worker"
    default_required_tags: str = "owner,environment,cost-center"
    auto_remediate_low_risk: bool = True
    remediation_max_retries: int = 3
    remediation_retry_base_seconds: float = 1.0
    key_vault_expiry_days: int = 30
    idle_cpu_threshold_percent: float = 5.0
    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: str = ""

    @field_validator("azure_provider")
    @classmethod
    def validate_provider(cls, value: str) -> str:
        value = value.lower()
        if value not in {"mock", "azure"}:
            raise ValueError("AZURE_PROVIDER must be 'mock' or 'azure'")
        return value

    @field_validator("execution_mode")
    @classmethod
    def validate_execution_mode(cls, value: str) -> str:
        value = value.lower()
        if value not in {"inline", "kubernetes"}:
            raise ValueError("EXECUTION_MODE must be 'inline' or 'kubernetes'")
        return value

    @field_validator("jwt_secret")
    @classmethod
    def require_production_secret(cls, value: str, info) -> str:
        if info.data.get("app_env") == "production" and (
            len(value) < 32 or value == "local-only-change-me-before-deployment"
        ):
            raise ValueError("Set a unique JWT_SECRET of at least 32 characters in production")
        return value

    @property
    def required_tags(self) -> list[str]:
        return [tag.strip() for tag in self.default_required_tags.split(",") if tag.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
