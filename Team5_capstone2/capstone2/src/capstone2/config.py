from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "capstone2"
    environment: str = "dev"
    database_url: str = "sqlite:///./cloudguard.db"
    jwt_secret: str = "change-me"
    access_token_minutes: int = 60
    azure_mode: str = "mock"
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    default_admin_username: str = "admin@cloudguard.local"
    default_admin_password: str = "ChangeMe123!"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()
