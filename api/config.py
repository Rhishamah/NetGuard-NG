from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    app_name: str = "NetGuard-NG API"
    app_version: str = "1.0.0"

    database_url: str = "sqlite:///.netguard.db"
    secret_key: str = Field(...)
    access_token_expire_minutes: int = 60

    admin_username: str = Field(...)
    admin_password_hash: str = Field(...)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()