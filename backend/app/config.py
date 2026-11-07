"""
Hackmetrix — Cyber Threat Intelligence Platform
Configuration module using Pydantic Settings.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_env: str = "development"
    secret_key: str = "CHANGE_ME_INSECURE_DEFAULT_KEY"
    debug: bool = True

    # Database
    database_url: str = "sqlite:///./hackmetrix.db"

    # CORS
    allowed_origins: str = "http://localhost:5173,http://localhost:3000"

    # External API keys
    google_safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""
    phishtank_api_key: str = ""
    urlhaus_api_key: str = ""

    # Rate limiting
    rate_limit_per_minute: int = 30

    # Scanning limits
    max_response_size_bytes: int = 5 * 1024 * 1024  # 5 MB
    scan_timeout_seconds: int = 30
    max_redirects: int = 5

    # JWT
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 1440  # 24 hours

    # Redis / Celery (optional)
    redis_url: str = "redis://localhost:6379/0"

    # Admin bootstrap
    admin_email: str = "admin@hackmetrix.local"
    admin_password: str = "changeme"

    # ------------------------------------------------------------------ #
    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def google_safe_browsing_configured(self) -> bool:
        return bool(self.google_safe_browsing_api_key)

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.virustotal_api_key)

    @property
    def phishtank_configured(self) -> bool:
        return bool(self.phishtank_api_key)

    @property
    def urlhaus_configured(self) -> bool:
        return bool(self.urlhaus_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
