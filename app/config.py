"""
SecOps AI Assistant — Application Configuration

Centralized configuration management using Pydantic Settings.
Loads from environment variables and .env files.
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class LLMProvider(str, Enum):
    OPENAI = "openai"
    GEMINI = "gemini"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- LLM Configuration ---
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", alias="OPENAI_MODEL")
    google_api_key: Optional[str] = Field(default=None, alias="GOOGLE_API_KEY")
    google_model: str = Field(default="gemini-2.0-flash", alias="GOOGLE_MODEL")
    llm_primary_provider: LLMProvider = Field(
        default=LLMProvider.OPENAI, alias="LLM_PRIMARY_PROVIDER"
    )

    # --- Enrichment ---
    virustotal_api_key: Optional[str] = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, alias="ABUSEIPDB_API_KEY")
    shodan_api_key: Optional[str] = Field(default=None, alias="SHODAN_API_KEY")
    enrichment_timeout_seconds: int = Field(default=5, alias="ENRICHMENT_TIMEOUT_SECONDS")
    enrichment_cache_ttl_seconds: int = Field(default=3600, alias="ENRICHMENT_CACHE_TTL_SECONDS")

    # --- Application ---
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_log_level: str = Field(default="INFO", alias="APP_LOG_LEVEL")
    database_path: str = Field(default="data/secops.db", alias="DATABASE_PATH")

    # --- Rate Limiting ---
    llm_max_concurrent: int = Field(default=3, alias="LLM_MAX_CONCURRENT")
    llm_retry_attempts: int = Field(default=3, alias="LLM_RETRY_ATTEMPTS")
    llm_retry_backoff_seconds: float = Field(default=2.0, alias="LLM_RETRY_BACKOFF_SECONDS")

    # --- Security ---
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000",
        alias="CORS_ORIGINS",
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "populate_by_name": True,
    }

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def database_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.database_path}"

    @property
    def is_demo_mode(self) -> bool:
        """True if no LLM API keys are configured."""
        return not self.openai_api_key and not self.google_api_key

    @property
    def has_openai(self) -> bool:
        return bool(self.openai_api_key)

    @property
    def has_gemini(self) -> bool:
        return bool(self.google_api_key)

    @property
    def active_provider(self) -> LLMProvider | None:
        """Determine which LLM provider to use based on config and availability."""
        if self.is_demo_mode:
            return None

        # Prefer the configured primary
        if self.llm_primary_provider == LLMProvider.OPENAI and self.has_openai:
            return LLMProvider.OPENAI
        if self.llm_primary_provider == LLMProvider.GEMINI and self.has_gemini:
            return LLMProvider.GEMINI

        # Fallback to whatever is available
        if self.has_openai:
            return LLMProvider.OPENAI
        if self.has_gemini:
            return LLMProvider.GEMINI

        return None

    @property
    def fallback_provider(self) -> LLMProvider | None:
        """Get the fallback provider (opposite of active)."""
        active = self.active_provider
        if active == LLMProvider.OPENAI and self.has_gemini:
            return LLMProvider.GEMINI
        if active == LLMProvider.GEMINI and self.has_openai:
            return LLMProvider.OPENAI
        return None

    @property
    def project_root(self) -> Path:
        return Path(__file__).parent.parent

    @property
    def db_path(self) -> Path:
        path = self.project_root / self.database_path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings."""
    return Settings()
