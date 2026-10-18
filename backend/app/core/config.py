import os
from pathlib import Path
from typing import List, Optional

from pydantic import AnyUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_env_file() -> str:
    """Locate the .env file in CWD or parent directories."""
    for candidate in [Path(".env"), Path("../.env")]:
        if candidate.exists():
            return str(candidate)
    return ".env"


class Settings(BaseSettings):
    """Application configuration loaded from environment variables.

    The class uses pydantic-settings to provide type‑checked settings with
    defaults suitable for development. Production deployments must provide the
    required variables, otherwise the application will fail to start.
    """

    # General
    ENVIRONMENT: str = Field("development")
    DEBUG: bool = Field(False)

    # Database — stored as str to support postgresql+asyncpg:// without
    # Pydantic DSN validation issues.
    DATABASE_URL: str = Field(...)

    # JWT
    JWT_SECRET: str = Field(...)
    JWT_ALGORITHM: str = Field("HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(30)

    # CORS
    CORS_ORIGINS: List[str] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )

    # LLM Provider (mock for now)
    LLM_PROVIDER: str = Field("mock")
    LLM_MODEL: Optional[str] = Field(None)
    GEMINI_API_KEY: Optional[str] = Field(None)

    model_config = SettingsConfigDict(
        env_file=_find_env_file(),
        env_file_encoding="utf-8",
        extra="ignore",
        # Do not JSON-decode complex fields (e.g. CORS_ORIGINS as a
        # comma-separated string) — the validators below handle parsing.
        enable_decoding=False,
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def split_origins(cls, v):
        """Allow a comma‑separated string for convenience."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

# Instantiate a single settings object for the application.
settings = Settings()
