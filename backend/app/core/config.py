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

    # Sensitive-data classification
    # NLP (Presidio + spaCy) is an *additional signal*: when the model or
    # the libraries are unavailable the classifier degrades gracefully to
    # deterministic rules only — it never fails open.
    CLASSIFIER_NLP_ENABLED: bool = Field(True)
    CLASSIFIER_SPACY_MODEL: str = Field("en_core_web_sm")
    CLASSIFIER_LANGUAGE: str = Field("en")
    #: Minimum Presidio score for a detection to be reported.
    CLASSIFIER_NLP_SCORE_THRESHOLD: float = Field(0.5, ge=0.0, le=1.0)
    #: Reported detections scoring below this are still returned, but the
    #: conservative uncertainty policy is applied (escalate/block).
    CLASSIFIER_UNCERTAINTY_THRESHOLD: float = Field(0.75, ge=0.0, le=1.0)
    #: Sensitivity applied to fields with no annotation and no rule match.
    CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY: str = Field("high")
    #: Handling recommended when classification is uncertain.
    CLASSIFIER_UNCERTAIN_HANDLING: str = Field("escalate")
    #: How sensitivity levels are labelled in outputs: "standard"
    #: (low/medium/high/restricted) or "business"
    #: (public/internal/confidential/restricted).
    SENSITIVITY_LABEL_SCHEME: str = Field("business")

    # ── Deterministic policy engine ─────────────────────────────────
    # All of these are hard, deterministic controls: nothing in the
    # policy engine consults an LLM, and permissive policies can never
    # override the mandatory floors below.
    #: Minimum group size for AGGREGATE decisions (k-anonymity).
    POLICY_MIN_GROUP_SIZE: int = Field(5, ge=1)
    #: How many identical aggregate requests one session may make in the
    #: window before the repeated-query control escalates (MOSAIC_RISK).
    POLICY_AGGREGATE_REPEAT_LIMIT: int = Field(5, ge=1)
    #: Sliding window (seconds) for the repeated-aggregate control.
    POLICY_AGGREGATE_WINDOW_SECONDS: int = Field(300, ge=1)
    #: PII categories that are masked whenever a policy would disclose
    #: them raw to *another* subject (third-party disclosure floor).
    POLICY_MANDATORY_MASK_CATEGORIES: str = Field(
        "phone,email,bank_account,credit_card"
    )
    #: PII categories that are generalized on third-party disclosure.
    POLICY_MANDATORY_GENERALIZE_CATEGORIES: str = Field("address,date_of_birth")
    #: PII categories that are always blocked, regardless of policy.
    POLICY_MANDATORY_BLOCK_CATEGORIES: str = Field("ssn")
    #: Role inheritance used when matching a policy's required_role,
    #: e.g. "hr_manager:hr_staff" means an hr_manager satisfies an
    #: hr_staff requirement. Comma-separated "holder:inherited" pairs.
    POLICY_ROLE_HIERARCHY: str = Field(
        "hr_manager:hr_staff,sales_manager:sales_staff,support_lead:support_agent"
    )
    #: Secret used for deterministic token generation. Falls back to
    #: JWT_SECRET when unset.
    POLICY_TOKEN_SECRET: Optional[str] = Field(None)
    #: Token lifetime (minutes) in the protected server-side vault.
    POLICY_TOKEN_TTL_MINUTES: int = Field(60, ge=1)

    # ── LLM adapter & output privacy guard (Prompt 8) ───────────────
    #: Built-in provider selection: "mock" (default, offline) or "gemini"
    #: (optional, requires GEMINI_API_KEY server-side). Any other value is
    #: rejected with a clear UnsupportedProviderError at request time.
    LLM_PROVIDER: str = Field("mock")
    #: Optional model override (e.g. "gemini-2.5-flash").
    LLM_MODEL: Optional[str] = Field(None)
    #: Server-side Gemini API key. NEVER returned by any API or logged.
    GEMINI_API_KEY: Optional[str] = Field(None)
    #: Canned deterministic mock response (testing/demo of leaky providers).
    LLM_MOCK_RESPONSE: Optional[str] = Field(None)
    #: Provider call timeout (seconds) and transient retry count.
    LLM_TIMEOUT_SECONDS: float = Field(20.0, ge=1)
    LLM_MAX_RETRIES: int = Field(1, ge=0, le=5)
    #: Output guard toggle and enforcement mode:
    #: "redact" (sanitize), "reject" (withhold), "escalate" (withhold + review).
    LLM_OUTPUT_GUARD_ENABLED: bool = Field(True)
    LLM_OUTPUT_GUARD_MODE: str = Field("redact")
    #: Maximum output length the guard scans; anything longer is truncated
    #: (the unscanned tail is never returned).
    LLM_MAX_OUTPUT_CHARS: int = Field(100_000, ge=1_000)

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

    @field_validator("CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY", mode="before")
    @classmethod
    def validate_unknown_sensitivity(cls, v):
        """Fail fast on an unusable conservative-default sensitivity."""
        allowed = {"low", "medium", "high", "restricted", "public", "internal", "confidential"}
        if isinstance(v, str) and v.strip().lower() in allowed:
            return v.strip().lower()
        raise ValueError(
            f"CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY must be one of {sorted(allowed)}"
        )

    @field_validator("CLASSIFIER_UNCERTAIN_HANDLING", mode="before")
    @classmethod
    def validate_uncertain_handling(cls, v):
        """Fail fast on an unknown conservative handling."""
        allowed = {
            "allow", "tokenize", "mask", "generalize",
            "aggregate", "escalate", "block",
        }
        if isinstance(v, str) and v.strip().lower() in allowed:
            return v.strip().lower()
        raise ValueError(
            f"CLASSIFIER_UNCERTAIN_HANDLING must be one of {sorted(allowed)}"
        )

    @field_validator("SENSITIVITY_LABEL_SCHEME", mode="before")
    @classmethod
    def validate_label_scheme(cls, v):
        allowed = {"standard", "business"}
        if isinstance(v, str) and v.strip().lower() in allowed:
            return v.strip().lower()
        raise ValueError(f"SENSITIVITY_LABEL_SCHEME must be one of {sorted(allowed)}")

    @field_validator("LLM_OUTPUT_GUARD_MODE", mode="before")
    @classmethod
    def validate_guard_mode(cls, v):
        allowed = {"redact", "reject", "escalate"}
        if isinstance(v, str) and v.strip().lower() in allowed:
            return v.strip().lower()
        raise ValueError(
            f"LLM_OUTPUT_GUARD_MODE must be one of {sorted(allowed)}"
        )

# Instantiate a single settings object for the application.
settings = Settings()
