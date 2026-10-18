"""Password hashing, JWT handling, and API-key utilities.

Security invariants enforced here:

* Plaintext passwords are never stored — bcrypt hashes only.
* Plaintext API keys are never stored — SHA-256 hashes only.
* JWTs are signed with ``JWT_SECRET`` (environment variable) and carry
  **no authorization data**. Roles/permissions are always re-resolved from
  the trusted database on every request (see ``app.services.auth_service``).
* Authentication secrets are never logged.

``bcrypt`` is used directly — passlib 1.7.4 is incompatible with
bcrypt >= 5.0, so it is deliberately not used here.
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings
from app.core.exceptions import AuthenticationError

#: bcrypt processes at most 72 bytes; longer inputs are truncated.
_BCRYPT_MAX_BYTES = 72

#: Prefix for service-account API keys, so credentials are recognisable
#: in configuration and can never be confused with JWTs.
API_KEY_PREFIX = "csk_"


# ──────────────────────────────────────────────────────────────────────
# Passwords
# ──────────────────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    """Return a bcrypt hash of ``password`` (never the plaintext)."""
    secret = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(secret, bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    """Check ``password`` against a bcrypt hash; never raises."""
    try:
        secret = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
        return bcrypt.checkpw(secret, hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


# ──────────────────────────────────────────────────────────────────────
# JWT access tokens
# ──────────────────────────────────────────────────────────────────────


def create_access_token(
    subject: str,
    username: str,
    expires_minutes: int | None = None,
) -> tuple[str, int]:
    """Create a signed access token for a user.

    Returns ``(token, expires_in_seconds)``.

    The payload intentionally contains identity claims only (``sub``,
    ``username``, ``jti``, ``iat``, ``exp``, ``typ``). It never contains
    roles or permissions: those are resolved from the database on every
    request, so revocation and role changes take effect immediately.
    """
    minutes = (
        settings.ACCESS_TOKEN_EXPIRE_MINUTES
        if expires_minutes is None
        else expires_minutes
    )
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=minutes)
    payload = {
        "sub": subject,
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, max(minutes * 60, 0)


def decode_access_token(token: str) -> dict:
    """Validate a token's signature and expiry; return its claims.

    Raises :class:`AuthenticationError` (→ HTTP 401) for any invalid,
    tampered, or expired token — the specific failure is deliberately not
    disclosed to the caller.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError as exc:
        raise AuthenticationError("Could not validate credentials") from exc
    if payload.get("typ") != "access" or not payload.get("sub"):
        raise AuthenticationError("Could not validate credentials")
    return payload


# ──────────────────────────────────────────────────────────────────────
# Service-account API keys
# ──────────────────────────────────────────────────────────────────────


def generate_api_key() -> tuple[str, str, str]:
    """Create an API key for a service account.

    Returns ``(plaintext, sha256_hex, display_prefix)``. Only the hash and
    the short display prefix may be persisted; the plaintext key is shown
    to the operator exactly once, at creation time.
    """
    key = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return key, hash_api_key(key), key[:12]


def hash_api_key(key: str) -> str:
    """SHA-256 of an API key.

    API keys are high-entropy random values (not user-chosen passwords),
    so a fast one-way hash is appropriate for storage and lookup.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
