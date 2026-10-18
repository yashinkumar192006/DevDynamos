"""Authentication service: credential verification and trusted identity resolution.

Separation of concerns (Prompt 5, section C):

* **Authentication** (this module) answers *who is the requester* by
  verifying a password or an API key against trusted database state.
* **Authorization** (``app.services.authorization``) answers *what may that
  identity do*. It is always a separate, explicit step.

Three concepts stay distinct and are never conflated:

* **Identity** — a :class:`Principal` resolved from a validated credential.
* **Purpose** — supplied per request and validated separately by
  authorization (never used to establish identity).
* **Target resource** — an argument to authorization checks, never part of
  the identity.

Nothing in this module trusts client-supplied headers such as ``X-User-Id``,
``X-Role``, or ``is_admin``; only the validated JWT/API-key credential and
the trusted database are consulted.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_api_key,
    hash_password,
    verify_password,
)
from app.models import ServiceAccount, User
from app.repositories import ServiceAccountRepository, UserRepository

#: Compared against when a username does not exist, so response timing does
#: not reveal whether an account exists.
_DUMMY_HASH = hash_password("contextshield-dummy-password")


@dataclass(frozen=True)
class Principal:
    """Verified identity for the duration of a single request.

    ``roles`` is populated for human users (re-resolved from the database
    on every request — never read from the token). ``scopes`` is populated
    for service accounts. Neither is ever accepted from client input.
    """

    id: str
    kind: str  # "user" | "service"
    display_name: str
    username: str | None = None
    roles: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    # ORM objects for convenience; excluded from equality/repr.
    user: User | None = field(default=None, repr=False, compare=False)
    service_account: ServiceAccount | None = field(
        default=None, repr=False, compare=False
    )


class AuthService:
    """Credential verification and principal resolution."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.users = UserRepository(session)
        self.service_accounts = ServiceAccountRepository(session)

    # ── User authentication ─────────────────────────────────────────

    async def authenticate_user(self, username: str, password: str) -> User | None:
        """Return the user iff the password matches and the account is active.

        Returns ``None`` for unknown usernames, wrong passwords, and
        inactive accounts alike so callers can emit one generic failure
        message without revealing which usernames exist.
        """
        user = await self.users.get_by_username(username)
        if user is None:
            # Constant-ish timing: verify against a dummy hash.
            verify_password(password, _DUMMY_HASH)
            return None
        if not verify_password(password, user.hashed_password):
            return None
        if not user.is_active:
            return None
        return user

    def create_token(self, user: User) -> tuple[str, int]:
        """Issue an access token for a verified user.

        Returns ``(token, expires_in_seconds)``.
        """
        return create_access_token(subject=user.id, username=user.username)

    async def principal_from_token(self, token: str) -> Principal:
        """Validate a JWT and resolve the *current* user state from the database.

        Roles are re-resolved from the database on every request — they are
        never read from the token — so role changes and deactivations take
        effect immediately, and a forged/stale token can never grant a role
        the user does not currently hold.
        """
        claims = decode_access_token(token)
        user = await self.users.get_with_roles(claims["sub"])
        if user is None:
            raise AuthenticationError("Could not validate credentials")
        if not user.is_active:
            raise AuthenticationError("User account is inactive")
        roles = frozenset(
            ur.role.name for ur in user.user_roles if ur.role is not None
        )
        return Principal(
            id=user.id,
            kind="user",
            display_name=user.full_name,
            username=user.username,
            roles=roles,
            user=user,
        )

    # ── Service / agent authentication ──────────────────────────────

    async def principal_from_api_key(self, api_key: str) -> Principal:
        """Validate a service-account API key and return a service principal."""
        account = await self.service_accounts.get_by_key_hash(hash_api_key(api_key))
        if account is None:
            raise AuthenticationError("Invalid API key")
        if not account.is_active:
            raise AuthenticationError("Service account is inactive")
        if account.expires_at is not None:
            expires = account.expires_at
            if expires.tzinfo is None:  # tolerate naive datetimes from SQLite-era data
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= datetime.now(timezone.utc):
                raise AuthenticationError("Service account key has expired")
        await self.service_accounts.touch_last_used(account)
        return Principal(
            id=account.id,
            kind="service",
            display_name=account.name,
            scopes=frozenset(account.scope_list()),
            service_account=account,
        )
