"""Authentication endpoints: login, profile, logout, and identity introspection.

``POST /login`` verifies credentials and issues a JWT access token.
``GET /me`` returns the authenticated profile (roles/permissions included)
resolved fresh from the database. ``GET /whoami`` echoes the verified
identity behind whichever credential was presented — useful for the SDK,
gateway, and debugging.
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_principal, get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.exceptions import AuthenticationError, RateLimitError
from app.core.rate_limit import login_ip_rate_limiter, login_rate_limiter
from app.models import AuditAction, User
from app.repositories import AuditRepository, UserRepository
from app.schemas.auth import (
    LoginRequest,
    MessageResponse,
    PermissionInfo,
    RoleInfo,
    TokenResponse,
    UserProfile,
    WhoAmIResponse,
)
from app.services import AuthService, Principal

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    """Client address for audit records — taken from the socket, not headers."""
    return request.client.host if request.client else None


async def _build_profile(db: AsyncSession, user: User) -> UserProfile:
    """Build the public profile from trusted database state."""
    user_repo = UserRepository(db)
    roles = await user_repo.get_user_roles(user.id)
    permissions = {
        (p.resource, p.action) for p in await user_repo.get_user_permissions(user.id)
    }
    return UserProfile(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        department=user.department,
        employee_id=user.employee_id,
        is_active=user.is_active,
        roles=[
            RoleInfo(name=r.name, description=r.description)
            for r in sorted(roles, key=lambda r: r.name)
        ],
        permissions=[
            PermissionInfo(resource=resource, action=action)
            for resource, action in sorted(permissions)
        ],
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Exchange credentials for an access token",
)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Verify username/password and issue a JWT access token.

    All credential failures (unknown user, wrong password, inactive
    account) return the same generic 401 response. Repeated failures for
    the same username+address are throttled with ``429`` (failure-only
    sliding window — see ``app/core/rate_limit.py``).
    """
    client_ip = _client_ip(request) or "unknown"
    user_key = f"{payload.username.strip().lower()}|{client_ip}"
    ip_key = f"ip:{client_ip}"
    if settings.AUTH_RATE_LIMIT_ENABLED:
        for limiter, key in (
            (login_rate_limiter, user_key),
            (login_ip_rate_limiter, ip_key),
        ):
            retry_after = limiter.retry_after(key)
            if retry_after is not None:
                raise RateLimitError(retry_after)

    auth = AuthService(db)
    user = await auth.authenticate_user(payload.username, payload.password)
    audit = AuditRepository(db)

    if user is None:
        if settings.AUTH_RATE_LIMIT_ENABLED:
            login_rate_limiter.record_failure(user_key)
            login_ip_rate_limiter.record_failure(ip_key)
        # Record the failed attempt and commit explicitly — raising below
        # makes the request session roll back any pending changes.
        await audit.log_event(
            actor_id=None,
            action=AuditAction.LOGIN,
            resource="auth",
            outcome="failed",
            detail=json.dumps({"username": payload.username}),
            ip_address=_client_ip(request),
        )
        await db.commit()
        raise AuthenticationError("Invalid username or password")

    if settings.AUTH_RATE_LIMIT_ENABLED:
        login_rate_limiter.clear(user_key)

    user.last_login = datetime.now(timezone.utc)
    token, expires_in = auth.create_token(user)
    await audit.log_event(
        actor_id=user.id,
        action=AuditAction.LOGIN,
        resource="auth",
        outcome="success",
        detail=json.dumps({"username": user.username}),
        ip_address=_client_ip(request),
    )
    return TokenResponse(
        access_token=token,
        expires_in=expires_in,
        user=await _build_profile(db, user),
    )


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Current authenticated user profile",
)
async def me(
    principal: Principal = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserProfile:
    """Return the caller's profile with current roles and permissions."""
    assert principal.user is not None  # guaranteed by get_current_user
    return await _build_profile(db, principal.user)


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Sign out (client discards the access token)",
)
async def logout(
    request: Request,
    principal: Principal = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Record the logout in the audit trail.

    Access tokens are stateless; the client is responsible for discarding
    the token. Deactivating the user or waiting for expiry invalidates it
    server-side.
    """
    await AuditRepository(db).log_event(
        actor_id=principal.id,
        action=AuditAction.LOGOUT,
        resource="auth",
        outcome="success",
        detail=json.dumps({"username": principal.username}),
        ip_address=_client_ip(request),
    )
    return MessageResponse(message="Signed out. Discard the access token on the client side.")


@router.get(
    "/whoami",
    response_model=WhoAmIResponse,
    summary="Verified identity behind the current credential",
)
async def whoami(
    principal: Principal = Depends(get_current_principal),
) -> WhoAmIResponse:
    """Return the verified identity — works for both users (JWT) and services (API key)."""
    return WhoAmIResponse(
        kind=principal.kind,
        id=principal.id,
        display_name=principal.display_name,
        username=principal.username,
        roles=sorted(principal.roles),
        scopes=sorted(principal.scopes),
    )
