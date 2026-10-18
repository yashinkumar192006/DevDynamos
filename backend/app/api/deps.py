"""FastAPI dependencies for authentication and authorization.

Route handlers never construct identities themselves: they depend on the
principal resolved here, which is always derived from a validated
credential (bearer JWT or service API key) plus trusted database state.

Request headers such as ``X-User-Id``, ``X-Role``, or ``X-Is-Admin`` are
deliberately **ignored** — an arbitrary user id in a header is never
treated as identity evidence. User identity, agent identity, task purpose,
and target resource remain distinct concepts and are validated separately.
"""

from fastapi import Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.exceptions import AuthenticationError, AuthorizationError
from app.services import AuthService, AuthorizationService, Principal

#: Parses ``Authorization: Bearer <token>``. ``auto_error=False`` lets us
#: emit the project's uniform 401 response instead of Starlette's default.
_bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="JWT",
    description="Access token obtained from POST /api/v1/auth/login",
)


async def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    x_api_key: str | None = Header(
        default=None,
        alias="X-API-Key",
        description="Service-account API key (AI agents / services only)",
    ),
    db: AsyncSession = Depends(get_db),
) -> Principal:
    """Resolve the caller's verified identity from a JWT or a service API key.

    Exactly one credential form may be presented per request.
    """
    auth = AuthService(db)
    if x_api_key:
        if credentials is not None:
            raise AuthenticationError(
                "Provide either a bearer token or an API key, not both"
            )
        return await auth.principal_from_api_key(x_api_key)
    if credentials is None:
        raise AuthenticationError("Not authenticated")
    if credentials.scheme.lower() != "bearer":
        raise AuthenticationError("Unsupported authentication scheme")
    return await auth.principal_from_token(credentials.credentials)


async def get_current_user(
    principal: Principal = Depends(get_current_principal),
) -> Principal:
    """Require a human user principal (JWT-based).

    Service accounts get 403 — they are authenticated but this class of
    endpoint is deliberately user-only (e.g. profile, self-service).
    """
    if principal.kind != "user":
        raise AuthorizationError("This endpoint requires a user account")
    return principal


def require_roles(*role_names: str):
    """Dependency factory: allow only the listed roles.

    Role names are matched against roles resolved from the database for
    user principals. Service principals must instead hold an explicit
    ``role:<name>`` scope (or ``*``). Roles are example definitions from
    the seed data — authorization rests on the permissions/scopes behind
    them, and this gate exists for coarser admin-style boundaries.
    """

    async def dependency(
        principal: Principal = Depends(get_current_principal),
    ) -> Principal:
        if principal.kind == "user":
            if principal.roles.intersection(role_names):
                return principal
        else:
            if "*" in principal.scopes or any(
                f"role:{name}" in principal.scopes for name in role_names
            ):
                return principal
        raise AuthorizationError(
            "Requires one of the following roles: " + ", ".join(role_names)
        )

    return dependency


def require_permission(resource: str, action: str):
    """Dependency factory: allow only identities with a matching permission/scope.

    Uses the same :class:`AuthorizationService` primitives available to the
    gateway and SDK, keeping every enforcement point consistent.
    """

    async def dependency(
        principal: Principal = Depends(get_current_principal),
        db: AsyncSession = Depends(get_db),
    ) -> Principal:
        decision = await AuthorizationService(db).check_resource_access(
            principal, resource, action
        )
        if not decision.allowed:
            raise AuthorizationError(
                f"Not permitted to {action} {resource} ({decision.reason_code})"
            )
        return principal

    return dependency
