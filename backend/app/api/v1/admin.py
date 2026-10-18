"""Administrative endpoints.

These endpoints demonstrate server-side role enforcement end-to-end: the
``admin`` gate is evaluated from the caller's verified identity and the
trusted database — never from request-supplied fields.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_roles
from app.core.database import get_db
from app.repositories import UserRepository
from app.schemas.auth import AdminUserView
from app.services import Principal

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get(
    "/users",
    response_model=list[AdminUserView],
    summary="List all users (admin role required)",
)
async def list_users(
    _principal: Principal = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> list[AdminUserView]:
    """Return every user with their current role assignments."""
    user_repo = UserRepository(db)
    users = await user_repo.get_all(limit=200)
    result: list[AdminUserView] = []
    for user in sorted(users, key=lambda u: u.username):
        roles = await user_repo.get_user_roles(user.id)
        result.append(
            AdminUserView(
                id=user.id,
                username=user.username,
                email=user.email,
                full_name=user.full_name,
                department=user.department,
                is_active=user.is_active,
                roles=sorted(r.name for r in roles),
            )
        )
    return result
