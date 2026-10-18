"""User and identity-related repositories."""

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import User, Role, Permission, UserRole
from .base import BaseRepository


class UserRepository(BaseRepository[User]):
    model = User

    async def get_by_username(self, username: str) -> User | None:
        stmt = select(User).where(User.username == username)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_employee_id(self, employee_id: str) -> User | None:
        stmt = select(User).where(User.employee_id == employee_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_with_roles(self, user_id: str) -> User | None:
        """Load user with eagerly-loaded roles and their permissions."""
        stmt = (
            select(User)
            .where(User.id == user_id)
            .options(
                selectinload(User.user_roles)
                .selectinload(UserRole.role)
                .selectinload(Role.permissions)
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_user_roles(self, user_id: str) -> Sequence[Role]:
        """Return all roles assigned to a user."""
        stmt = (
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_user_permissions(self, user_id: str) -> Sequence[Permission]:
        """Return all permissions for a user (flattened across roles)."""
        stmt = (
            select(Permission)
            .join(Role, Permission.role_id == Role.id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def has_permission(self, user_id: str, resource: str, action: str) -> bool:
        """Check if a user has a specific permission (including wildcard)."""
        perms = await self.get_user_permissions(user_id)
        for p in perms:
            if (p.resource == "*" or p.resource == resource) and (p.action == "*" or p.action == action):
                return True
        return False

    async def get_active_users(self) -> Sequence[User]:
        stmt = select(User).where(User.is_active.is_(True))
        result = await self.session.execute(stmt)
        return result.scalars().all()


class RoleRepository(BaseRepository[Role]):
    model = Role

    async def get_by_name(self, name: str) -> Role | None:
        stmt = select(Role).where(Role.name == name)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_with_permissions(self, role_id: str) -> Role | None:
        stmt = (
            select(Role)
            .where(Role.id == role_id)
            .options(selectinload(Role.permissions))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
