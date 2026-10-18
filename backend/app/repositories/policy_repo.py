"""Privacy policy repository."""

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import PrivacyPolicy, PolicyStatus
from .base import BaseRepository


class PrivacyPolicyRepository(BaseRepository[PrivacyPolicy]):
    model = PrivacyPolicy

    async def get_active_policies(self) -> Sequence[PrivacyPolicy]:
        """Return all currently active policies."""
        stmt = (
            select(PrivacyPolicy)
            .where(PrivacyPolicy.status == PolicyStatus.ACTIVE)
            .order_by(PrivacyPolicy.name, PrivacyPolicy.version.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_policies_for_resource(self, resource: str) -> Sequence[PrivacyPolicy]:
        """Return active policies that match the given resource.

        Supports exact match and wildcard patterns (e.g. ``customer_*``).
        """
        stmt = (
            select(PrivacyPolicy)
            .where(PrivacyPolicy.status == PolicyStatus.ACTIVE)
            .order_by(PrivacyPolicy.version.desc())
        )
        result = await self.session.execute(stmt)
        all_active = result.scalars().all()

        matched: list[PrivacyPolicy] = []
        for policy in all_active:
            pattern = policy.resource_pattern
            if pattern == resource:
                matched.append(policy)
            elif pattern.endswith("*") and resource.startswith(pattern[:-1]):
                matched.append(policy)
        return matched

    async def get_latest_version(self, name: str) -> PrivacyPolicy | None:
        """Return the highest-version policy with the given name."""
        stmt = (
            select(PrivacyPolicy)
            .where(PrivacyPolicy.name == name)
            .order_by(PrivacyPolicy.version.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_policy_history(self, name: str) -> Sequence[PrivacyPolicy]:
        """Return all versions of a named policy, newest first."""
        stmt = (
            select(PrivacyPolicy)
            .where(PrivacyPolicy.name == name)
            .order_by(PrivacyPolicy.version.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
