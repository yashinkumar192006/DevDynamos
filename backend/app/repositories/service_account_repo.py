"""Service-account repository."""

from datetime import datetime, timezone

from sqlalchemy import select

from app.models import ServiceAccount
from .base import BaseRepository


class ServiceAccountRepository(BaseRepository[ServiceAccount]):
    model = ServiceAccount

    async def get_by_name(self, name: str) -> ServiceAccount | None:
        stmt = select(ServiceAccount).where(ServiceAccount.name == name)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_key_hash(self, hashed_key: str) -> ServiceAccount | None:
        stmt = select(ServiceAccount).where(ServiceAccount.hashed_key == hashed_key)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def touch_last_used(self, account: ServiceAccount) -> None:
        """Record that the account authenticated a request just now."""
        account.last_used_at = datetime.now(timezone.utc)
        await self.session.flush()
