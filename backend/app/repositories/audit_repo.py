"""Audit event repository."""

from datetime import datetime
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditEvent, AuditAction
from .base import BaseRepository


class AuditRepository(BaseRepository[AuditEvent]):
    model = AuditEvent

    async def get_by_actor(self, actor_id: str, *, limit: int = 50) -> Sequence[AuditEvent]:
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.actor_id == actor_id)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_by_action(self, action: AuditAction, *, limit: int = 50) -> Sequence[AuditEvent]:
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.action == action)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_by_resource(self, resource: str, *, limit: int = 50) -> Sequence[AuditEvent]:
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.resource == resource)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_recent(self, *, limit: int = 100) -> Sequence[AuditEvent]:
        stmt = (
            select(AuditEvent)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_in_range(
        self,
        start: datetime,
        end: datetime,
        *,
        action: AuditAction | None = None,
        limit: int = 500,
    ) -> Sequence[AuditEvent]:
        """Return audit events within a time range, optionally filtered by action."""
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.created_at >= start, AuditEvent.created_at <= end)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
        )
        if action is not None:
            stmt = stmt.where(AuditEvent.action == action)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def log_event(
        self,
        *,
        actor_id: str | None,
        action: AuditAction,
        resource: str | None = None,
        resource_id: str | None = None,
        outcome: str = "success",
        detail: str | None = None,
        ip_address: str | None = None,
        session_id: str | None = None,
    ) -> AuditEvent:
        """Create and flush a new audit event."""
        event = AuditEvent(
            actor_id=actor_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            outcome=outcome,
            detail=detail,
            ip_address=ip_address,
            session_id=session_id,
        )
        self.session.add(event)
        await self.session.flush()
        return event
