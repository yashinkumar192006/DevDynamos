"""Audit event repository."""

from datetime import datetime
from typing import Sequence

from sqlalchemy import func, or_, select
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

    @staticmethod
    def _conditions(
        *,
        actor_id: str | None = None,
        actor_kind: str | None = None,
        action: AuditAction | None = None,
        actions_in: Sequence[AuditAction] | None = None,
        resource: str | None = None,
        outcome: str | None = None,
        session_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list:
        """Shared SQL conditions for scoped audit queries."""
        conditions = []
        if actor_id is not None:
            conditions.append(AuditEvent.actor_id == actor_id)
        if actor_kind is not None:
            if actor_kind == "user":
                # Legacy pre-actor-kind rows are user actors.
                conditions.append(
                    or_(
                        AuditEvent.actor_kind == "user",
                        AuditEvent.actor_kind.is_(None),
                    )
                )
            else:
                conditions.append(AuditEvent.actor_kind == actor_kind)
        if action is not None:
            conditions.append(AuditEvent.action == action)
        if actions_in is not None:
            conditions.append(AuditEvent.action.in_(list(actions_in)))
        if resource is not None:
            conditions.append(AuditEvent.resource == resource)
        if outcome is not None:
            conditions.append(AuditEvent.outcome == outcome)
        if session_id is not None:
            conditions.append(AuditEvent.session_id == session_id)
        if start is not None:
            conditions.append(AuditEvent.created_at >= start)
        if end is not None:
            conditions.append(AuditEvent.created_at <= end)
        return conditions

    async def query_events(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        actor_id: str | None = None,
        actor_kind: str | None = None,
        action: AuditAction | None = None,
        actions_in: Sequence[AuditAction] | None = None,
        resource: str | None = None,
        outcome: str | None = None,
        session_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> tuple[Sequence[AuditEvent], int]:
        """Filtered, paginated audit query returning ``(rows, total)``.

        ``actor_kind`` / ``actions_in`` express *visibility scopes* that the
        caller (the audit service) derives from the verified principal and
        applies in SQL — never as post-filtering, so out-of-scope rows are
        never even loaded.
        """
        conditions = self._conditions(
            actor_id=actor_id,
            actor_kind=actor_kind,
            action=action,
            actions_in=actions_in,
            resource=resource,
            outcome=outcome,
            session_id=session_id,
            start=start,
            end=end,
        )

        total_stmt = (
            select(func.count()).select_from(AuditEvent).where(*conditions)
        )
        total = (await self.session.execute(total_stmt)).scalar_one()

        stmt = (
            select(AuditEvent)
            .where(*conditions)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        return rows, int(total)

    async def fetch_window(
        self,
        *,
        start: datetime,
        end: datetime | None = None,
        actor_id: str | None = None,
        actor_kind: str | None = None,
        actions_in: Sequence[AuditAction] | None = None,
        limit: int = 20_000,
    ) -> Sequence[AuditEvent]:
        """All (scoped) events in a time window, newest first.

        Used by aggregation endpoints (e.g. the dashboard) that need the
        full, already-scoped slice rather than one page. The ``limit`` is a
        defensive cap for demo-scale data, not a page size.
        """
        conditions = self._conditions(
            actor_id=actor_id,
            actor_kind=actor_kind,
            actions_in=actions_in,
            start=start,
            end=end,
        )
        stmt = (
            select(AuditEvent)
            .where(*conditions)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def log_event(
        self,
        *,
        actor_id: str | None,
        action: AuditAction,
        actor_kind: str | None = None,
        resource: str | None = None,
        resource_id: str | None = None,
        outcome: str = "success",
        detail: str | None = None,
        ip_address: str | None = None,
        session_id: str | None = None,
    ) -> AuditEvent:
        """Create and flush a new audit event."""

        def _clamp(value: str | None, limit: int) -> str | None:
            if value is None:
                return None
            text = str(value)
            # Column widths are a storage detail: an audit row must be
            # written even when a hostile caller supplies an oversized
            # identifier, so free-text fields are truncated rather than
            # allowed to fail the insert. Reason codes, actions, and
            # decisions are never truncated (they are server-generated and
            # bounded).
            return text[:limit]

        event = AuditEvent(
            actor_id=_clamp(actor_id, 32),
            actor_kind=_clamp(actor_kind, 20),
            action=action,
            resource=_clamp(resource, 200),
            resource_id=_clamp(resource_id, 32),
            outcome=_clamp(outcome, 50),
            detail=detail,
            ip_address=_clamp(ip_address, 45),
            session_id=_clamp(session_id, 64),
        )
        self.session.add(event)
        await self.session.flush()
        return event
