"""Privacy decision and AI interaction repositories."""

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    PrivacyDecision,
    PrivacyRequest,
    RequestContext,
    TransformationEvent,
    AIInteraction,
    OutputInspection,
    DecisionOutcome,
    RequestStatus,
)
from .base import BaseRepository


class PrivacyRequestRepository(BaseRepository[PrivacyRequest]):
    model = PrivacyRequest

    async def get_with_context(self, request_id: str) -> PrivacyRequest | None:
        stmt = (
            select(PrivacyRequest)
            .where(PrivacyRequest.id == request_id)
            .options(
                selectinload(PrivacyRequest.context),
                selectinload(PrivacyRequest.decision),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_requester(
        self, requester_id: str, *, status: RequestStatus | None = None, limit: int = 50
    ) -> Sequence[PrivacyRequest]:
        stmt = (
            select(PrivacyRequest)
            .where(PrivacyRequest.requester_id == requester_id)
            .order_by(PrivacyRequest.created_at.desc())
            .limit(limit)
        )
        if status is not None:
            stmt = stmt.where(PrivacyRequest.status == status)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_pending(self, *, limit: int = 100) -> Sequence[PrivacyRequest]:
        stmt = (
            select(PrivacyRequest)
            .where(PrivacyRequest.status == RequestStatus.PENDING)
            .order_by(PrivacyRequest.created_at)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()


class PrivacyDecisionRepository(BaseRepository[PrivacyDecision]):
    model = PrivacyDecision

    async def get_with_transformations(self, decision_id: str) -> PrivacyDecision | None:
        stmt = (
            select(PrivacyDecision)
            .where(PrivacyDecision.id == decision_id)
            .options(selectinload(PrivacyDecision.transformations))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_outcome(
        self, outcome: DecisionOutcome, *, limit: int = 50
    ) -> Sequence[PrivacyDecision]:
        stmt = (
            select(PrivacyDecision)
            .where(PrivacyDecision.outcome == outcome)
            .order_by(PrivacyDecision.decided_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()


class AIInteractionRepository(BaseRepository[AIInteraction]):
    model = AIInteraction

    async def get_by_session(self, session_id: str) -> Sequence[AIInteraction]:
        stmt = (
            select(AIInteraction)
            .where(AIInteraction.session_id == session_id)
            .order_by(AIInteraction.created_at)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_with_inspections(self, interaction_id: str) -> AIInteraction | None:
        stmt = (
            select(AIInteraction)
            .where(AIInteraction.id == interaction_id)
            .options(selectinload(AIInteraction.output_inspections))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_user(self, user_id: str, *, limit: int = 50) -> Sequence[AIInteraction]:
        stmt = (
            select(AIInteraction)
            .where(AIInteraction.user_id == user_id)
            .order_by(AIInteraction.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
