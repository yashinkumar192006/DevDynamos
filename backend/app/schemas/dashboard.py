"""Schemas for the dashboard overview API (docs/api-design.md §4.10).

Every metric is derived exclusively from recorded audit events and live
configuration, scoped with the same visibility rules as the audit trail
APIs. If the trail contains no data the summary is zeros — the UI is
responsible for rendering an explicit empty state; nothing is fabricated
and no synthetic events are ever created for display purposes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.audit import AuditEventSummary


class DashboardSummary(BaseModel):
    """Decision counts over the requested window."""

    window_days: int
    total_requests: int = 0
    #: Keyed by overall decision: ALLOW / PARTIAL_ALLOW / BLOCK /
    #: ESCALATION_NEEDED. Only decisions actually recorded are counted.
    decisions: dict[str, int] = Field(default_factory=dict)
    requests_with_transformations: int = 0
    model_invocations: int = 0
    guard_triggered: int = 0
    mosaic_warnings: int = 0


class DashboardDailyPoint(BaseModel):
    """One day of the decision series (chart data)."""

    date: str  # YYYY-MM-DD (UTC)
    total: int = 0
    allow: int = 0
    partial_allow: int = 0
    block: int = 0
    escalation: int = 0


class DashboardPolicyStats(BaseModel):
    """Live policy configuration stats."""

    active_policies: int = 0
    most_triggered_policy: str | None = None


class DashboardHealth(BaseModel):
    """Live provider health — same safe shapes as /system/status."""

    database: str
    database_latency_ms: float | None = None
    llm: dict[str, Any] = Field(default_factory=dict)
    classifier: dict[str, Any] = Field(default_factory=dict)


class DashboardOverview(BaseModel):
    """Dashboard payload for one visibility scope."""

    #: "full" (admin), "privacy_trail" (compliance roles), or "own".
    scope: str
    window_days: int
    summary: DashboardSummary
    daily: list[DashboardDailyPoint]
    recent_decisions: list[AuditEventSummary]
    policy_stats: DashboardPolicyStats
    health: DashboardHealth
    timestamp: datetime


__all__ = [
    "DashboardSummary",
    "DashboardDailyPoint",
    "DashboardPolicyStats",
    "DashboardHealth",
    "DashboardOverview",
]
