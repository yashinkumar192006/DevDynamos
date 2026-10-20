"""Read-only policy catalogue (docs/api-design.md §4.7).

Any authenticated principal may read the *active* policies — they describe
the rules in effect and are the same rule summaries shipped in the project
documentation. Inactive / superseded versions are administrative history
and are visible only to administrators (user role ``admin``, or a service
account holding ``*`` / ``role:admin`` / policy-admin scopes).

The projection is allowlisted: nothing outside
:class:`app.schemas.policies.PolicyItem` can leak through this endpoint.
"""

from __future__ import annotations

import json
from typing import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthorizationError
from app.models import PrivacyPolicy
from app.repositories import PrivacyPolicyRepository
from app.schemas.common import Pagination
from app.schemas.policies import PolicyItem, PolicyListResponse
from app.services.auth_service import Principal
from app.services.policy_admin import PolicyAdminService

#: Defensive cap: the policy store is versioned configuration, not data.
_MAX_ROWS = 2000


def _json_list(raw: str | None) -> list[str]:
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _pattern_matches_resource(pattern: str, resource: str) -> bool:
    """Same matching semantics as the policy engine's resource patterns."""
    if pattern == resource:
        return True
    return pattern.endswith("*") and resource.startswith(pattern[:-1])


def _to_item(policy: PrivacyPolicy) -> PolicyItem:
    return PolicyItem(
        id=policy.id,
        name=policy.name,
        version=policy.version,
        description=policy.description,
        policy_text=policy.policy_text,
        resource_pattern=policy.resource_pattern,
        required_role=policy.required_role,
        min_sensitivity=policy.min_sensitivity,
        allowed_purposes=_json_list(policy.allowed_purposes),
        allowed_actions=_json_list(policy.allowed_actions),
        action=policy.action,
        priority=policy.priority,
        status=policy.status.value,
        is_active=policy.status.value == "active",
        effective_from=policy.effective_from,
        effective_until=policy.effective_until,
    )


class PolicyCatalogService:
    """Read-side catalogue over the versioned policy store."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = PrivacyPolicyRepository(session)

    async def list_policies(
        self,
        principal: Principal,
        *,
        limit: int = 20,
        offset: int = 0,
        resource: str | None = None,
        role: str | None = None,
        include_inactive: bool = False,
    ) -> PolicyListResponse:
        #: Single definition of "administrator" shared with policy admin
        #: (user role ``admin`` / service ``*``-class scopes).
        is_admin = PolicyAdminService._is_admin(principal)
        if include_inactive and not is_admin:
            raise AuthorizationError(
                "Reading inactive policy versions requires an administrator identity"
            )

        rows: Sequence[PrivacyPolicy]
        if include_inactive:
            rows = await PolicyAdminService(self.session).list_policies(
                principal, include_inactive=True
            )
        else:
            rows = await self.repo.get_active_policies()

        filtered = [
            policy
            for policy in rows
            if (
                resource is None
                or _pattern_matches_resource(policy.resource_pattern, resource)
            )
            and (role is None or policy.required_role == role)
        ][:_MAX_ROWS]
        filtered.sort(key=lambda policy: (policy.name, -policy.version))

        total = len(filtered)
        window = filtered[offset : offset + limit]
        return PolicyListResponse(
            items=[_to_item(policy) for policy in window],
            pagination=Pagination(
                total=total,
                limit=limit,
                offset=offset,
                has_more=offset + len(window) < total,
            ),
        )


__all__ = ["PolicyCatalogService"]
