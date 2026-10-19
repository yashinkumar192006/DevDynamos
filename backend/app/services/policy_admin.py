"""Policy administration — versioned policy management with access control.

Only administrators may change the rules the policy engine enforces. A
normal user or an LLM-driven caller has no path into these methods: every
entry point verifies the principal and raises :class:`PolicyAdminDenied`
otherwise. Every successful change is recorded as an ``ADMIN_ACTION``
audit event.

Versioning model (docs/privacy-policies.md §6):

* Policies are immutable per version. An update creates a **new version**
  and marks the previous version ``SUPERSEDED`` — it is retained for the
  audit trail.
* Deactivate / reactivate switches ``status``; reactivating an older
  version is the rollback path.
* The policy engine always evaluates active policies; when several
  versions of a name are somehow active, the highest version wins.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AuditAction,
    PolicyStatus,
    PrivacyPolicy,
    RequestPurpose,
    SensitivityLevel,
)
from app.repositories import AuditRepository, PrivacyPolicyRepository
from app.services.auth_service import Principal
from app.services.authorization import KNOWN_OPERATIONS
from app.services.policy_engine import PolicyAction

logger = logging.getLogger(__name__)


class PolicyAdminDenied(PermissionError):
    """Raised when a principal may not administer policies."""


class PolicyValidationError(ValueError):
    """Raised for structurally invalid policy definitions."""


class PolicyAdminService:
    """Administrative operations over the versioned policy store."""

    #: Service scopes that grant policy administration.
    _ADMIN_SCOPES = frozenset({"*", "admin", "policy:admin", "policies:write"})

    def __init__(self, session: AsyncSession):
        self.session = session
        self.policies = PrivacyPolicyRepository(session)
        self.audit = AuditRepository(session)

    # ── Access control ──────────────────────────────────────────────

    @classmethod
    def _is_admin(cls, principal: Principal | None) -> bool:
        if principal is None or not getattr(principal, "id", None):
            return False
        if principal.kind == "user":
            return "admin" in principal.roles
        if principal.kind == "service":
            return bool(cls._ADMIN_SCOPES & set(principal.scopes))
        return False

    def _require_admin(self, principal: Principal | None) -> None:
        if not self._is_admin(principal):
            raise PolicyAdminDenied(
                "policy administration requires an administrator identity"
            )

    # ── Queries ─────────────────────────────────────────────────────

    async def list_policies(
        self, principal: Principal | None, *, include_inactive: bool = False
    ) -> Sequence[PrivacyPolicy]:
        """Administrators see every version; used by admin tooling."""
        self._require_admin(principal)
        if include_inactive:
            stmt = select(PrivacyPolicy).order_by(
                PrivacyPolicy.name, PrivacyPolicy.version.desc()
            )
        else:
            stmt = (
                select(PrivacyPolicy)
                .where(PrivacyPolicy.status == PolicyStatus.ACTIVE)
                .order_by(PrivacyPolicy.name, PrivacyPolicy.version.desc())
            )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # ── Validation ──────────────────────────────────────────────────

    @staticmethod
    def _validate_definition(
        *,
        name: str,
        policy_text: str,
        resource_pattern: str,
        action: str | None,
        min_sensitivity: str | None,
        allowed_purposes: Sequence[str],
        allowed_actions: Sequence[str],
        priority: int,
    ) -> None:
        if not name or not name.strip():
            raise PolicyValidationError("policy name is required")
        if not policy_text or not policy_text.strip():
            raise PolicyValidationError("policy_text is required")
        if not resource_pattern or not resource_pattern.strip():
            raise PolicyValidationError("resource_pattern is required")
        if action is not None:
            try:
                PolicyAction(str(action).strip().upper())
            except ValueError as exc:
                raise PolicyValidationError(
                    f"action must be one of {[a.value for a in PolicyAction]}"
                ) from exc
        if min_sensitivity is not None:
            try:
                SensitivityLevel(str(min_sensitivity).strip().lower())
            except ValueError as exc:
                raise PolicyValidationError(
                    "min_sensitivity must be one of "
                    f"{[level.value for level in SensitivityLevel]}"
                ) from exc
        valid_purposes = {purpose.value for purpose in RequestPurpose}
        for purpose in allowed_purposes:
            if purpose != "*" and purpose not in valid_purposes:
                raise PolicyValidationError(
                    f"unknown purpose '{purpose}'; allowed: "
                    f"{sorted(valid_purposes)} or '*'"
                )
        for operation in allowed_actions:
            if operation != "*" and operation not in KNOWN_OPERATIONS:
                raise PolicyValidationError(
                    f"unknown operation '{operation}'; allowed: "
                    f"{sorted(KNOWN_OPERATIONS)} or '*'"
                )
        if not isinstance(priority, int):
            raise PolicyValidationError("priority must be an integer")

    # ── Mutations ───────────────────────────────────────────────────

    async def create_policy(
        self,
        principal: Principal | None,
        *,
        name: str,
        description: str | None,
        policy_text: str,
        resource_pattern: str,
        action: str | None = None,
        required_role: str | None = None,
        min_sensitivity: str | None = None,
        allowed_purposes: Sequence[str] = (),
        allowed_actions: Sequence[str] = ("read",),
        priority: int = 0,
    ) -> PrivacyPolicy:
        """Create version 1 of a new policy."""
        self._require_admin(principal)
        self._validate_definition(
            name=name,
            policy_text=policy_text,
            resource_pattern=resource_pattern,
            action=action,
            min_sensitivity=min_sensitivity,
            allowed_purposes=allowed_purposes,
            allowed_actions=allowed_actions,
            priority=priority,
        )
        existing = await self.policies.get_latest_version(name)
        if existing is not None:
            raise PolicyValidationError(
                f"policy '{name}' already exists (latest v{existing.version}); "
                "use update_policy to create a new version"
            )

        policy = PrivacyPolicy(
            name=name.strip(),
            version=1,
            description=description,
            policy_text=policy_text,
            resource_pattern=resource_pattern.strip(),
            required_role=required_role,
            min_sensitivity=min_sensitivity,
            allowed_purposes=json.dumps(list(allowed_purposes)),
            allowed_actions=json.dumps(list(allowed_actions)),
            action=(str(action).strip().upper() if action else None),
            priority=priority,
            status=PolicyStatus.ACTIVE,
        )
        self.session.add(policy)
        await self.session.flush()
        await self._audit(principal, "create_policy", policy.id, policy.name, policy.version)
        return policy

    async def update_policy(
        self,
        principal: Principal | None,
        policy_id: str,
        *,
        description: str | None = None,
        policy_text: str | None = None,
        resource_pattern: str | None = None,
        action: str | None = None,
        required_role: str | None = None,
        min_sensitivity: str | None = None,
        allowed_purposes: Sequence[str] | None = None,
        allowed_actions: Sequence[str] | None = None,
        priority: int | None = None,
    ) -> PrivacyPolicy:
        """Create a new version based on an existing policy.

        Unspecified fields are inherited from the source version. The
        source version is marked ``SUPERSEDED`` (retained for audit).
        """
        self._require_admin(principal)

        source = await self.session.get(PrivacyPolicy, policy_id)
        if source is None:
            raise PolicyValidationError(f"policy '{policy_id}' not found")

        merged = {
            "name": source.name,
            "description": description if description is not None else source.description,
            "policy_text": policy_text if policy_text is not None else source.policy_text,
            "resource_pattern": (
                resource_pattern if resource_pattern is not None else source.resource_pattern
            ),
            "action": action if action is not None else source.action,
            "required_role": (
                required_role if required_role is not None else source.required_role
            ),
            "min_sensitivity": (
                min_sensitivity if min_sensitivity is not None else source.min_sensitivity
            ),
            "allowed_purposes": (
                list(allowed_purposes)
                if allowed_purposes is not None
                else json.loads(source.allowed_purposes or "[]")
            ),
            "allowed_actions": (
                list(allowed_actions)
                if allowed_actions is not None
                else json.loads(source.allowed_actions or "[]")
            ),
            "priority": priority if priority is not None else source.priority,
        }
        self._validate_definition(
            name=merged["name"],
            policy_text=merged["policy_text"],
            resource_pattern=merged["resource_pattern"],
            action=merged["action"],
            min_sensitivity=merged["min_sensitivity"],
            allowed_purposes=merged["allowed_purposes"],
            allowed_actions=merged["allowed_actions"],
            priority=merged["priority"],
        )

        latest = await self.policies.get_latest_version(source.name)
        next_version = (latest.version if latest else source.version) + 1

        new_policy = PrivacyPolicy(
            name=source.name,
            version=next_version,
            description=merged["description"],
            policy_text=merged["policy_text"],
            resource_pattern=merged["resource_pattern"],
            required_role=merged["required_role"],
            min_sensitivity=merged["min_sensitivity"],
            allowed_purposes=json.dumps(merged["allowed_purposes"]),
            allowed_actions=json.dumps(merged["allowed_actions"]),
            action=(
                str(merged["action"]).strip().upper()
                if merged["action"]
                else None
            ),
            priority=merged["priority"],
            status=PolicyStatus.ACTIVE,
        )
        self.session.add(new_policy)
        if source.status != PolicyStatus.SUPERSEDED:
            source.status = PolicyStatus.SUPERSEDED
        await self.session.flush()
        await self._audit(
            principal, "update_policy", new_policy.id, new_policy.name, next_version
        )
        return new_policy

    async def set_status(
        self,
        principal: Principal | None,
        policy_id: str,
        status: PolicyStatus | str,
    ) -> PrivacyPolicy:
        """Activate / deactivate / archive a policy version (rollback path)."""
        self._require_admin(principal)
        if isinstance(status, str):
            try:
                status = PolicyStatus(status)
            except ValueError as exc:
                raise PolicyValidationError(
                    f"unknown status '{status}'"
                ) from exc
        policy = await self.session.get(PrivacyPolicy, policy_id)
        if policy is None:
            raise PolicyValidationError(f"policy '{policy_id}' not found")
        policy.status = status
        await self.session.flush()
        await self._audit(
            principal,
            "set_policy_status",
            policy.id,
            policy.name,
            policy.version,
            extra={"status": status.value},
        )
        return policy

    # ── Audit helper ────────────────────────────────────────────────

    async def _audit(
        self,
        principal: Principal | None,
        operation: str,
        policy_id: str,
        policy_name: str,
        version: int,
        *,
        extra: dict[str, Any] | None = None,
    ) -> None:
        detail = {
            "operation": operation,
            "policy_id": policy_id,
            "policy_name": policy_name,
            "policy_version": version,
        }
        if extra:
            detail.update(extra)
        actor_id = principal.id if principal is not None and principal.kind == "user" else None
        await self.audit.log_event(
            actor_id=actor_id,
            action=AuditAction.ADMIN_ACTION,
            resource="privacy_policy",
            resource_id=policy_id,
            outcome="success",
            detail=json.dumps(detail),
        )
