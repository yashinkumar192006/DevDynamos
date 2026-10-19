"""Authorization services: what a verified identity may do.

Authentication (see ``app.services.auth_service``) answers *who* the
requester is. This module answers *what that identity may do* — resource
access, field-level access, data ownership, allowed operations, purpose
restrictions, and relevant policy requirements.

All checks run server-side against trusted database state and return an
:class:`AccessDecision` with a machine-readable reason code. They are
reusable by the gateway, the SDK, and API endpoints. The full policy
engine (later phase) builds on top of these primitives; they are
deliberately fail-closed.
"""

import json
from dataclasses import dataclass
from typing import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import PrivacyPolicy, RequestPurpose
from app.repositories import (
    CustomerRepository,
    DataFieldRepository,
    EmployeeRepository,
    OrderRepository,
    PrivacyPolicyRepository,
    UserRepository,
)
from app.services.auth_service import Principal

#: Operations recognised when expanding wildcard permissions/scopes.
KNOWN_OPERATIONS = ("read", "write", "delete", "aggregate", "export")

#: Assets whose records are linked to a user via ``employees.user_id``.
#: Shared with the context analyzer so ownership semantics live in one place.
PERSONAL_ASSETS = ("employee_records", "employee_salary", "employee_contact")

#: Every asset whose records carry a per-user ownership link. Employee
#: assets resolve through ``employees.user_id``; customer accounts through
#: ``customers.user_id`` and orders through their customer. Self-service
#: reads (role-less policies) are only ever granted on an ownership match.
OWNERSHIP_ASSETS = PERSONAL_ASSETS + ("customer_records", "order_records")

#: Assets where record ownership alone can pass the operation-level
#: (RBAC) pre-check for a *user* principal. The external ``customer`` role
#: holds no standing permissions by design, so its self-service reads are
#: granted per-record from the trusted link; the deterministic policy
#: engine still applies per-field norms (role-less self-service policies).
#: Internal employee assets keep the RBAC gate: ownership there only scopes
#: rows/fields and never substitutes for a permission.
SELF_SERVICE_OWNERSHIP_ASSETS = ("customer_records", "order_records")


@dataclass(frozen=True)
class AccessDecision:
    """Outcome of one authorization check — never carries the raw data."""

    allowed: bool
    reason_code: str
    detail: str | None = None


def _atom_matches(granted: str, requested: str) -> bool:
    """Match one wildcard-able atom (``"*"`` matches everything)."""
    return granted == "*" or granted == requested


def _scope_allows(scopes: frozenset[str], resource: str, action: str) -> bool:
    """Match service scopes against a resource/action request.

    Accepted scope shapes: ``"*"``, ``"resource"`` (any action),
    ``"resource:*"``, ``"resource:action"``.
    """
    for scope in scopes:
        if scope == "*":
            return True
        parts = scope.split(":", 1)
        if len(parts) == 1:
            if _atom_matches(parts[0], resource):
                return True
        elif _atom_matches(parts[0], resource) and _atom_matches(parts[1], action):
            return True
    return False


def _json_list(raw: str | None) -> list[str]:
    """Parse a JSON list column, tolerating malformed/None values."""
    try:
        value = json.loads(raw or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    return value if isinstance(value, list) else []


class AuthorizationService:
    """Reusable authorization checks against trusted database state."""

    #: Assets whose records carry a per-user ownership link.
    _PERSONAL_ASSETS = PERSONAL_ASSETS
    _OWNERSHIP_ASSETS = OWNERSHIP_ASSETS

    def __init__(self, session: AsyncSession):
        self.session = session
        self.users = UserRepository(session)

    # ── Resource access ─────────────────────────────────────────────

    async def check_resource_access(
        self, principal: Principal, resource: str, action: str
    ) -> AccessDecision:
        """May this identity perform ``action`` on ``resource`` at all?

        Users are checked against role permissions; service accounts are
        checked against their scopes. A wildcard permission/scope grants
        access, but a role *name* alone never does — roles only matter
        through the permissions they carry.
        """
        if principal.kind == "service":
            if _scope_allows(principal.scopes, resource, action):
                return AccessDecision(
                    True, "SCOPE_GRANTED", f"Scope permits {resource}:{action}"
                )
            return AccessDecision(
                False,
                "NO_MATCHING_SCOPE",
                f"No scope permits {resource}:{action}",
            )
        permissions = await self.users.get_user_permissions(principal.id)
        for permission in permissions:
            if _atom_matches(permission.resource, resource) and _atom_matches(
                permission.action, action
            ):
                return AccessDecision(
                    True,
                    "PERMISSION_GRANTED",
                    f"Permission '{permission.resource}:{permission.action}' "
                    f"covers {resource}:{action}",
                )
        return AccessDecision(
            False,
            "NO_MATCHING_PERMISSION",
            f"No permission grants {resource}:{action}",
        )

    async def allowed_operations(
        self, principal: Principal, resource: str
    ) -> set[str]:
        """Return the set of actions this identity may perform on ``resource``."""
        operations: set[str] = set()
        if principal.kind == "service":
            for operation in KNOWN_OPERATIONS:
                if _scope_allows(principal.scopes, resource, operation):
                    operations.add(operation)
            return operations
        for permission in await self.users.get_user_permissions(principal.id):
            if not _atom_matches(permission.resource, resource):
                continue
            if permission.action == "*":
                operations.update(KNOWN_OPERATIONS)
            else:
                operations.add(permission.action)
        return operations

    # ── Field-level access ──────────────────────────────────────────

    async def check_field_access(
        self, principal: Principal, asset_name: str, field_name: str
    ) -> AccessDecision:
        """May this identity read ``field_name`` from ``asset_name``?

        This is the RBAC gate: a resource-level ``read`` permission on the
        asset **and** a field that actually exists in the asset's
        schema. Sensitivity caps and purpose-based field restrictions are
        applied on top by the policy engine — never here.
        """
        resource_decision = await self.check_resource_access(
            principal, asset_name, "read"
        )
        if not resource_decision.allowed:
            return resource_decision
        fields = await DataFieldRepository(self.session).get_permitted_fields(
            asset_name, allowed_field_names=[field_name]
        )
        if not fields:
            return AccessDecision(
                False,
                "FIELD_NOT_FOUND",
                f"Field '{field_name}' not found in asset '{asset_name}'",
            )
        return AccessDecision(
            True,
            "FIELD_PERMITTED",
            f"Field '{field_name}' readable under asset permission",
        )

    async def filter_fields(
        self,
        principal: Principal,
        asset_name: str,
        requested_fields: Sequence[str],
    ) -> tuple[list[str], list[str]]:
        """Split requested fields into ``(permitted, denied)`` — fail closed.

        Denied fields are simply not returned; they are never fetched and
        then filtered in application code.
        """
        resource_decision = await self.check_resource_access(
            principal, asset_name, "read"
        )
        if not resource_decision.allowed:
            return [], list(requested_fields)
        known = {
            field.field_name
            for field in await DataFieldRepository(self.session).get_permitted_fields(
                asset_name, allowed_field_names=list(requested_fields)
            )
        }
        permitted = [name for name in requested_fields if name in known]
        denied = [name for name in requested_fields if name not in known]
        return permitted, denied

    # ── Data ownership ──────────────────────────────────────────────

    async def check_data_ownership(
        self, principal: Principal, asset_name: str, record_key: str
    ) -> AccessDecision:
        """Is this identity the owner of the referenced record?

        Ownership is resolved from trusted links only — ``employees.user_id``
        for employee assets, ``customers.user_id`` for customer accounts and
        (through their customer) for orders. Only user principals can own
        records. Ownership and RBAC are independent: a self-service read
        requires the ownership match, not a broad permission.
        """
        if principal.kind != "user":
            return AccessDecision(
                False,
                "NOT_OWNER",
                "Service principals cannot own personal records",
            )
        if asset_name not in self._OWNERSHIP_ASSETS:
            return AccessDecision(
                False,
                "OWNERSHIP_NOT_APPLICABLE",
                f"No ownership link is defined for '{asset_name}'",
            )

        owner_id: str | None = None
        if asset_name in self._PERSONAL_ASSETS:
            employee = await EmployeeRepository(self.session).get_by_employee_number(
                record_key
            )
            if employee is None:
                return AccessDecision(
                    False,
                    "RECORD_NOT_FOUND",
                    f"Record '{record_key}' does not exist",
                )
            owner_id = employee.user_id
        elif asset_name == "customer_records":
            customer = await CustomerRepository(self.session).get_by_customer_number(
                record_key
            )
            if customer is None:
                return AccessDecision(
                    False,
                    "RECORD_NOT_FOUND",
                    f"Record '{record_key}' does not exist",
                )
            owner_id = customer.user_id
        elif asset_name == "order_records":
            order = await OrderRepository(self.session).get_by_order_number(record_key)
            if order is None:
                return AccessDecision(
                    False,
                    "RECORD_NOT_FOUND",
                    f"Record '{record_key}' does not exist",
                )
            customer = await CustomerRepository(self.session).get_by_id(
                order.customer_id
            )
            owner_id = customer.user_id if customer is not None else None
        else:  # pragma: no cover — defensive: unknown ownership asset
            return AccessDecision(
                False,
                "OWNERSHIP_NOT_APPLICABLE",
                f"No ownership resolver for '{asset_name}'",
            )

        if owner_id is not None and owner_id == principal.id:
            return AccessDecision(
                True, "OWNER_MATCH", f"Identity owns record '{record_key}'"
            )
        return AccessDecision(
            False, "NOT_OWNER", f"Identity does not own record '{record_key}'"
        )

    # ── Purpose restrictions & policy requirements ──────────────────

    async def check_purpose(
        self, principal: Principal, resource: str, purpose: str
    ) -> AccessDecision:
        """Purpose-level pre-check against active policies (RBAC layer).

        Confirms the purpose is recognised and that an active policy
        covering this resource lists the purpose — and, when the policy
        names a required role, that the principal holds it. The full policy
        engine performs deeper evaluation later; this check is fail-closed
        and never assumes a purpose is acceptable just because the identity
        is authenticated.
        """
        try:
            requested = RequestPurpose(purpose)
        except ValueError:
            return AccessDecision(
                False, "INVALID_PURPOSE", f"Unknown purpose '{purpose}'"
            )
        policies = await self.get_relevant_policies(resource)
        if not policies:
            return AccessDecision(
                False,
                "NO_POLICY_FOR_RESOURCE",
                f"No active policy covers '{resource}'",
            )
        for policy in policies:
            if requested.value not in _json_list(policy.allowed_purposes):
                continue
            if policy.required_role:
                if principal.kind == "user":
                    if policy.required_role not in principal.roles:
                        continue
                else:
                    if f"role:{policy.required_role}" not in principal.scopes:
                        continue
            return AccessDecision(
                True,
                "PURPOSE_ALLOWED",
                f"Matched policy '{policy.name}' v{policy.version}",
            )
        return AccessDecision(
            False,
            "PURPOSE_NOT_ALLOWED",
            f"Purpose '{purpose}' not permitted for '{resource}'",
        )

    async def get_relevant_policies(self, resource: str) -> Sequence[PrivacyPolicy]:
        """Active policies whose resource pattern matches ``resource``."""
        return await PrivacyPolicyRepository(self.session).get_policies_for_resource(
            resource
        )
