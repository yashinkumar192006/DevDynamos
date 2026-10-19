"""Context analysis: build the trusted, typed context tuple for a request.

:class:`ContextAnalyzer` turns an authenticated :class:`Principal` plus a
request payload into an :class:`~app.schemas.context.AnalyzedContext` — the
single structured representation the policy engine consumes.

Trust model (see ``docs/security-model.md`` §5):

* **Identity is never client input.** The requester block is built from the
  validated principal (credential + trusted database state). Statements in
  request text such as "I am the administrator" are *scanned as signals*
  and recorded, never believed. Authorization-looking client metadata keys
  (``role``, ``is_admin``, ``clearance``, …) are recorded by name and their
  values dropped.
* **Purpose is an input to policy, never proof of authorization.** The
  purpose claim is normalised, hashed for audit correlation, scanned for
  prompt-injection language, and pre-checked against active policies — but
  it can never elevate permissions.
* **Target scope is resolved server-side.** Resource metadata comes from
  the data catalog; self-vs-record scope comes from the trusted ownership
  link (``employees.user_id``), never from request fields. Unknown
  resources and unknown fields never fail open — they are flagged and
  surfaced for clarification.
* **Flags never contain raw client text.** Flag details reference signal
  names, key names, reason codes, and counts only.

Everything the analyzer produces is explainable: each flag names the
component it came from, and ``trusted_components`` /
``untrusted_components`` classify every part of the context.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any, Mapping, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RequestPurpose
from app.repositories import DataAssetRepository, UserRepository
from app.schemas.context import (
    AnalyzedContext,
    ContextAgent,
    ContextField,
    ContextFlag,
    ContextRequester,
    ConversationMetadata,
    DestinationAnalysis,
    FlagSeverity,
    OperationAnalysis,
    OwnershipScope,
    PolicyReference,
    PurposeAnalysis,
    TargetAnalysis,
)
from app.services.auth_service import Principal
from app.services.authorization import (
    KNOWN_OPERATIONS,
    OWNERSHIP_ASSETS,
    SELF_SERVICE_OWNERSHIP_ASSETS,
    AuthorizationService,
)

# ──────────────────────────────────────────────────────────────────────
# Injection signals
# ──────────────────────────────────────────────────────────────────────

#: Prompt-injection / social-engineering signals. Only signal *names* are
#: ever returned or logged — never the matched text.
INJECTION_SIGNALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_previous",
        re.compile(
            r"(?i)\bignore\s+(all\s+|any\s+|the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?|messages?|directions?)"
        ),
    ),
    (
        "override_rules",
        re.compile(
            r"(?i)\b(override|bypass|circumvent|disable|turn\s+off)\s+"
            r"(the\s+|all\s+|any\s+)?"
            r"(rules?|polic(y|ies)|security|restrictions?|controls?|checks?|"
            r"authorization|authentication|access\s+control)"
        ),
    ),
    (
        "identity_claim",
        re.compile(
            r"(?i)\bi\s*(?:'m|\s+am)\s+(?:the\s+)?(?:an?\s+)?"
            r"(administrator|admin|root|super\s*user|superuser|owner|ceo|cto|cfo|ciso)\b"
            r"|\bas\s+(?:the\s+|a\s+)?(administrator|admin|root|super\s*user|superuser|owner)\b"
        ),
    ),
    (
        "authority_claim",
        re.compile(
            r"(?i)\bi\s+(have|hold|possess|carry)\s+"
            r"(full\s+|all\s+|the\s+|complete\s+)?"
            r"(admin(istrator)?\s+|root\s+|super\s*user\s+|elevated\s+|"
            r"unrestricted\s+|special\s+)?"
            r"(rights?|privileges?|permissions?|access|authority|clearance)\b"
        ),
    ),
    (
        "jailbreak",
        re.compile(
            r"(?i)\b(developer|debug|maintenance|god)\s+mode\b"
            r"|\bdo\s+anything\s+now\b|\bjailbreak\b|\bDAN\s+mode\b"
        ),
    ),
    (
        "system_prompt",
        re.compile(
            r"(?i)\b(system|initial|hidden|secret)\s+(prompt|instructions?|message)"
            r"|\breveal\s+(your|the)\s+(system\s+)?(prompt|instructions?|guidelines)"
        ),
    ),
    (
        "access_demand",
        re.compile(
            r"(?i)\b(give|grant|show|provide|send|hand\s+over|dump)\s+"
            r"(me\s+|us\s+)?(the\s+|all\s+|every\s+|any\s+)?"
            r"(data|records?|salar(y|ies)|passwords?|credentials?|secrets?|"
            r"tokens?|everything|keys?)"
            r"|\bbypass\s+the\s+(check|policy|rules|security)"
        ),
    ),
    (
        "pretense",
        re.compile(
            r"(?i)\bpretend\b|hypothetical(ly)?|fictional\s+scenario"
            r"|for\s+(testing|research|training)\s+purposes|just\s+imagine"
            r"|role[- ]?play(ing)?"
        ),
    ),
    (
        "authorization_claim",
        re.compile(
            r"(?i)\bi\s*(?:'m|\s+am)\s+(authorized|allowed|permitted|cleared|approved)\b"
            r"|\bauthorized\s+by\b|\bapproved\s+by\b|\bon\s+behalf\s+of\b"
            r"|\bthis\s+is\s+an?\s+(authorized|approved|official)\s+request\b"
        ),
    ),
)


def scan_for_injection(*texts: str | None) -> list[str]:
    """Return the ordered, de-duplicated names of injection signals found.

    Scans claim text only (purpose / purpose detail). The matched text is
    never returned or logged — downstream systems act on signal names.
    """
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        for name, pattern in INJECTION_SIGNALS:
            if name not in found and pattern.search(text):
                found.append(name)
    return found


# ──────────────────────────────────────────────────────────────────────
# Recognised vocabulary
# ──────────────────────────────────────────────────────────────────────

#: Client metadata keys the analyzer accepts as conversation/task
#: correlation values (still recorded as untrusted).
RECOGNIZED_METADATA_KEYS = frozenset(
    {"session_id", "conversation_id", "task_id", "turn_index", "agent_name"}
)

#: Client metadata keys that look like authorization claims. Their values
#: are dropped; the key names are recorded as ignored claims.
IDENTITY_CLAIM_KEYS = frozenset(
    {
        "role",
        "roles",
        "is_admin",
        "admin",
        "user_id",
        "clearance",
        "permissions",
        "scopes",
    }
)

#: Target-entity sentinels that resolve to organisation-wide scope.
ORG_TARGETS = frozenset({"*", "all", "organization", "org", "department-all"})

#: ``department:<name>`` / ``department-<name>`` / ``department_<name>``.
DEPARTMENT_TARGET_RE = re.compile(r"^department[-_:]\s*(?P<dept>[\w .-]+)$", re.IGNORECASE)

#: Purpose values recognised by the request model.
PURPOSE_VALUES = frozenset(purpose.value for purpose in RequestPurpose)

#: Flags that request additional information from the client. Suppressed
#: when injection is suspected — a suspicious request is escalated/denied,
#: not clarified.
CLARIFICATION_FLAGS = frozenset(
    {"PURPOSE_MISSING", "PURPOSE_UNRECOGNIZED", "RESOURCE_UNKNOWN", "FIELDS_MISSING"}
)

#: Bounds keeping untrusted input from inflating the context object.
MAX_REQUESTED_FIELDS = 100
MAX_METADATA_VALUE_LEN = 128
MAX_LISTED_KEYS = 25

_PURPOSE_CLEAN_RE = re.compile(r"[^a-z0-9]+")


def _flag(code: str, severity: FlagSeverity, component: str, detail: str) -> ContextFlag:
    return ContextFlag(code=code, severity=severity, component=component, detail=detail)


def _clean_str(value: Any, limit: int = MAX_METADATA_VALUE_LEN) -> str | None:
    """Coerce an untrusted value to a bounded string (never raises)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _policy_purposes(policy) -> list[str]:
    """Parse a policy's ``allowed_purposes`` JSON column, tolerating junk."""
    try:
        value = json.loads(policy.allowed_purposes or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


class ContextAnalyzer:
    """Build the typed, trust-annotated context for one request.

    The analyzer is read-only: it resolves identity, catalog metadata,
    ownership, authorization outcomes, and policy references but makes no
    decisions and writes nothing. The policy engine owns decisions.

    ``destination_kind`` / ``destination_name`` must be supplied by the
    server (flow configuration), never by the client payload.
    """

    def __init__(
        self,
        session: AsyncSession,
        authorization: AuthorizationService | None = None,
    ):
        self.session = session
        self.authz = authorization or AuthorizationService(session)
        self.assets = DataAssetRepository(session)
        self.users = UserRepository(session)

    # ── Public API ──────────────────────────────────────────────────

    async def analyze(
        self,
        principal: Principal,
        *,
        resource: str,
        operation: str = "read",
        purpose: str | None = None,
        purpose_detail: str | None = None,
        requested_fields: Sequence[str] = (),
        target_entity: str | None = None,
        request_id: str | None = None,
        destination_kind: str | None = None,
        destination_name: str | None = None,
        client_metadata: Mapping[str, Any] | None = None,
    ) -> AnalyzedContext:
        """Analyse a request into the trusted context tuple.

        Raises nothing for bad/untrusted input: unknown resources, unknown
        purposes, and unknown fields are *represented* in the context (with
        flags and clarification requests), fail-closed, so the policy
        engine can deny without the analyzer having to guess.
        """
        resource = (resource or "").strip()

        requester, agent = await self._resolve_requester(principal)

        operation_analysis, operation_flags = await self._analyze_operation(
            principal, resource, operation, target_entity
        )

        policies, policy_coverage, policy_flags = await self._resolve_policies(resource)
        allowed_purposes = sorted(
            {purpose_name for ref in policies for purpose_name in ref.allowed_purposes}
        )

        purpose_analysis, purpose_flags = await self._analyze_purpose(
            principal, resource, purpose, purpose_detail, allowed_purposes
        )

        asset = (
            await self.assets.get_by_name_with_fields(resource) if resource else None
        )

        target, target_flags = await self._analyze_target(
            principal, requester, resource, target_entity, asset
        )
        fields, field_flags = self._analyze_fields(asset, requested_fields)

        (
            conversation,
            metadata_keys,
            identity_claims,
            conversation_flags,
        ) = self._analyze_client_metadata(client_metadata, principal)
        destination, destination_flags = self._analyze_destination(
            destination_kind, destination_name
        )

        flags = [
            *conversation_flags,
            *purpose_flags,
            *operation_flags,
            *target_flags,
            *field_flags,
            *policy_flags,
            *destination_flags,
        ]

        injection_suspected = purpose_analysis.injection_suspected
        requires_clarification = (
            any(flag.code in CLARIFICATION_FLAGS for flag in flags)
            and not injection_suspected
        )

        trusted_components = ["requester"]
        if agent is not None:
            trusted_components.append("agent")
        trusted_components.append("operation_authorization")
        trusted_components.append("target_catalog")
        if target.ownership.checked:
            trusted_components.append("target_ownership")
        trusted_components.append("policies")
        if destination.trusted:
            trusted_components.append("destination")

        untrusted_components = ["purpose"]
        if purpose_detail:
            untrusted_components.append("purpose_detail")
        if fields:
            untrusted_components.append("requested_fields")
        if target.target_entity:
            untrusted_components.append("target_entity")
        if conversation_flags or any(
            (
                conversation.session_id,
                conversation.conversation_id,
                conversation.task_id,
                conversation.turn_index,
                conversation.agent_name,
            )
        ):
            untrusted_components.append("conversation_metadata")
        if client_metadata:
            untrusted_components.append("client_metadata")

        return AnalyzedContext(
            request_id=request_id or uuid.uuid4().hex,
            requester=requester,
            agent=agent,
            operation=operation_analysis,
            purpose=purpose_analysis,
            target=target,
            requested_fields=fields,
            destination=destination,
            conversation=conversation,
            policies=policies,
            policy_coverage=policy_coverage,
            flags=flags,
            requires_clarification=requires_clarification,
            trusted_components=trusted_components,
            untrusted_components=untrusted_components,
            client_metadata_keys=metadata_keys,
            identity_claims_ignored=identity_claims,
        )

    # ── Identity ────────────────────────────────────────────────────

    async def _resolve_requester(
        self, principal: Principal
    ) -> tuple[ContextRequester, ContextAgent | None]:
        """Requester block from the validated credential — never from input."""
        user = principal.user
        if principal.kind == "user" and user is None:
            # Principal built without the ORM object; re-resolve the current
            # trusted state so department/employee scope stay server-side.
            user = await self.users.get_with_roles(principal.id)

        requester = ContextRequester(
            id=principal.id,
            kind=principal.kind,
            display_name=principal.display_name,
            username=principal.username,
            roles=sorted(principal.roles),
            department=getattr(user, "department", None) if user else None,
            employee_id=getattr(user, "employee_id", None) if user else None,
        )
        agent: ContextAgent | None = None
        if principal.kind == "service":
            agent = ContextAgent(
                id=principal.id,
                kind="service_account",
                name=principal.display_name,
                scopes=sorted(principal.scopes),
            )
        return requester, agent

    # ── Operation ───────────────────────────────────────────────────

    async def _analyze_operation(
        self,
        principal: Principal,
        resource: str,
        operation: str,
        target_entity: str | None = None,
    ) -> tuple[OperationAnalysis, list[ContextFlag]]:
        raw = _clean_str(operation, 50) or ""
        normalized = raw.lower()
        flags: list[ContextFlag] = []

        if normalized and normalized not in KNOWN_OPERATIONS:
            flags.append(
                _flag(
                    "OPERATION_UNRECOGNIZED",
                    FlagSeverity.WARNING,
                    "operation",
                    f"operation is not in the recognised set: {', '.join(KNOWN_OPERATIONS)}",
                )
            )

        allowed = False
        reason_code = "RESOURCE_UNSPECIFIED"
        detail: str | None = None
        if resource:
            decision = await self.authz.check_resource_access(
                principal, resource, normalized or "read"
            )
            allowed = decision.allowed
            reason_code = decision.reason_code
            detail = decision.detail

            # Ownership-granted self-service: an identity with no standing
            # permission may still read its *own* record on the external
            # self-service assets (customers hold no role permissions by
            # design; see docs/authentication.md). The ownership match is
            # trusted database state and read-only.
            if (
                not allowed
                and normalized == "read"
                and target_entity
                and resource in SELF_SERVICE_OWNERSHIP_ASSETS
            ):
                ownership = await self.authz.check_data_ownership(
                    principal, resource, str(target_entity)
                )
                if ownership.allowed:
                    allowed = True
                    reason_code = "SELF_SERVICE_OWNERSHIP"
                    detail = ownership.detail

            if not allowed:
                flags.append(
                    _flag(
                        "OPERATION_NOT_ALLOWED",
                        FlagSeverity.WARNING,
                        "operation",
                        f"authorization pre-check failed: {reason_code}",
                    )
                )

        return (
            OperationAnalysis(
                requested=raw,
                normalized=normalized,
                allowed=allowed,
                reason_code=reason_code,
                detail=detail,
            ),
            flags,
        )

    # ── Purpose ─────────────────────────────────────────────────────

    async def _analyze_purpose(
        self,
        principal: Principal,
        resource: str,
        purpose: str | None,
        purpose_detail: str | None,
        allowed_purposes: list[str],
    ) -> tuple[PurposeAnalysis, list[ContextFlag]]:
        flags: list[ContextFlag] = []

        raw_claim = purpose.strip() if isinstance(purpose, str) else None
        if not raw_claim:
            raw_claim = None

        signals = scan_for_injection(raw_claim, purpose_detail)
        injection_suspected = bool(signals)

        normalized: str | None = None
        recognized = False
        claimed_hash: str | None = None
        if raw_claim is not None:
            claimed_hash = hashlib.sha256(raw_claim.encode("utf-8")).hexdigest()
            normalized = _PURPOSE_CLEAN_RE.sub("_", raw_claim.lower()).strip("_")
            recognized = normalized in PURPOSE_VALUES

        precheck_allowed: bool | None = None
        precheck_reason: str | None = None
        if raw_claim is None:
            flags.append(
                _flag(
                    "PURPOSE_MISSING",
                    FlagSeverity.INFO,
                    "purpose",
                    "no purpose claim supplied; policy evaluation requires one",
                )
            )
        elif not recognized:
            precheck_allowed = False
            precheck_reason = "INVALID_PURPOSE"
            flags.append(
                _flag(
                    "PURPOSE_UNRECOGNIZED",
                    FlagSeverity.WARNING,
                    "purpose",
                    "purpose claim does not match any recognised purpose value",
                )
            )
        else:
            decision = await self.authz.check_purpose(principal, resource, normalized)
            precheck_allowed = decision.allowed
            precheck_reason = decision.reason_code

        if injection_suspected:
            flags.append(
                _flag(
                    "INJECTION_SUSPECTED",
                    FlagSeverity.HIGH,
                    "purpose",
                    "injection signals detected: " + ", ".join(signals),
                )
            )

        return (
            PurposeAnalysis(
                claimed=raw_claim[:500] if raw_claim else None,
                claimed_hash=claimed_hash,
                normalized=normalized,
                recognized=recognized,
                allowed_purposes=allowed_purposes,
                precheck_allowed=precheck_allowed,
                precheck_reason_code=precheck_reason,
                injection_suspected=injection_suspected,
                injection_signals=signals,
            ),
            flags,
        )

    # ── Target / ownership scope ────────────────────────────────────

    async def _analyze_target(
        self,
        principal: Principal,
        requester: ContextRequester,
        resource: str,
        target_entity: str | None,
        asset,
    ) -> tuple[TargetAnalysis, list[ContextFlag]]:
        flags: list[ContextFlag] = []
        ownership = OwnershipScope()
        subject_scope = "unknown"
        department_scope_match: bool | None = None

        entity = _clean_str(target_entity)
        if entity:
            lowered = entity.lower()
            if lowered in ORG_TARGETS:
                subject_scope = "organization"
            else:
                department = DEPARTMENT_TARGET_RE.match(entity)
                if department:
                    subject_scope = "department"
                    dept = department.group("dept").strip()
                    if requester.department:
                        department_scope_match = (
                            dept.lower() == requester.department.strip().lower()
                        )
                        if not department_scope_match:
                            flags.append(
                                _flag(
                                    "DEPARTMENT_SCOPE_MISMATCH",
                                    FlagSeverity.HIGH,
                                    "target",
                                    "department-scoped target does not match the "
                                    "requester's department",
                                )
                            )
                elif resource in OWNERSHIP_ASSETS and principal.kind == "user":
                    # Only user principals can own records; service
                    # principals get no ownership scope at all.
                    decision = await self.authz.check_data_ownership(
                        principal, resource, entity
                    )
                    ownership = OwnershipScope(
                        checked=True,
                        allowed=decision.allowed,
                        reason_code=decision.reason_code,
                    )
                    subject_scope = "self" if decision.allowed else "record"
                    if not decision.allowed:
                        flags.append(
                            _flag(
                                "OWNERSHIP_NOT_MATCHED",
                                FlagSeverity.INFO,
                                "target",
                                f"ownership check did not match: {decision.reason_code}",
                            )
                        )
                else:
                    subject_scope = "record"
        # No entity named: personal-asset reads stay unscoped (unknown)
        # rather than being assumed self. Business assets are likewise left
        # unspecified for the policy engine to rule on.

        if asset is None:
            flags.append(
                _flag(
                    "RESOURCE_UNKNOWN",
                    FlagSeverity.WARNING,
                    "target",
                    "resource is not present in the data catalog",
                )
            )

        return (
            TargetAnalysis(
                resource=resource,
                resource_known=asset is not None,
                asset_type=getattr(asset, "asset_type", None),
                owner_department=getattr(asset, "owner_department", None),
                table_name=getattr(asset, "table_name", None),
                target_entity=entity,
                subject_scope=subject_scope,
                department_scope_match=department_scope_match,
                ownership=ownership,
            ),
            flags,
        )

    # ── Requested fields ────────────────────────────────────────────

    def _analyze_fields(
        self, asset, requested_fields: Sequence[str]
    ) -> tuple[list[ContextField], list[ContextFlag]]:
        flags: list[ContextFlag] = []
        names: list[str] = []
        seen: set[str] = set()
        for raw in requested_fields or ():
            name = _clean_str(raw, 100)
            if name is None:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(name)

        if len(names) > MAX_REQUESTED_FIELDS:
            names = names[:MAX_REQUESTED_FIELDS]
            flags.append(
                _flag(
                    "FIELDS_TRUNCATED",
                    FlagSeverity.WARNING,
                    "fields",
                    f"requested fields truncated at {MAX_REQUESTED_FIELDS}",
                )
            )

        fields: list[ContextField] = []
        missing: list[str] = []
        if asset is None:
            for name in names:
                fields.append(
                    ContextField(
                        name=name,
                        known_in_asset=False,
                        note="asset not found in the data catalog",
                    )
                )
                missing.append(name)
        else:
            catalog = {field.field_name.lower(): field for field in asset.fields}
            for name in names:
                catalog_field = catalog.get(name.lower())
                if catalog_field is not None:
                    fields.append(
                        ContextField(
                            name=catalog_field.field_name,
                            known_in_asset=True,
                            column_name=catalog_field.column_name
                            or catalog_field.field_name,
                        )
                    )
                else:
                    fields.append(
                        ContextField(
                            name=name,
                            known_in_asset=False,
                            note="not present in the asset schema",
                        )
                    )
                    missing.append(name)

        if missing:
            flags.append(
                _flag(
                    "FIELDS_MISSING",
                    FlagSeverity.WARNING,
                    "fields",
                    f"{len(missing)} requested field(s) could not be resolved "
                    "in the data catalog",
                )
            )
        return fields, flags

    # ── Policies ────────────────────────────────────────────────────

    async def _resolve_policies(
        self, resource: str
    ) -> tuple[list[PolicyReference], bool, list[ContextFlag]]:
        if not resource:
            return [], False, []
        policies = await self.authz.get_relevant_policies(resource)
        refs = [
            PolicyReference(
                id=policy.id,
                name=policy.name,
                version=policy.version,
                required_role=policy.required_role,
                allowed_purposes=_policy_purposes(policy),
            )
            for policy in policies
        ]
        flags: list[ContextFlag] = []
        if not refs:
            flags.append(
                _flag(
                    "NO_POLICY_FOR_RESOURCE",
                    FlagSeverity.WARNING,
                    "policies",
                    "no active policy covers this resource",
                )
            )
        return refs, bool(refs), flags

    # ── Conversation metadata / client claims ───────────────────────

    def _analyze_client_metadata(
        self, client_metadata: Mapping[str, Any] | None, principal: Principal
    ) -> tuple[ConversationMetadata, list[str], list[str], list[ContextFlag]]:
        """Split client metadata into correlation values and ignored claims.

        Recognised correlation keys are stored (bounded, marked untrusted).
        Authorization-looking keys are recorded by name only; their values
        are dropped. Unrecognised keys are listed by name only.

        Returns ``(conversation, unrecognised_keys, ignored_identity_claims,
        flags)``.
        """
        conversation = ConversationMetadata()
        if not client_metadata:
            return conversation, [], [], []

        lowered: dict[str, Any] = {}
        for key, value in client_metadata.items():
            lowered.setdefault(str(key).strip().lower(), value)

        flags: list[ContextFlag] = []

        conversation.session_id = _clean_str(lowered.get("session_id"))
        conversation.conversation_id = _clean_str(lowered.get("conversation_id"))
        conversation.task_id = _clean_str(lowered.get("task_id"))
        conversation.agent_name = _clean_str(lowered.get("agent_name"), 100)

        turn_index = lowered.get("turn_index")
        if turn_index is not None:
            try:
                parsed_turn = int(str(turn_index).strip())
            except (TypeError, ValueError):
                parsed_turn = None
            if parsed_turn is not None and parsed_turn >= 0:
                conversation.turn_index = parsed_turn

        unrecognized_keys = sorted(
            key
            for key in lowered
            if key not in RECOGNIZED_METADATA_KEYS
            and key not in IDENTITY_CLAIM_KEYS
        )[:MAX_LISTED_KEYS]

        ignored_claims = sorted(
            key for key in lowered if key in IDENTITY_CLAIM_KEYS
        )
        if ignored_claims:
            flags.append(
                _flag(
                    "IDENTITY_CLAIM_IGNORED",
                    FlagSeverity.HIGH,
                    "client_metadata",
                    "authorization-looking metadata keys recorded and ignored "
                    "(values dropped): " + ", ".join(ignored_claims),
                )
            )

        if (
            principal.kind == "service"
            and conversation.agent_name
            and conversation.agent_name.lower() != principal.display_name.strip().lower()
        ):
            flags.append(
                _flag(
                    "AGENT_CLAIM_MISMATCH",
                    FlagSeverity.WARNING,
                    "conversation_metadata",
                    "client-declared agent name does not match the "
                    "authenticated service identity",
                )
            )

        return conversation, unrecognized_keys, ignored_claims, flags

    # ── Destination ─────────────────────────────────────────────────

    def _analyze_destination(
        self, kind: str | None, name: str | None
    ) -> tuple[DestinationAnalysis, list[ContextFlag]]:
        clean_name = _clean_str(name, 100)
        raw_kind = (kind or "").strip().lower()
        if not raw_kind:
            return DestinationAnalysis(name=clean_name), []
        if raw_kind in {"model", "tool", "service"}:
            return (
                DestinationAnalysis(
                    kind=raw_kind,
                    name=clean_name,
                    source="server_declared",
                    trusted=True,
                ),
                [],
            )
        return (
            DestinationAnalysis(name=clean_name),
            [
                _flag(
                    "DESTINATION_UNRECOGNIZED",
                    FlagSeverity.WARNING,
                    "destination",
                    "server-declared destination kind is not recognised "
                    "(model | tool | service)",
                )
            ],
        )
