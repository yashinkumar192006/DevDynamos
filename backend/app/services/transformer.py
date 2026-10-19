"""Minimum-disclosure transformer — real data transformations.

Implements the value-level transformations the policy engine can decide:
``MASK``, ``TOKENIZE``, ``GENERALIZE``, ``AGGREGATE`` (and pass-through for
``ALLOW``; ``BLOCK`` / ``ESCALATE`` produce no value at all).

Design notes
============

* **Real transformations, not labels.** Masking rewrites digit groups,
  generalization replaces values with coarser representations, tokens
  are cryptographic substitutes, and aggregation returns statistics —
  the raw payload is never attached alongside a decision.
* **Protected token mapping.** :class:`TokenVault` keeps the
  token → value mapping server-side only. Tokens are deterministic per
  ``(value, server secret, session)`` so internal correlation works
  inside a session; the vault refuses to resolve a token from another
  session, and it is never exposed through the API surface.
* **Noise-free mathematics.** Aggregates are computed exactly; this
  module makes **no claim of differential privacy**. The safeguards are
  the configurable minimum group size (k-anonymity) and the repeated-
  query control (:class:`AggregateGuard`).

Mask patterns and generalize targets follow ``docs/privacy-policies.md``
§2.3.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import math
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Sequence

from app.core.config import settings as default_settings
from app.models import TransformationType
from app.services.policy_engine import FieldDecision, PolicyAction

logger = logging.getLogger(__name__)

#: Maximum length kept for a transformed preview in audit records.
_PREVIEW_LIMIT = 200


# ──────────────────────────────────────────────────────────────────────
# Masking
# ──────────────────────────────────────────────────────────────────────


def _digits_of(value: Any) -> str:
    return re.sub(r"\D", "", str(value))


def mask_ssn(value: Any) -> str:
    """``123-45-6789`` → ``***-**-6789`` (docs §2.3)."""
    digits = _digits_of(value)
    return f"***-**-{digits[-4:].zfill(4)}"


def mask_credit_card(value: Any) -> str:
    """``4111-1111-1111-1234`` → ``****-****-****-1234``."""
    digits = _digits_of(value)
    return f"****-****-****-{digits[-4:].zfill(4)}"


def mask_bank_account(value: Any) -> str:
    """``9876543210`` → ``******3210``."""
    digits = _digits_of(value)
    return f"******{digits[-4:].zfill(4)}"


def mask_email(value: Any) -> str:
    """``john.doe@company.com`` → ``j***@company.com``."""
    text = str(value)
    local, separator, domain = text.partition("@")
    if not separator or not local:
        return mask_generic(value)
    return f"{local[0]}***@{domain}"


def mask_phone(value: Any) -> str:
    """Keep the last four digits (and any country code), star the rest.

    ``(555) 123-4567`` → ``(***) ***-4567``; ``+1-555-0101`` →
    ``+1-***-0101``. Separators (``+``, ``-``, spaces, parentheses) are
    preserved so the masked value remains recognisable as a phone number
    without being usable.
    """
    text = str(value)
    digit_positions = [index for index, char in enumerate(text) if char.isdigit()]
    keep_first = 0
    if text.startswith("+") and len(digit_positions) > 4:
        # Preserve the country code (leading digit run).
        keep_first = 1
        first = digit_positions[0]
        while (
            keep_first < len(digit_positions)
            and digit_positions[keep_first] == first + keep_first
        ):
            keep_first += 1
        keep_first = min(keep_first, len(digit_positions) - 4)
    keep_from = len(digit_positions) - 4
    masked = list(text)
    for rank, position in enumerate(digit_positions):
        if rank >= keep_first and rank < keep_from:
            masked[position] = "*"
    return "".join(masked)


def mask_api_key(value: Any) -> str:
    """``sk-abcdefghij1234567890`` → ``sk-****...7890``."""
    text = str(value)
    prefix, separator, _ = text.partition("-")
    if separator:
        return f"{prefix}-****...{text[-4:]}"
    return f"****...{text[-4:]}"


def mask_generic(value: Any) -> str:
    """Keep the first and last character; star out the middle."""
    text = str(value)
    if len(text) <= 2:
        return "*" * max(len(text), 3)
    return f"{text[0]}{'*' * max(len(text) - 2, 3)}{text[-1]}"


#: Category → masker. Categories follow ``DataField.pii_category``.
_MASKERS: dict[str, Callable[[Any], str]] = {
    "ssn": mask_ssn,
    "credit_card": mask_credit_card,
    "bank_account": mask_bank_account,
    "email": mask_email,
    "phone": mask_phone,
    "api_key": mask_api_key,
}


def mask_value(value: Any, *, category: str | None = None) -> Any:
    """Mask ``value`` using the pattern for ``category`` (docs §2.3)."""
    if value is None:
        return None
    masker = _MASKERS.get((category or "").strip().lower(), mask_generic)
    return masker(value)


# ──────────────────────────────────────────────────────────────────────
# Generalization
# ──────────────────────────────────────────────────────────────────────

_SALARY_BRACKET = 10_000

_ADDRESS_RE = re.compile(
    r",\s*(?P<city>[A-Za-z][A-Za-z .'\-]*),\s*(?P<region>[A-Z]{2})(?:\s|$)"
)


def generalize_salary(value: Any) -> str:
    """``95000`` → ``$90,000 – $100,000`` (10k brackets, docs §2.3)."""
    amount = float(value)
    lower = int(amount // _SALARY_BRACKET) * _SALARY_BRACKET
    upper = lower + _SALARY_BRACKET
    return f"${lower:,} – ${upper:,}"


def generalize_date_of_birth(value: Any) -> str:
    """``1990-03-15`` → ``35–40 years old`` (5-year bands)."""
    if isinstance(value, datetime):
        born = value.date()
    elif isinstance(value, date):
        born = value
    else:
        born = date.fromisoformat(str(value)[:10])
    today = datetime.now(timezone.utc).date()
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    band = (age // 5) * 5
    return f"{band}\u2013{band + 5} years old"


def generalize_address(value: Any) -> str:
    """``123 Main St, Springfield, IL 62701`` → ``Springfield, IL``."""
    text = str(value)
    match = _ADDRESS_RE.search(text)
    if match:
        return f"{match.group('city').strip()}, {match.group('region')}"
    # Fallback: last two comma-separated segments, stripped of the ZIP.
    parts = [part.strip() for part in text.split(",") if part.strip()]
    if len(parts) >= 2:
        region = re.sub(r"\s+\d{4,}.*$", "", parts[-1]).strip()
        return f"{parts[-2]}, {region}" if region else parts[-2]
    return "[generalized]"


def generalize_number(value: Any) -> float | int:
    """Round a number down to two significant digits."""
    amount = float(value)
    if amount == 0:
        return 0
    magnitude = 10 ** (math.floor(math.log10(abs(amount))) - 1)
    rounded = round(amount / magnitude) * magnitude
    return int(rounded) if float(rounded).is_integer() else rounded


def generalize_value(
    value: Any,
    *,
    category: str | None = None,
    field_name: str | None = None,
    field_type: str | None = None,
) -> Any:
    """Reduce the precision of ``value`` (docs §2.3 generalize table)."""
    if value is None:
        return None
    category_key = (category or "").strip().lower()
    name_key = (field_name or "").strip().lower()

    if category_key == "salary" or "salary" in name_key or "bonus" in name_key:
        try:
            return generalize_salary(value)
        except (TypeError, ValueError):
            return "[generalized]"
    if category_key == "date_of_birth" or "birth" in name_key:
        try:
            return generalize_date_of_birth(value)
        except (TypeError, ValueError):
            return "[generalized]"
    if category_key == "address" or "address" in name_key:
        return generalize_address(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return generalize_number(value)
    if isinstance(value, (date, datetime)):
        return str(value)[:4]  # year only
    # Fail safe: unhandled free text is replaced, never echoed raw.
    return "[generalized]"


# ──────────────────────────────────────────────────────────────────────
# Tokenization
# ──────────────────────────────────────────────────────────────────────


@dataclass
class _TokenEntry:
    value: str
    session_id: str
    expires_at: float


class TokenVault:
    """Protected, session-scoped token → value mapping.

    The vault lives server-side only. Tokens are deterministic within a
    session (same value → same token) so internal correlation works, and
    the mapping is never exposed to callers. ``resolve`` refuses tokens
    from a different session or past their TTL.
    """

    def __init__(
        self,
        secret: str,
        *,
        ttl_seconds: int = 3600,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._secret = secret.encode("utf-8")
        self._ttl = ttl_seconds
        self._clock = clock
        self._entries: dict[str, _TokenEntry] = {}

    def tokenize(self, value: Any, *, session_id: str | None = None) -> str:
        """Return ``tok_<base64(sha256(value + secret + session))[:16]>``."""
        session_key = session_id or "anonymous"
        digest = hashlib.sha256(
            str(value).encode("utf-8")
            + b"\x00"
            + self._secret
            + b"\x00"
            + session_key.encode("utf-8")
        ).digest()
        token = "tok_" + base64.urlsafe_b64encode(digest[:16]).decode("ascii").rstrip("=")
        self._entries[token] = _TokenEntry(
            value=str(value),
            session_id=session_key,
            expires_at=self._clock() + self._ttl,
        )
        return token

    def resolve(self, token: str, *, session_id: str | None = None) -> str | None:
        """Resolve a token within its session; ``None`` otherwise."""
        entry = self._entries.get(token)
        if entry is None:
            return None
        if entry.expires_at < self._clock():
            del self._entries[token]
            return None
        if entry.session_id != (session_id or "anonymous"):
            return None
        return entry.value

    def purge_expired(self) -> int:
        """Drop expired entries; returns the number removed."""
        now = self._clock()
        expired = [token for token, entry in self._entries.items() if entry.expires_at < now]
        for token in expired:
            del self._entries[token]
        return len(expired)


# ──────────────────────────────────────────────────────────────────────
# Aggregation
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AggregateResult:
    """Approved aggregate statistics (docs §2.3 AGGREGATE output)."""

    mean: float
    median: float
    count: int
    min: float
    max: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "mean": self.mean,
            "median": self.median,
            "count": self.count,
            "range": [self.min, self.max],
        }


def compute_aggregate(
    values: Sequence[Any], *, min_group_size: int
) -> AggregateResult | None:
    """Compute ``{mean, median, count, range}`` or ``None`` when the group
    is smaller than ``min_group_size`` (k-anonymity). No noise is added —
    this is not differential privacy."""
    numbers: list[float] = []
    for value in values:
        if value is None:
            continue
        numbers.append(float(value))  # raises ValueError on junk → fail closed
    if len(numbers) < max(int(min_group_size), 1):
        return None
    ordered = sorted(numbers)
    count = len(ordered)
    middle = count // 2
    median = (
        ordered[middle]
        if count % 2 == 1
        else (ordered[middle - 1] + ordered[middle]) / 2
    )
    return AggregateResult(
        mean=round(sum(ordered) / count, 2),
        median=round(median, 2),
        count=count,
        min=ordered[0],
        max=ordered[-1],
    )


class AggregateGuard:
    """Repeated-query control for aggregate requests.

    Counts identical aggregate requests (same session, resource, scope and
    field set) inside a sliding window. Once the configured limit is
    exceeded the guard refuses further repeats — the connector turns that
    into ``ESCALATE`` / ``MOSAIC_RISK``. In-memory and per-process by
    design; it is an inference *brake*, not a formal privacy mechanism.
    """

    def __init__(
        self,
        *,
        repeat_limit: int = 5,
        window_seconds: int = 300,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._limit = max(int(repeat_limit), 1)
        self._window = max(int(window_seconds), 1)
        self._clock = clock
        self._history: dict[tuple, list[float]] = {}

    @staticmethod
    def signature(
        *, session_id: str | None, resource: str, scope: str | None, fields: Sequence[str]
    ) -> tuple:
        return (
            session_id or "anonymous",
            resource,
            (scope or "").lower(),
            tuple(sorted(field.lower() for field in fields)),
        )

    def allow(self, signature: tuple) -> bool:
        """Record one request; ``True`` while inside the repeat budget."""
        now = self._clock()
        history = self._history.setdefault(signature, [])
        history[:] = [stamp for stamp in history if now - stamp < self._window]
        if len(history) >= self._limit:
            return False
        history.append(now)
        return True


# ──────────────────────────────────────────────────────────────────────
# Transformer
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TransformedValue:
    """One transformed field value plus its audit fingerprint."""

    field_name: str
    action: str
    value: Any
    transformation_type: str | None
    original_hash: str | None
    preview: str | None
    #: Raw original value — held in memory only so the output privacy guard
    #: can compare model output against protected source values. It is
    #: never persisted, logged, or attached to responses (audit trails use
    #: ``original_hash`` / ``preview`` only).
    source_value: Any = None


def _value_hash(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _json_safe(value: Any) -> Any:
    """Normalise DB scalar types (Decimal, date) for response payloads."""
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return value


class Transformer:
    """Applies :class:`FieldDecision`\\ s to raw values."""

    def __init__(self, *, token_vault: TokenVault | None = None, settings_obj: Any = None):
        settings = settings_obj or default_settings
        secret = getattr(settings, "POLICY_TOKEN_SECRET", None) or getattr(
            settings, "JWT_SECRET", "contextshield-token-secret"
        )
        ttl_seconds = int(getattr(settings, "POLICY_TOKEN_TTL_MINUTES", 60)) * 60
        self.token_vault = token_vault or TokenVault(secret, ttl_seconds=ttl_seconds)
        self.min_group_size = int(getattr(settings, "POLICY_MIN_GROUP_SIZE", 5))

    # ── Single value ────────────────────────────────────────────────

    def transform_value(
        self,
        value: Any,
        decision: FieldDecision,
        *,
        session_id: str | None = None,
    ) -> TransformedValue:
        action = decision.action
        if action in {PolicyAction.BLOCK, PolicyAction.ESCALATE}:
            return TransformedValue(
                field_name=decision.field_name,
                action=action.value,
                value=None,
                transformation_type=(
                    TransformationType.SUPPRESS.value
                    if action is PolicyAction.BLOCK
                    else None
                ),
                original_hash=None,
                preview=None,
            )

        if action is PolicyAction.ALLOW:
            safe_value = _json_safe(value)
            return TransformedValue(
                field_name=decision.field_name,
                action=action.value,
                value=safe_value,
                transformation_type=None,
                original_hash=_value_hash(value) if value is not None else None,
                preview=None,
                source_value=value,
            )

        original_hash = _value_hash(value) if value is not None else None

        if action is PolicyAction.MASK:
            masked = mask_value(value, category=decision.pii_category)
            return TransformedValue(
                field_name=decision.field_name,
                action=action.value,
                value=masked,
                transformation_type=TransformationType.MASK.value,
                original_hash=original_hash,
                preview=str(masked)[:_PREVIEW_LIMIT],
                source_value=value,
            )

        if action is PolicyAction.GENERALIZE:
            generalized = generalize_value(
                value,
                category=decision.pii_category,
                field_name=decision.field_name,
                field_type=decision.field_type,
            )
            return TransformedValue(
                field_name=decision.field_name,
                action=action.value,
                value=generalized,
                transformation_type=TransformationType.GENERALIZE.value,
                original_hash=original_hash,
                preview=str(generalized)[:_PREVIEW_LIMIT],
                source_value=value,
            )

        if action is PolicyAction.TOKENIZE:
            token = self.token_vault.tokenize(value, session_id=session_id)
            return TransformedValue(
                field_name=decision.field_name,
                action=action.value,
                value=token,
                transformation_type=TransformationType.TOKENIZE.value,
                original_hash=original_hash,
                preview=token,
                source_value=value,
            )

        # AGGREGATE is applied by the connector to a value list, not here.
        raise ValueError(f"Cannot transform a single value for action {action}")

    # ── Record level ────────────────────────────────────────────────

    def transform_records(
        self,
        records: Sequence[dict[str, Any]],
        decisions: Sequence[FieldDecision],
        *,
        session_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[TransformedValue]]:
        """Transform fetched records, returning ``(records, audit entries)``.

        Only fields the policy decision granted are included in the output;
        non-granted fields are impossible to leak because they were never
        fetched, and are dropped here anyway. The internal surrogate ``id``
        column is always removed. Aggregate entries never reach this path —
        statistics are computed by the connector.
        """
        granted = [
            decision
            for decision in decisions
            if decision.requires_retrieval
            and decision.action is not PolicyAction.AGGREGATE
        ]
        if not granted:
            return [], []
        transformed: list[TransformedValue] = []
        output: list[dict[str, Any]] = []
        for record in records:
            row: dict[str, Any] = {}
            for decision in granted:
                column = decision.column_name or decision.field_name
                if column not in record:
                    continue
                outcome = self.transform_value(
                    record.get(column), decision, session_id=session_id
                )
                transformed.append(outcome)
                row[decision.field_name] = outcome.value
            output.append(row)
        return output, transformed

    # ── Aggregation ─────────────────────────────────────────────────

    def aggregate_values(self, values: Sequence[Any]) -> AggregateResult | None:
        """Statistics or ``None`` below the configured minimum group size."""
        return compute_aggregate(values, min_group_size=self.min_group_size)
