"""Output Privacy Guard — the second line of defense for model output.

The guard inspects natural-language text produced by an LLM provider *after*
the deterministic policy pipeline already decided what the model was allowed
to see. It is deliberately **not** an authorization mechanism:

* Authorization happens before retrieval; the guard never re-grants anything.
* The model only ever receives approved, transformed values (see
  :mod:`app.services.llm_adapter`), so a clean output is expected.
* The guard exists to catch leakage that slips past the first line:
  hallucinated PII, raw values of fields that were masked/generalized/
  tokenized, and providers re-introducing protected source values.

Detection is deterministic (no NLP dependency, no LLM):

1. The pattern catalogue from :mod:`app.services.classifier`
   (SSN, credit card + Luhn, email, phone, API key, password,
   date of birth) plus a guard-specific street-address rule.
2. **Permitted-disclosure set** — every value that was actually in the
   approved model context. A detection that matches an approved value is
   recorded but *not* redacted (it was authorized).
3. **Protected source values** — the raw originals behind values that were
   masked, generalized, or tokenized. If any of them appears in the output
   it is unauthorized by construction and is always redacted.

Configured policy (``LLM_OUTPUT_GUARD_MODE``) decides what happens when a
finding is not permitted:

* ``redact`` (default) — replace the span with ``[REDACTED-<CATEGORY>]``
  and return the sanitized text.
* ``reject`` — withhold the model response entirely (``text = None``).
* ``escalate`` — withhold the response and require human review.

Fail-closed guarantees:

* If the guard itself cannot complete, callers must not return the raw
  text; :class:`~app.services.llm_adapter.SafeLLMService` withholds the
  response and reports ``OUTPUT_GUARD_ERROR``.
* An unknown configured mode degrades to ``reject``.
* Output longer than the scan limit is truncated with a marker so an
  unscanned tail is never returned.

Findings carry category, rule id, span positions, and the redaction
placeholder — **never the matched text itself**, so guard metadata can be
persisted and returned without leaking values.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence, Tuple

from app.schemas.classifier import DataCategory
from app.services.classifier import TEXT_RULES, TextPatternRule

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Reason codes (guard-level; distinct from policy-engine reason codes)
# ──────────────────────────────────────────────────────────────────────

GUARD_REASON_CLEAN = "OUTPUT_CLEAN"
GUARD_REASON_REDACTED = "OUTPUT_PII_REDACTED"
GUARD_REASON_REJECTED = "OUTPUT_REJECTED"
GUARD_REASON_ESCALATED = "OUTPUT_GUARD_ESCALATED"
GUARD_REASON_DISABLED = "OUTPUT_GUARD_DISABLED"
GUARD_REASON_ERROR = "OUTPUT_GUARD_ERROR"
GUARD_REASON_TRUNCATED = "OUTPUT_TRUNCATED"

#: Guard actions (returned per inspection).
GUARD_ACTION_NONE = "none"
GUARD_ACTION_REDACTED = "redacted"
GUARD_ACTION_REJECTED = "rejected"
GUARD_ACTION_ESCALATED = "escalated"
GUARD_ACTION_DISABLED = "disabled"
GUARD_ACTION_ERROR = "error"

#: Configured guard modes, in increasing severity.
GUARD_MODES = ("redact", "reject", "escalate")
_DEFAULT_MODE = "redact"
#: Unknown configuration must never weaken the guard.
_FAILSAFE_MODE = "reject"

#: Generic placeholder for a protected source value (no category known).
GENERIC_REDACTION = "[REDACTED]"
#: Marker appended when output exceeds the scan limit (tail is dropped).
TRUNCATION_MARKER = "\n[output truncated by the privacy guard]"

#: Source values shorter than this are not searched for (too noisy to match
#: meaningfully — e.g. single digits would redact arbitrary text).
_MIN_PROTECTED_VALUE_LENGTH = 4

#: Guard-specific street address rule (house number + street suffix).
#: Presidio-style NLP would be a signal only; this deterministic pattern is
#: what the guard acts on. House numbers and suffixes keep false positives
#: low ("456 Oak Street", "1200 Foundry Road", "17 Data Mesa Court").
ADDRESS_RULE = TextPatternRule(
    "address_street",
    re.compile(
        r"\b\d{1,6}\s+(?:[A-Z][A-Za-z'.\-]*\s+){0,4}"
        r"(?:Street|Avenue|Road|Lane|Drive|Court|Way|Place|Boulevard|"
        r"Terrace|Circle|Path|Trail|Parkway|Highway|Square|Row|Walk|"
        r"Grove|Point|Ridge|Run|Hollow|Loop|Mews|Inlet|Plaza|Tower|"
        r"St|Ave|Rd|Ln|Dr|Ct|Pl|Blvd|Cir|Pkwy|Hwy|Sq)\.?"
        r"(?=[\s,.!?]|$)",
        re.MULTILINE,
    ),
    DataCategory.ADDRESS,
    0.8,
)

#: The rules the guard evaluates, in priority order (first match wins for
#: overlapping spans). Guard-specific rules come first so an address with a
#: house number is not partially consumed by the loose phone pattern.
_GUARD_RULES: tuple[TextPatternRule, ...] = (ADDRESS_RULE, *TEXT_RULES)

#: Category → redaction placeholder token.
_PLACEHOLDER_BY_CATEGORY: dict[str, str] = {
    category.value: f"[REDACTED-{category.value.upper().replace('_', '-')}]"
    for category in DataCategory
}
_PLACEHOLDER_BY_CATEGORY.setdefault("protected_value", GENERIC_REDACTION)


def placeholder_for(category: str | None) -> str:
    """Return the redaction token for a category (safe to store/return)."""
    return _PLACEHOLDER_BY_CATEGORY.get(
        (category or "").strip().lower(), GENERIC_REDACTION
    )


@dataclass(frozen=True)
class GuardFinding:
    """One inspection finding — metadata only, never the matched text."""

    category: str
    rule_id: str
    permitted: bool
    start: int
    end: int
    redacted_as: str | None = None
    value_length: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "rule": self.rule_id,
            "permitted": self.permitted,
            "start": self.start,
            "end": self.end,
            "redacted_as": self.redacted_as,
        }


@dataclass
class GuardResult:
    """Outcome of one output inspection."""

    text: str | None
    triggered: bool = False
    action: str = GUARD_ACTION_NONE
    reason_code: str | None = None
    findings: list[GuardFinding] = field(default_factory=list)
    error: str | None = None

    @property
    def redacted_count(self) -> int:
        return sum(1 for finding in self.findings if not finding.permitted)

    def to_dict(self) -> dict[str, Any]:
        return {
            "triggered": self.triggered,
            "action": self.action,
            "reason_code": self.reason_code,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class _Candidate:
    """A span proposed for redaction (before overlap resolution)."""

    start: int
    end: int
    category: str
    rule_id: str
    placeholder: str

    @property
    def length(self) -> int:
        return self.end - self.start


class OutputPrivacyGuard:
    """Deterministic output inspection with configurable enforcement."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        mode: str = _DEFAULT_MODE,
        max_scan_chars: int = 100_000,
        detector: Callable[[str, Sequence[Tuple[int, int]]], Iterable[Any]]
        | None = None,
    ):
        self.enabled = bool(enabled)
        raw_mode = (mode or _DEFAULT_MODE).strip().lower()
        if raw_mode not in GUARD_MODES:
            logger.warning(
                "Unknown LLM output guard mode '%s'; failing closed to '%s'",
                raw_mode,
                _FAILSAFE_MODE,
            )
            raw_mode = _FAILSAFE_MODE
        self.mode = raw_mode
        self.max_scan_chars = max(int(max_scan_chars), 1_000)
        #: Optional additional detector hook ``(text, occupied_spans) ->
        #: iterable`` used by tests or future NLP signal integration.
        self.detector = detector

    # ── Construction helpers ────────────────────────────────────────

    @classmethod
    def from_settings(cls, settings_obj: Any) -> "OutputPrivacyGuard":
        return cls(
            enabled=bool(
                getattr(settings_obj, "LLM_OUTPUT_GUARD_ENABLED", True)
            ),
            mode=str(
                getattr(settings_obj, "LLM_OUTPUT_GUARD_MODE", _DEFAULT_MODE)
                or _DEFAULT_MODE
            ),
            max_scan_chars=int(
                getattr(settings_obj, "LLM_MAX_OUTPUT_CHARS", 100_000)
                or 100_000
            ),
        )

    def status(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "mode": self.mode}

    # ── Public API ──────────────────────────────────────────────────

    def inspect(
        self,
        text: str | None,
        *,
        allowed_values: Sequence[Any] = (),
        protected_values: Sequence[Any] = (),
    ) -> GuardResult:
        """Inspect ``text`` against the permitted set and protected values.

        Returns a :class:`GuardResult` whose ``text`` is the value that may
        be returned to the caller (``None`` when the configured mode
        withholds it).
        """
        if text is None or not str(text).strip():
            return GuardResult(text=text)

        if not self.enabled:
            return GuardResult(
                text=text,
                triggered=False,
                action=GUARD_ACTION_DISABLED,
                reason_code=GUARD_REASON_DISABLED,
            )

        original = str(text)
        scan_text = original[: self.max_scan_chars]
        truncated = len(original) > self.max_scan_chars

        allowed_lower = tuple(
            str(value).strip().lower()
            for value in allowed_values
            if value is not None and str(value).strip()
        )

        findings: list[GuardFinding] = []
        candidates: list[_Candidate] = []

        occupied: list[tuple[int, int]] = []

        # 1. Pattern-based sensitive categories.
        for rule in _GUARD_RULES:
            category = (
                rule.category.value
                if isinstance(rule.category, DataCategory)
                else str(rule.category)
            )
            placeholder = placeholder_for(category)
            for match in rule.pattern.finditer(scan_text):
                start, end = match.span(rule.value_group)
                if start < 0 or end <= start:
                    continue
                if _overlaps_spans(occupied, start, end):
                    continue
                span_text = scan_text[start:end]
                if rule.validate is not None and not rule.validate(span_text):
                    continue
                occupied.append((start, end))
                permitted = _is_permitted(span_text, allowed_lower)
                if permitted:
                    findings.append(
                        GuardFinding(
                            category=category,
                            rule_id=rule.rule_id,
                            permitted=True,
                            start=start,
                            end=end,
                            value_length=len(span_text),
                        )
                    )
                    continue
                findings.append(
                    GuardFinding(
                        category=category,
                        rule_id=rule.rule_id,
                        permitted=False,
                        start=start,
                        end=end,
                        redacted_as=placeholder,
                        value_length=len(span_text),
                    )
                )
                candidates.append(
                    _Candidate(start, end, category, rule.rule_id, placeholder)
                )

        # 2. Protected source values (raw originals of transformed fields).
        protected_lower = _normalised_variants(protected_values)
        if protected_lower:
            lowered_scan = scan_text.lower()
            for variant in protected_lower:
                search_from = 0
                while True:
                    index = lowered_scan.find(variant, search_from)
                    if index < 0:
                        break
                    end = index + len(variant)
                    search_from = index + 1
                    if _overlaps_spans(occupied, index, end):
                        continue
                    if _covered_by_allowed(
                        scan_text[index:end], allowed_lower
                    ):
                        # The raw value appears inside an approved value
                        # (e.g. it was authorized raw) — not a leak.
                        continue
                    occupied.append((index, end))
                    findings.append(
                        GuardFinding(
                            category="protected_value",
                            rule_id="protected_source_value",
                            permitted=False,
                            start=index,
                            end=end,
                            redacted_as=GENERIC_REDACTION,
                            value_length=len(variant),
                        )
                    )
                    candidates.append(
                        _Candidate(
                            index,
                            end,
                            "protected_value",
                            "protected_source_value",
                            GENERIC_REDACTION,
                        )
                    )

        # 3. Optional extension detector (signal only; must not re-grant).
        if self.detector is not None:
            for item in self.detector(scan_text, tuple(occupied)):
                start = int(getattr(item, "start", -1))
                end = int(getattr(item, "end", -1))
                category = str(getattr(item, "category", "unknown"))
                if start < 0 or end <= start:
                    continue
                if _overlaps_spans(occupied, start, end):
                    continue
                occupied.append((start, end))
                permitted = _is_permitted(scan_text[start:end], allowed_lower)
                placeholder = placeholder_for(category)
                findings.append(
                    GuardFinding(
                        category=category,
                        rule_id=str(getattr(item, "rule_id", "detector")),
                        permitted=permitted,
                        start=start,
                        end=end,
                        redacted_as=None if permitted else placeholder,
                        value_length=end - start,
                    )
                )
                if not permitted:
                    candidates.append(
                        _Candidate(start, end, category, "detector", placeholder)
                    )

        # 4. Apply the configured enforcement policy.
        violations = [finding for finding in findings if not finding.permitted]
        if truncated:
            findings.append(
                GuardFinding(
                    category="output_length",
                    rule_id="max_scan_length",
                    permitted=False,
                    start=self.max_scan_chars,
                    end=len(original),
                    redacted_as="[TRUNCATED]",
                )
            )
            violations.append(findings[-1])

        if not violations:
            return GuardResult(
                text=original,
                triggered=False,
                action=GUARD_ACTION_NONE,
                reason_code=GUARD_REASON_CLEAN,
                findings=findings,
            )

        if self.mode == "redact":
            sanitized = _apply_redactions(scan_text, candidates)
            if truncated:
                sanitized += TRUNCATION_MARKER
            return GuardResult(
                text=sanitized,
                triggered=True,
                action=GUARD_ACTION_REDACTED,
                reason_code=(
                    GUARD_REASON_TRUNCATED
                    if truncated and not candidates
                    else GUARD_REASON_REDACTED
                ),
                findings=findings,
            )

        # reject / escalate: withhold the response entirely.
        action = (
            GUARD_ACTION_REJECTED
            if self.mode == "reject"
            else GUARD_ACTION_ESCALATED
        )
        reason = (
            GUARD_REASON_REJECTED
            if self.mode == "reject"
            else GUARD_REASON_ESCALATED
        )
        return GuardResult(
            text=None,
            triggered=True,
            action=action,
            reason_code=reason,
            findings=findings,
        )


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _overlaps_spans(
    spans: Sequence[tuple[int, int]], start: int, end: int
) -> bool:
    """True when ``(start, end)`` overlaps any recorded span."""
    for span_start, span_end in spans:
        if start < span_end and span_start < end:
            return True
    return False


def _is_permitted(span_text: str, allowed_lower: Sequence[str]) -> bool:
    """Was this span explicitly authorized for disclosure?"""
    needle = span_text.strip().lower()
    if not needle:
        return False
    return any(needle in allowed for allowed in allowed_lower)


def _covered_by_allowed(span_text: str, allowed_lower: Sequence[str]) -> bool:
    """True when the raw value itself appears inside an approved value."""
    needle = span_text.strip().lower()
    if not needle:
        return False
    return any(needle in allowed for allowed in allowed_lower)


def _normalised_variants(values: Sequence[Any]) -> list[str]:
    """Build lowercase search variants for source values.

    Numeric values get an integer variant as well so a generalised
    ``62000.00`` is still caught when the model prints ``62000``.
    """
    variants: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if len(text) < _MIN_PROTECTED_VALUE_LENGTH:
            continue
        variants.add(text.lower())
        # Decimal-like values: also search the trimmed integer form.
        candidate = text[:-3] if text.endswith(".00") else None
        if candidate is not None and len(candidate) >= _MIN_PROTECTED_VALUE_LENGTH:
            variants.add(candidate.lower())
    return sorted(variants, key=len, reverse=True)


def _apply_redactions(
    text: str, candidates: Sequence[_Candidate]
) -> str:
    """Replace candidate spans with placeholders (no overlap)."""
    if not candidates:
        return text
    ordered = sorted(candidates, key=lambda c: (c.start, -c.end))
    selected: list[_Candidate] = []
    occupied: list[tuple[int, int]] = []
    for candidate in ordered:
        if _overlaps_spans(occupied, candidate.start, candidate.end):
            continue
        occupied.append((candidate.start, candidate.end))
        selected.append(candidate)
    result = text
    for candidate in sorted(selected, key=lambda c: c.start, reverse=True):
        result = (
            result[: candidate.start]
            + candidate.placeholder
            + result[candidate.end :]
        )
    return result


__all__ = [
    "ADDRESS_RULE",
    "GENERIC_REDACTION",
    "GUARD_ACTION_DISABLED",
    "GUARD_ACTION_ESCALATED",
    "GUARD_ACTION_ERROR",
    "GUARD_ACTION_NONE",
    "GUARD_ACTION_REDACTED",
    "GUARD_ACTION_REJECTED",
    "GUARD_MODES",
    "GUARD_REASON_CLEAN",
    "GUARD_REASON_DISABLED",
    "GUARD_REASON_ERROR",
    "GUARD_REASON_ESCALATED",
    "GUARD_REASON_REDACTED",
    "GUARD_REASON_REJECTED",
    "GUARD_REASON_TRUNCATED",
    "GuardFinding",
    "GuardResult",
    "OutputPrivacyGuard",
    "placeholder_for",
]
