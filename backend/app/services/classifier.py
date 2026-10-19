"""Sensitive-data classification engine.

Classifies structured fields, documents, and free text into
:class:`~app.schemas.classifier.DataCategory` values with a sensitivity
level, confidence, detection method, and recommended handling — no raw
values ever appear in the output.

Trust model (see ``docs/security-model.md`` §5):

1. **Database schema annotations are authoritative.** When a field has
   metadata, its sensitivity wins over every heuristic.
2. **Deterministic rules are high-confidence.** A catalogue of configured
   business field names (salary, ssn, bank_account, …) plus precise text
   patterns (SSN, credit card + Luhn, email, phone, API keys, …) covers
   the data a text classifier cannot reliably identify.
3. **NLP (Presidio + spaCy) is a signal only.** It supplements the two
   layers above for free text; it can never downgrade an authoritative
   classification, and a detector failure degrades gracefully to
   deterministic-only mode.

Conservative uncertainty policy (documented, fail-closed):

* A structured field with no annotation and no rule match is treated as
  ``CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY`` (default ``high``) with
  handling ``CLASSIFIER_UNCERTAIN_HANDLING`` (default ``escalate``).
  It is *never* assumed safe.
* A detection whose confidence is below
  ``CLASSIFIER_UNCERTAINTY_THRESHOLD`` is reported but its recommended
  handling is raised to at least ``escalate`` (hard-block categories
  stay ``block``), and the result is marked ``uncertain``.

The recommended handling is guidance for the policy engine, not an
authorization decision. Classification is not a permission check.

This module is intentionally free of database access so it can be tested
in isolation; :mod:`app.services.classification_service` adapts it to
database metadata.
"""

import hashlib
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Literal, Protocol, Sequence

from app.core.config import settings
from app.models import SensitivityLevel
from app.schemas.classifier import (
    ClassifiedField,
    ClassificationResult,
    DataCategory,
    DetectionMethod,
    RecommendedHandling,
)

logger = logging.getLogger("contextshield.classifier")

#: Upper bound on the number of characters scanned per text (DoS guard).
MAX_TEXT_SCAN_CHARS = 20_000

# ──────────────────────────────────────────────────────────────────────
# Sensitivity levels and labels
# ──────────────────────────────────────────────────────────────────────

#: Ordering used whenever "highest sensitivity" is computed.
SENSITIVITY_ORDER: dict[SensitivityLevel, int] = {
    SensitivityLevel.LOW: 0,
    SensitivityLevel.MEDIUM: 1,
    SensitivityLevel.HIGH: 2,
    SensitivityLevel.RESTRICTED: 3,
}

#: Canonical labels — identical to the database enum values.
_STANDARD_LABELS: dict[SensitivityLevel, str] = {
    SensitivityLevel.LOW: "low",
    SensitivityLevel.MEDIUM: "medium",
    SensitivityLevel.HIGH: "high",
    SensitivityLevel.RESTRICTED: "restricted",
}

#: Business-facing labels for the same four levels.
_BUSINESS_LABELS: dict[SensitivityLevel, str] = {
    SensitivityLevel.LOW: "public",
    SensitivityLevel.MEDIUM: "internal",
    SensitivityLevel.HIGH: "confidential",
    SensitivityLevel.RESTRICTED: "restricted",
}

_LABEL_SCHEMES: dict[str, dict[SensitivityLevel, str]] = {
    "standard": _STANDARD_LABELS,
    "business": _BUSINESS_LABELS,
}

#: Accepts canonical names and business aliases, case-insensitively.
_SENSITIVITY_ALIASES: dict[str, SensitivityLevel] = {
    "low": SensitivityLevel.LOW,
    "public": SensitivityLevel.LOW,
    "medium": SensitivityLevel.MEDIUM,
    "internal": SensitivityLevel.MEDIUM,
    "high": SensitivityLevel.HIGH,
    "confidential": SensitivityLevel.HIGH,
    "restricted": SensitivityLevel.RESTRICTED,
}


def resolve_sensitivity(value: SensitivityLevel | str) -> SensitivityLevel:
    """Resolve a sensitivity level from canonical names or business aliases."""
    if isinstance(value, SensitivityLevel):
        return value
    try:
        return _SENSITIVITY_ALIASES[str(value).strip().lower()]
    except KeyError as exc:
        raise ValueError(f"Unknown sensitivity level: {value!r}") from exc


def sensitivity_label(
    level: SensitivityLevel, scheme: str | None = None
) -> str:
    """Return the configured presentation label for a sensitivity level."""
    name = (scheme or settings.SENSITIVITY_LABEL_SCHEME).strip().lower()
    table = _LABEL_SCHEMES.get(name, _BUSINESS_LABELS)
    return table[level]


#: Restrictiveness ordering from the privacy-policies document.
_HANDLING_ORDER: dict[RecommendedHandling, int] = {
    RecommendedHandling.ALLOW: 0,
    RecommendedHandling.TOKENIZE: 1,
    RecommendedHandling.MASK: 2,
    RecommendedHandling.GENERALIZE: 3,
    RecommendedHandling.AGGREGATE: 4,
    RecommendedHandling.ESCALATE: 5,
    RecommendedHandling.BLOCK: 6,
}

#: Minimum handling implied by a sensitivity level.
_HANDLING_FLOOR: dict[SensitivityLevel, RecommendedHandling] = {
    SensitivityLevel.LOW: RecommendedHandling.ALLOW,
    SensitivityLevel.MEDIUM: RecommendedHandling.ALLOW,
    SensitivityLevel.HIGH: RecommendedHandling.MASK,
    SensitivityLevel.RESTRICTED: RecommendedHandling.ESCALATE,
}


def most_restrictive(*handlings: RecommendedHandling) -> RecommendedHandling:
    """Return the most restrictive of the given handlings."""
    return max(handlings, key=lambda h: _HANDLING_ORDER[h])


#: Business-document classification labels → (sensitivity, base handling).
_DOCUMENT_LABELS: dict[str, tuple[SensitivityLevel, RecommendedHandling]] = {
    "public": (SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    "internal": (SensitivityLevel.MEDIUM, RecommendedHandling.ESCALATE),
    "confidential": (SensitivityLevel.HIGH, RecommendedHandling.ESCALATE),
    "restricted": (SensitivityLevel.RESTRICTED, RecommendedHandling.BLOCK),
}


# ──────────────────────────────────────────────────────────────────────
# Category profiles
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CategoryProfile:
    """Default classification attributes for one data category."""

    category: DataCategory
    sensitivity: SensitivityLevel
    handling: RecommendedHandling
    description: str
    aliases: tuple[str, ...] = ()


CATEGORY_PROFILES: dict[DataCategory, CategoryProfile] = {
    profile.category: profile
    for profile in (
        # ── Personal / direct identifiers ───────────────────────────
        CategoryProfile(
            DataCategory.PERSON_NAME, SensitivityLevel.MEDIUM,
            RecommendedHandling.ALLOW,
            "Personal name", ("person_name", "name", "full_name", "contact_name"),
        ),
        CategoryProfile(
            DataCategory.EMAIL, SensitivityLevel.MEDIUM,
            RecommendedHandling.MASK,
            "Email address", ("email", "email_address", "contact_email"),
        ),
        CategoryProfile(
            DataCategory.PHONE, SensitivityLevel.HIGH,
            RecommendedHandling.MASK,
            "Telephone number", ("phone", "phone_number", "telephone", "mobile"),
        ),
        CategoryProfile(
            DataCategory.ADDRESS, SensitivityLevel.HIGH,
            RecommendedHandling.MASK,
            "Postal address",
            ("address", "location", "billing_address", "shipping_address"),
        ),
        CategoryProfile(
            DataCategory.DATE_OF_BIRTH, SensitivityLevel.HIGH,
            RecommendedHandling.GENERALIZE,
            "Date of birth", ("date_of_birth", "dob", "birthdate"),
        ),
        CategoryProfile(
            DataCategory.SSN, SensitivityLevel.RESTRICTED,
            RecommendedHandling.BLOCK,
            "Social Security Number",
            ("ssn", "social_security_number", "social_security"),
        ),
        CategoryProfile(
            DataCategory.GOVERNMENT_ID, SensitivityLevel.RESTRICTED,
            RecommendedHandling.BLOCK,
            "Government-issued identifier (passport, driver licence, …)",
            ("government_id", "passport", "driver_license", "national_id"),
        ),
        CategoryProfile(
            DataCategory.MEDICAL_RECORD, SensitivityLevel.RESTRICTED,
            RecommendedHandling.BLOCK,
            "Medical / health information",
            ("medical_record", "medical", "health_record", "diagnosis"),
        ),
        CategoryProfile(
            DataCategory.CREDIT_CARD, SensitivityLevel.RESTRICTED,
            RecommendedHandling.BLOCK,
            "Payment card number",
            ("credit_card", "card_number", "cc_number"),
        ),
        CategoryProfile(
            DataCategory.BANK_ACCOUNT, SensitivityLevel.RESTRICTED,
            RecommendedHandling.BLOCK,
            "Bank account / IBAN",
            ("bank_account", "iban", "account_number"),
        ),
        CategoryProfile(
            DataCategory.PASSWORD, SensitivityLevel.RESTRICTED,
            RecommendedHandling.BLOCK,
            "Password or passphrase",
            ("password", "passwd", "pwd"),
        ),
        CategoryProfile(
            DataCategory.API_KEY, SensitivityLevel.RESTRICTED,
            RecommendedHandling.BLOCK,
            "API key, access token, or client secret",
            ("api_key", "apikey", "access_token", "secret_key"),
        ),
        # ── Structured business data ────────────────────────────────
        CategoryProfile(
            DataCategory.SALARY, SensitivityLevel.RESTRICTED,
            RecommendedHandling.ESCALATE,
            "Compensation data (salary, bonus, pay grade)",
            ("salary", "compensation", "payroll", "bonus", "pay_grade"),
        ),
        CategoryProfile(
            DataCategory.EMPLOYEE_HR_RECORD, SensitivityLevel.HIGH,
            RecommendedHandling.ESCALATE,
            "Employee HR / employment record",
            ("employee_hr_record", "employee_record", "hr_record"),
        ),
        CategoryProfile(
            DataCategory.CUSTOMER_ACCOUNT, SensitivityLevel.MEDIUM,
            RecommendedHandling.MASK,
            "Customer account data",
            ("customer_account", "customer_number", "account_tier", "account_status"),
        ),
        CategoryProfile(
            DataCategory.ORDER_DATA, SensitivityLevel.MEDIUM,
            RecommendedHandling.ALLOW,
            "Customer order data",
            ("order_data", "order_number", "order_status", "order_total"),
        ),
        CategoryProfile(
            DataCategory.INTERNAL_FINANCIAL, SensitivityLevel.RESTRICTED,
            RecommendedHandling.ESCALATE,
            "Internal financial information (revenue, budget, margin)",
            ("internal_financial", "revenue", "financial", "budget"),
        ),
        CategoryProfile(
            DataCategory.CONFIDENTIAL_DOCUMENT, SensitivityLevel.RESTRICTED,
            RecommendedHandling.BLOCK,
            "Confidential business document",
            ("confidential_document", "document", "contract"),
        ),
        CategoryProfile(
            DataCategory.UNKNOWN, SensitivityLevel.HIGH,
            RecommendedHandling.ESCALATE,
            "Unclassified data (conservative default applied)",
            (),
        ),
    )
}

_ALIAS_TO_CATEGORY: dict[str, DataCategory] = {
    alias: profile.category
    for profile in CATEGORY_PROFILES.values()
    for alias in profile.aliases
}


def _handling_for(
    category: DataCategory, sensitivity: SensitivityLevel
) -> RecommendedHandling:
    """Category default handling, raised by the sensitivity floor.

    The floor ensures a mis-annotated (or newly annotated) field can never
    end up with a handling weaker than its sensitivity implies.
    """
    profile = CATEGORY_PROFILES[category]
    return most_restrictive(profile.handling, _HANDLING_FLOOR[sensitivity])


# ──────────────────────────────────────────────────────────────────────
# Deterministic field-name catalogue
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FieldRule:
    """One deterministic business-field rule.

    ``tokens`` must all appear as whole tokens in the normalised field
    name (e.g. ``{"bank", "account"}`` matches ``bank_account_last4``).
    """

    rule_id: str
    tokens: frozenset[str]
    category: DataCategory
    sensitivity: SensitivityLevel | None = None  # None → category default
    handling: RecommendedHandling | None = None
    confidence: float = 0.9


def _rule(
    rule_id: str,
    tokens: Sequence[str],
    category: DataCategory,
    sensitivity: SensitivityLevel | None = None,
    handling: RecommendedHandling | None = None,
    confidence: float = 0.9,
) -> FieldRule:
    return FieldRule(rule_id, frozenset(tokens), category, sensitivity, handling, confidence)


#: Configured business-field catalogue. Order matters only for equal
#: specificity: the first matching rule with the longest token set wins.
FIELD_RULES: tuple[FieldRule, ...] = (
    # Employee / HR
    _rule("employee_number", ["employee", "number"], DataCategory.EMPLOYEE_HR_RECORD,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("employee_id", ["employee", "id"], DataCategory.EMPLOYEE_HR_RECORD,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("hire_date", ["hire", "date"], DataCategory.EMPLOYEE_HR_RECORD,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("department", ["department"], DataCategory.EMPLOYEE_HR_RECORD,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("title", ["title"], DataCategory.EMPLOYEE_HR_RECORD,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("manager_id", ["manager", "id"], DataCategory.EMPLOYEE_HR_RECORD,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("pay_grade", ["pay", "grade"], DataCategory.SALARY,
          SensitivityLevel.HIGH, RecommendedHandling.ESCALATE),
    _rule("salary", ["salary"], DataCategory.SALARY),
    _rule("bonus", ["bonus"], DataCategory.SALARY),
    _rule("compensation", ["compensation"], DataCategory.SALARY),
    _rule("payroll", ["payroll"], DataCategory.SALARY),
    _rule("pay_rate", ["pay", "rate"], DataCategory.SALARY),
    # Direct identifiers
    _rule("ssn", ["ssn"], DataCategory.SSN, confidence=0.95),
    _rule("social_security", ["social", "security"], DataCategory.SSN, confidence=0.95),
    _rule("date_of_birth", ["date", "birth"], DataCategory.DATE_OF_BIRTH,
          confidence=0.95),
    _rule("dob", ["dob"], DataCategory.DATE_OF_BIRTH, confidence=0.95),
    _rule("birthdate", ["birthdate"], DataCategory.DATE_OF_BIRTH, confidence=0.95),
    _rule("email", ["email"], DataCategory.EMAIL, confidence=0.95),
    _rule("phone", ["phone"], DataCategory.PHONE, confidence=0.95),
    _rule("mobile", ["mobile"], DataCategory.PHONE, confidence=0.95),
    _rule("telephone", ["telephone"], DataCategory.PHONE, confidence=0.95),
    _rule("address", ["address"], DataCategory.ADDRESS, confidence=0.95),
    _rule("street", ["street"], DataCategory.ADDRESS),
    _rule("passport", ["passport"], DataCategory.GOVERNMENT_ID),
    _rule("driver_license", ["driver", "license"], DataCategory.GOVERNMENT_ID),
    _rule("national_id", ["national", "id"], DataCategory.GOVERNMENT_ID),
    _rule("medical", ["medical"], DataCategory.MEDICAL_RECORD),
    _rule("diagnosis", ["diagnosis"], DataCategory.MEDICAL_RECORD),
    _rule("prescription", ["prescription"], DataCategory.MEDICAL_RECORD),
    _rule("patient", ["patient"], DataCategory.MEDICAL_RECORD),
    # Payment / secrets
    _rule("credit_card", ["credit", "card"], DataCategory.CREDIT_CARD, confidence=0.95),
    _rule("card_number", ["card", "number"], DataCategory.CREDIT_CARD, confidence=0.95),
    _rule("cvv", ["cvv"], DataCategory.CREDIT_CARD, confidence=0.95),
    _rule("bank_account", ["bank", "account"], DataCategory.BANK_ACCOUNT,
          confidence=0.95),
    _rule("account_number", ["account", "number"], DataCategory.BANK_ACCOUNT),
    _rule("iban", ["iban"], DataCategory.BANK_ACCOUNT, confidence=0.95),
    _rule("routing_number", ["routing", "number"], DataCategory.BANK_ACCOUNT),
    _rule("password", ["password"], DataCategory.PASSWORD, confidence=0.95),
    _rule("passwd", ["passwd"], DataCategory.PASSWORD, confidence=0.95),
    _rule("pwd", ["pwd"], DataCategory.PASSWORD, confidence=0.95),
    _rule("api_key", ["api", "key"], DataCategory.API_KEY, confidence=0.95),
    _rule("api_secret", ["api", "secret"], DataCategory.API_KEY, confidence=0.95),
    _rule("secret_key", ["secret", "key"], DataCategory.API_KEY, confidence=0.95),
    _rule("access_token", ["access", "token"], DataCategory.API_KEY, confidence=0.95),
    # Customer / order
    _rule("customer_number", ["customer", "number"], DataCategory.CUSTOMER_ACCOUNT,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("customer_id", ["customer", "id"], DataCategory.CUSTOMER_ACCOUNT,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("account_tier", ["account", "tier"], DataCategory.CUSTOMER_ACCOUNT,
          SensitivityLevel.MEDIUM, RecommendedHandling.MASK),
    _rule("account_status", ["account", "status"], DataCategory.CUSTOMER_ACCOUNT,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("company_name", ["company", "name"], DataCategory.CUSTOMER_ACCOUNT,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("order_number", ["order", "number"], DataCategory.ORDER_DATA,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("order_id", ["order", "id"], DataCategory.ORDER_DATA,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("order_date", ["order", "date"], DataCategory.ORDER_DATA,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("order_status", ["order", "status"], DataCategory.ORDER_DATA,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("total_amount", ["total", "amount"], DataCategory.ORDER_DATA,
          SensitivityLevel.MEDIUM, RecommendedHandling.ALLOW),
    # Finance / documents
    _rule("revenue", ["revenue"], DataCategory.INTERNAL_FINANCIAL),
    _rule("profit", ["profit"], DataCategory.INTERNAL_FINANCIAL),
    _rule("margin", ["margin"], DataCategory.INTERNAL_FINANCIAL),
    _rule("budget", ["budget"], DataCategory.INTERNAL_FINANCIAL),
    _rule("expense", ["expense"], DataCategory.INTERNAL_FINANCIAL),
    _rule("cost", ["cost"], DataCategory.INTERNAL_FINANCIAL),
    _rule("document_number", ["document", "number"], DataCategory.CONFIDENTIAL_DOCUMENT,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("document_id", ["document", "id"], DataCategory.CONFIDENTIAL_DOCUMENT,
          SensitivityLevel.LOW, RecommendedHandling.ALLOW),
    _rule("classification", ["classification"], DataCategory.CONFIDENTIAL_DOCUMENT,
          SensitivityLevel.MEDIUM, RecommendedHandling.MASK),
    _rule("content_summary", ["content", "summary"], DataCategory.CONFIDENTIAL_DOCUMENT,
          SensitivityLevel.HIGH, RecommendedHandling.MASK),
    _rule("summary", ["summary"], DataCategory.CONFIDENTIAL_DOCUMENT,
          SensitivityLevel.HIGH, RecommendedHandling.MASK),
    _rule("contract", ["contract"], DataCategory.CONFIDENTIAL_DOCUMENT,
          SensitivityLevel.HIGH, RecommendedHandling.ESCALATE),
)

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _normalise_tokens(name: str) -> tuple[str, ...]:
    return tuple(token for token in _TOKEN_SPLIT.split(name.lower()) if token)


def match_field_rule(field_name: str) -> FieldRule | None:
    """Return the most specific catalogue rule matching ``field_name``."""
    tokens = set(_normalise_tokens(field_name))
    best: FieldRule | None = None
    for rule in FIELD_RULES:
        if not rule.tokens <= tokens:
            continue
        if best is None or len(rule.tokens) > len(best.tokens):
            best = rule
    return best


def category_from_alias(value: str | None) -> DataCategory | None:
    """Map a schema ``pii_category`` / alias string to a category."""
    if not value:
        return None
    normalised = "_".join(_normalise_tokens(value))
    if not normalised:
        return None
    if normalised in _ALIAS_TO_CATEGORY:
        return _ALIAS_TO_CATEGORY[normalised]
    rule = match_field_rule(normalised)
    return rule.category if rule is not None else None


# ──────────────────────────────────────────────────────────────────────
# Deterministic free-text patterns
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TextPatternRule:
    """A precision-oriented regex rule for free-text detection."""

    rule_id: str
    pattern: re.Pattern[str]
    category: DataCategory
    confidence: float
    validate: Callable[[str], bool] | None = None
    #: Capture group holding the sensitive span (defaults to the match).
    value_group: int = 0


def _luhn(value: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _valid_ssn(value: str) -> bool:
    area, group, serial = value.split("-")
    return area != "000" and group != "00" and serial != "0000"


def _valid_intl_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 8 <= len(digits) <= 15:
        return False
    # Reject ISO-like dates (2026-10-18) captured by the loose pattern.
    return not re.fullmatch(r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}", value.strip())


TEXT_RULES: tuple[TextPatternRule, ...] = (
    TextPatternRule(
        "email",
        re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        DataCategory.EMAIL,
        0.99,
    ),
    TextPatternRule(
        "ssn_dashed",
        re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b"),
        DataCategory.SSN,
        0.95,
        validate=_valid_ssn,
    ),
    TextPatternRule(
        "credit_card",
        re.compile(r"\b\d(?:[ -]?\d){12,18}\b"),
        DataCategory.CREDIT_CARD,
        0.98,
        validate=_luhn,
    ),
    TextPatternRule(
        "phone_us_intl",
        re.compile(r"\+1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        DataCategory.PHONE,
        0.9,
    ),
    TextPatternRule(
        "phone_us_parens",
        re.compile(r"\(\d{3}\)\s?\d{3}[-.\s]\d{4}\b"),
        DataCategory.PHONE,
        0.9,
    ),
    TextPatternRule(
        "phone_us_dashed",
        re.compile(r"\b\d{3}-\d{3}-\d{4}\b"),
        DataCategory.PHONE,
        0.9,
    ),
    TextPatternRule(
        "phone_intl",
        re.compile(r"\+\d{1,3}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b"),
        DataCategory.PHONE,
        0.8,
        validate=_valid_intl_phone,
    ),
    TextPatternRule(
        "api_key_prefixed",
        re.compile(
            r"\b(?:sk|pk|rk)-[A-Za-z0-9]{12,}\b"
            r"|\b(?:ghp|gho|ghu|ghs|glpat)_[A-Za-z0-9_\-]{12,}\b"
            r"|\b(?:xoxb|xoxp|xoxa|xoxr)-[A-Za-z0-9\-]{10,}\b"
            r"|\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b"
            r"|\bcsk_[A-Za-z0-9_\-]{16,}\b"
        ),
        DataCategory.API_KEY,
        0.9,
    ),
    TextPatternRule(
        "api_key_assignment",
        re.compile(
            r"(?i)\b(?:api[_\- ]?key|secret[_\- ]?key|access[_\- ]?token)\b"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{12,})"
        ),
        DataCategory.API_KEY,
        0.85,
        value_group=1,
    ),
    TextPatternRule(
        "password_assignment",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*[\"']?(\S{3,})"),
        DataCategory.PASSWORD,
        0.85,
        value_group=1,
    ),
    TextPatternRule(
        "date_of_birth",
        re.compile(
            r"(?i)\b(?:born|birth\s*date|date\s*of\s*birth|dob)\b[^\d\n]{0,15}?"
            r"(\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|\d{4}[-/.]\d{1,2}[-/.]\d{1,2})"
        ),
        DataCategory.DATE_OF_BIRTH,
        0.85,
        value_group=1,
    ),
)


def _overlaps(spans: Sequence[tuple[int, int]], start: int, end: int) -> bool:
    return any(not (end <= s or start >= e) for s, e in spans)


_DOB_CONTEXT = re.compile(r"(?i)\b(?:born|birth|dob)\b")


def _has_dob_context(text: str, start: int) -> bool:
    window = text[max(0, start - 40) : start]
    return bool(_DOB_CONTEXT.search(window))


# ──────────────────────────────────────────────────────────────────────
# NLP detector (Presidio + spaCy)
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class NlpEntity:
    """One entity reported by an NLP engine (offsets into the scanned text)."""

    entity_type: str
    start: int
    end: int
    score: float


class NlpDetector(Protocol):
    """Minimal interface a PII detector must implement (injectable in tests)."""

    name: str

    def analyze(self, text: str) -> Sequence[NlpEntity]:  # pragma: no cover
        ...


#: Presidio entity types → internal categories. Entity types not listed
#: here are ignored (they are not sensitive for our purposes).
_PRESIDIO_ENTITY_MAP: dict[str, DataCategory] = {
    "PERSON": DataCategory.PERSON_NAME,
    "EMAIL_ADDRESS": DataCategory.EMAIL,
    "PHONE_NUMBER": DataCategory.PHONE,
    "US_SSN": DataCategory.SSN,
    "US_ITIN": DataCategory.GOVERNMENT_ID,
    "US_PASSPORT": DataCategory.GOVERNMENT_ID,
    "US_DRIVER_LICENSE": DataCategory.GOVERNMENT_ID,
    "MEDICAL_LICENSE": DataCategory.GOVERNMENT_ID,
    "CREDIT_CARD": DataCategory.CREDIT_CARD,
    "US_BANK_NUMBER": DataCategory.BANK_ACCOUNT,
    "IBAN_CODE": DataCategory.BANK_ACCOUNT,
    "LOCATION": DataCategory.ADDRESS,
}


class PresidioDetector:
    """Thin adapter around a configured Presidio ``AnalyzerEngine``."""

    def __init__(self, engine, *, model_name: str, language: str, score_threshold: float):
        self._engine = engine
        self.model_name = model_name
        self.language = language
        self.score_threshold = score_threshold
        self.name = f"presidio+spacy:{model_name}"

    def analyze(self, text: str) -> Sequence[NlpEntity]:
        results = self._engine.analyze(
            text=text,
            language=self.language,
            score_threshold=self.score_threshold,
        )
        return [
            NlpEntity(
                entity_type=result.entity_type,
                start=int(result.start),
                end=int(result.end),
                score=float(result.score),
            )
            for result in results
        ]


@lru_cache(maxsize=8)
def build_presidio_detector(
    model_name: str, language: str, score_threshold: float
) -> NlpDetector | None:
    """Build a Presidio detector, or return ``None`` on any failure.

    Failures (missing libraries, missing spaCy model, engine errors) are
    logged once and degrade the classifier to deterministic-only mode —
    classification never fails open because NLP is unavailable.
    """
    try:
        import spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except Exception as exc:  # pragma: no cover - depends on environment
        logger.warning("classifier_nlp_unavailable reason=import_failed error=%s", exc)
        return None

    installed = spacy.util.get_installed_models()
    candidates = [model_name, "en_core_web_lg", "en_core_web_md", "en_core_web_sm"]
    resolved = next((name for name in candidates if name in installed), None)
    if resolved is None:
        logger.warning(
            "classifier_nlp_unavailable reason=no_spacy_model configured=%s installed=%s",
            model_name,
            installed,
        )
        return None

    try:
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": resolved}],
            }
        )
        engine = AnalyzerEngine(
            nlp_engine=provider.create_engine(),
            supported_languages=[language],
            default_score_threshold=0.0,
        )
    except Exception as exc:  # pragma: no cover - depends on environment
        logger.warning(
            "classifier_nlp_unavailable reason=engine_error model=%s error=%s",
            resolved,
            exc,
        )
        return None

    logger.info("classifier_nlp_ready detector=presidio+spacy:%s", resolved)
    return PresidioDetector(
        engine,
        model_name=resolved,
        language=language,
        score_threshold=score_threshold,
    )


# ──────────────────────────────────────────────────────────────────────
# Classification service
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FieldMetadata:
    """Metadata describing a structured field (from the data catalog).

    ``sensitivity`` is the schema annotation and is authoritative when
    present. No field *values* are ever passed to the classifier.
    """

    name: str
    column_name: str | None = None
    sensitivity: SensitivityLevel | None = None
    pii_category: str | None = None
    description: str | None = None
    field_type: str | None = None
    asset_name: str | None = None
    asset_type: str | None = None
    table_name: str | None = None


@dataclass(frozen=True)
class TextDetection:
    """One accepted detection inside a text (span offsets, never values)."""

    category: DataCategory
    start: int
    end: int
    confidence: float
    method: DetectionMethod
    rule_id: str
    note: str | None = None


class SensitiveDataClassifier:
    """Classify structured fields, documents, and free text.

    ``nlp`` controls the detector: ``"auto"`` builds the Presidio/spaCy
    detector lazily (and silently degrades to ``None`` when unavailable),
    ``None`` disables NLP entirely, or pass an object implementing
    :class:`NlpDetector` (used by tests).
    """

    def __init__(
        self,
        *,
        nlp: "NlpDetector | None | Literal['auto']" = "auto",
        language: str | None = None,
        score_threshold: float | None = None,
        uncertainty_threshold: float | None = None,
        unknown_field_sensitivity: SensitivityLevel | str | None = None,
        uncertain_handling: RecommendedHandling | str | None = None,
        label_scheme: str | None = None,
    ):
        self._nlp_choice = nlp
        self._nlp: NlpDetector | None = nlp if hasattr(nlp, "analyze") else None
        self._nlp_resolved = hasattr(nlp, "analyze")
        self._nlp_unavailable_reason: str | None = (
            None if hasattr(nlp, "analyze") else ("disabled" if nlp is None else None)
        )
        self.language = language or settings.CLASSIFIER_LANGUAGE
        self.score_threshold = (
            settings.CLASSIFIER_NLP_SCORE_THRESHOLD
            if score_threshold is None
            else score_threshold
        )
        self.uncertainty_threshold = (
            settings.CLASSIFIER_UNCERTAINTY_THRESHOLD
            if uncertainty_threshold is None
            else uncertainty_threshold
        )
        self.unknown_field_sensitivity = resolve_sensitivity(
            unknown_field_sensitivity
            or settings.CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY
        )
        self.uncertain_handling = (
            uncertain_handling
            if isinstance(uncertain_handling, RecommendedHandling)
            else RecommendedHandling(
                uncertain_handling or settings.CLASSIFIER_UNCERTAIN_HANDLING
            )
        )
        self.label_scheme = (label_scheme or settings.SENSITIVITY_LABEL_SCHEME).lower()

    # ── Status / discovery ──────────────────────────────────────────

    def status(self) -> dict:
        """Report classifier configuration and NLP availability.

        Does not construct the NLP engine; ``resolved`` indicates whether
        a resolution attempt has already happened in this process.
        """
        return {
            "nlp_enabled": settings.CLASSIFIER_NLP_ENABLED,
            "configured_model": settings.CLASSIFIER_SPACY_MODEL,
            "detector": self._nlp.name if self._nlp is not None else None,
            "resolved": self._nlp_resolved,
            "unavailable_reason": self._nlp_unavailable_reason,
            "unknown_field_sensitivity": self.unknown_field_sensitivity.value,
            "uncertain_handling": self.uncertain_handling.value,
            "label_scheme": self.label_scheme,
        }

    def _resolve_nlp(self) -> NlpDetector | None:
        if self._nlp_resolved:
            return self._nlp
        self._nlp_resolved = True
        if self._nlp_choice is None:
            self._nlp_unavailable_reason = "disabled"
            return None
        if not settings.CLASSIFIER_NLP_ENABLED:
            self._nlp_unavailable_reason = "disabled_by_config"
            return None
        detector = build_presidio_detector(
            settings.CLASSIFIER_SPACY_MODEL, self.language, self.score_threshold
        )
        if detector is None:
            self._nlp_unavailable_reason = "presidio_or_spacy_model_unavailable"
        self._nlp = detector
        return detector

    # ── Structured fields ───────────────────────────────────────────

    def classify_field(self, meta: FieldMetadata) -> ClassifiedField:
        """Classify one field from its metadata (never its value)."""
        if meta.sensitivity is not None:
            return self._classify_annotated(meta)
        rule = match_field_rule(meta.name)
        if rule is not None:
            return self._classify_by_rule(meta, rule)
        return self._classify_fallback(
            meta, "no schema annotation and no catalogue rule matched"
        )

    def classify_structured_record(
        self, asset_name: str, fields: Sequence[FieldMetadata]
    ) -> ClassificationResult:
        """Classify a record's fields using schema metadata / rules only.

        NLP is deliberately not consulted here: for structured data the
        schema annotation is authoritative and free text is out of scope.
        """
        classified = [self.classify_field(meta) for meta in fields]
        unclassified = [
            item.field_name
            for item in classified
            if item.detection_method is DetectionMethod.CONSERVATIVE_FALLBACK
        ]
        highest = max(
            (item.sensitivity for item in classified),
            key=lambda level: SENSITIVITY_ORDER[level],
            default=None,
        )
        notes = [
            "schema annotations are authoritative; NLP is not consulted "
            "for structured records"
        ]
        if unclassified:
            notes.append(
                "conservative default applied to fields without annotations: "
                + ", ".join(sorted(unclassified))
            )
        return ClassificationResult(
            source_ref=asset_name,
            source_type="structured_record",
            fields=classified,
            highest_sensitivity=highest,
            uncertain=bool(unclassified),
            unclassified_fields=unclassified,
            nlp_used=False,
            notes=notes,
        )

    def _classify_annotated(self, meta: FieldMetadata) -> ClassifiedField:
        sensitivity = resolve_sensitivity(meta.sensitivity)  # type: ignore[arg-type]
        category = category_from_alias(meta.pii_category)
        if category is not None:
            category_reason = (
                f"category from schema pii_category '{meta.pii_category}'"
            )
        else:
            rule = match_field_rule(meta.name)
            if rule is not None:
                category = rule.category
                category_reason = (
                    f"category inferred from field name (rule '{rule.rule_id}'); "
                    "sensitivity remains schema-annotated"
                )
            else:
                category = DataCategory.UNKNOWN
                category_reason = "no category mapping for annotated field"
        handling = _handling_for(category, sensitivity)
        reasons = [
            f"schema annotation: sensitivity={sensitivity.value}"
            + (f", pii_category={meta.pii_category}" if meta.pii_category else ""),
            category_reason,
        ]
        if handling is not CATEGORY_PROFILES[category].handling:
            reasons.append(
                f"handling raised to '{handling.value}' by sensitivity floor"
            )
        return ClassifiedField(
            field_name=meta.name,
            resource=meta.asset_name,
            category=category,
            sensitivity=sensitivity,
            sensitivity_label=sensitivity_label(sensitivity, self.label_scheme),
            confidence=1.0 if meta.pii_category else 0.95,
            detection_method=DetectionMethod.SCHEMA_ANNOTATION,
            recommended_handling=handling,
            authoritative=True,
            conservative=False,
            reasons=reasons,
        )

    def _classify_by_rule(
        self, meta: FieldMetadata, rule: FieldRule
    ) -> ClassifiedField:
        profile = CATEGORY_PROFILES[rule.category]
        sensitivity = rule.sensitivity or profile.sensitivity
        handling = most_restrictive(
            rule.handling or profile.handling, _HANDLING_FLOOR[sensitivity]
        )
        return ClassifiedField(
            field_name=meta.name,
            resource=meta.asset_name,
            category=rule.category,
            sensitivity=sensitivity,
            sensitivity_label=sensitivity_label(sensitivity, self.label_scheme),
            confidence=rule.confidence,
            detection_method=DetectionMethod.DETERMINISTIC_RULE,
            recommended_handling=handling,
            authoritative=False,
            conservative=False,
            reasons=[
                f"deterministic rule '{rule.rule_id}' "
                f"(tokens: {', '.join(sorted(rule.tokens))})",
                f"category default handling: '{profile.handling.value}'",
            ],
        )

    def _classify_fallback(
        self, meta: FieldMetadata, reason: str
    ) -> ClassifiedField:
        """Conservative policy for fields the classifier cannot resolve."""
        handling = most_restrictive(
            self.uncertain_handling, _HANDLING_FLOOR[self.unknown_field_sensitivity]
        )
        return ClassifiedField(
            field_name=meta.name,
            resource=meta.asset_name,
            category=DataCategory.UNKNOWN,
            sensitivity=self.unknown_field_sensitivity,
            sensitivity_label=sensitivity_label(
                self.unknown_field_sensitivity, self.label_scheme
            ),
            confidence=0.0,
            detection_method=DetectionMethod.CONSERVATIVE_FALLBACK,
            recommended_handling=handling,
            authoritative=False,
            conservative=True,
            reasons=[
                reason,
                "conservative default applied: "
                f"sensitivity='{self.unknown_field_sensitivity.value}', "
                f"handling='{handling.value}' "
                "(CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY / "
                "CLASSIFIER_UNCERTAIN_HANDLING)",
            ],
        )

    # ── Free text ───────────────────────────────────────────────────

    def detect_text(self, text: str) -> list[TextDetection]:
        """Return every accepted detection in ``text`` (spans only)."""
        detections, _ = self._detect(text)
        return detections

    def classify_text(
        self, text: str, *, source_ref: str = "text"
    ) -> ClassificationResult:
        """Classify free text into aggregated, explainable detections."""
        detections, nlp_used = self._detect(text or "")
        fields = self._detections_to_fields(detections, source_ref)
        highest = max(
            (item.sensitivity for item in fields),
            key=lambda level: SENSITIVITY_ORDER[level],
            default=None,
        )
        notes: list[str] = []
        if len(text or "") > MAX_TEXT_SCAN_CHARS:
            notes.append(f"scan truncated at {MAX_TEXT_SCAN_CHARS} characters")
        if not fields:
            notes.append(
                "no sensitive patterns detected — best-effort only; absence "
                "of detection is not proof that the text is safe"
            )
        elif nlp_used:
            notes.append("Presidio/spaCy contributed to this classification")
        elif self._nlp_unavailable_reason:
            notes.append(
                "NLP unavailable "
                f"({self._nlp_unavailable_reason}); deterministic detection only"
            )
        return ClassificationResult(
            source_ref=source_ref,
            source_type="free_text",
            fields=fields,
            highest_sensitivity=highest,
            uncertain=any(item.conservative for item in fields),
            unclassified_fields=[],
            nlp_used=nlp_used,
            notes=notes,
        )

    def _detect(self, text: str) -> tuple[list[TextDetection], bool]:
        """Run deterministic rules, then NLP; return (detections, nlp_used)."""
        if not text:
            return [], False
        scanned = text[:MAX_TEXT_SCAN_CHARS]
        detections: list[TextDetection] = []
        accepted: list[tuple[int, int]] = []

        # 1. Deterministic patterns (highest precision first — they win
        #    overlapping spans against NLP output).
        for rule in TEXT_RULES:
            for match in rule.pattern.finditer(scanned):
                if rule.value_group:
                    start, end = match.start(rule.value_group), match.end(rule.value_group)
                else:
                    start, end = match.start(), match.end()
                value = scanned[start:end]
                if rule.validate is not None and not rule.validate(value):
                    continue
                if _overlaps(accepted, start, end):
                    continue
                accepted.append((start, end))
                detections.append(
                    TextDetection(
                        category=rule.category,
                        start=start,
                        end=end,
                        confidence=rule.confidence,
                        method=DetectionMethod.DETERMINISTIC_RULE,
                        rule_id=rule.rule_id,
                    )
                )

        # 2. NLP signal (never overrides an authoritative/deterministic span).
        nlp_used = False
        detector = self._resolve_nlp()
        if detector is not None:
            for entity in detector.analyze(scanned):
                category = _PRESIDIO_ENTITY_MAP.get(entity.entity_type)
                note: str | None = None
                if entity.entity_type == "DATE_TIME":
                    if _has_dob_context(scanned, entity.start):
                        category = DataCategory.DATE_OF_BIRTH
                        note = "date in date-of-birth context"
                    else:
                        category = None
                if category is None:
                    continue
                if entity.score < self.score_threshold:
                    continue
                if _overlaps(accepted, entity.start, entity.end):
                    continue
                accepted.append((entity.start, entity.end))
                detections.append(
                    TextDetection(
                        category=category,
                        start=entity.start,
                        end=entity.end,
                        confidence=entity.score,
                        method=DetectionMethod.NLP_PRESIDIO,
                        rule_id=f"presidio:{entity.entity_type}",
                        note=note,
                    )
                )
                nlp_used = True

        detections.sort(key=lambda item: item.start)
        return detections, nlp_used

    def _detections_to_fields(
        self, detections: Sequence[TextDetection], source_ref: str
    ) -> list[ClassifiedField]:
        grouped: dict[DataCategory, list[TextDetection]] = {}
        for detection in detections:
            grouped.setdefault(detection.category, []).append(detection)

        fields: list[ClassifiedField] = []
        for category, items in grouped.items():
            confidence = max(item.confidence for item in items)
            method = (
                DetectionMethod.DETERMINISTIC_RULE
                if any(item.method is DetectionMethod.DETERMINISTIC_RULE for item in items)
                else DetectionMethod.NLP_PRESIDIO
            )
            sensitivity = CATEGORY_PROFILES[category].sensitivity
            handling = _handling_for(category, sensitivity)
            low_confidence = confidence < self.uncertainty_threshold
            if low_confidence:
                handling = most_restrictive(handling, RecommendedHandling.ESCALATE)
            reasons = [f"rule:{rule_id}" for rule_id in sorted({i.rule_id for i in items})]
            reasons.append(f"occurrences={len(items)}")
            reasons.append(f"confidence={confidence:.2f}")
            if low_confidence:
                reasons.append(
                    f"confidence below uncertainty threshold "
                    f"{self.uncertainty_threshold:.2f}; conservative escalation applied"
                )
            fields.append(
                ClassifiedField(
                    field_name=source_ref,
                    resource=None,
                    category=category,
                    sensitivity=sensitivity,
                    sensitivity_label=sensitivity_label(sensitivity, self.label_scheme),
                    confidence=confidence,
                    detection_method=method,
                    recommended_handling=handling,
                    authoritative=False,
                    conservative=low_confidence,
                    reasons=reasons,
                    notes=[item.note for item in items if item.note][:1],
                )
            )
        return fields

    # ── Documents ───────────────────────────────────────────────────

    def classify_document(
        self,
        document_ref: str,
        label: str | None,
        *,
        summary_text: str | None = None,
    ) -> ClassificationResult:
        """Classify a business document from its label (authoritative).

        The document ``classification`` column (``internal``,
        ``confidential``, ``restricted``, …) is trusted metadata — the
        same role schema annotations play for structured fields. An
        unrecognised label falls back to the conservative default.

        ``summary_text``, when provided, is additionally scanned for PII
        with the deterministic + NLP detectors.
        """
        normalised = (label or "").strip().lower()
        fields: list[ClassifiedField] = []
        notes: list[str] = []

        if normalised in _DOCUMENT_LABELS:
            sensitivity, base_handling = _DOCUMENT_LABELS[normalised]
            handling = most_restrictive(
                base_handling, _HANDLING_FLOOR[sensitivity]
            )
            fields.append(
                ClassifiedField(
                    field_name="classification",
                    resource=document_ref,
                    category=DataCategory.CONFIDENTIAL_DOCUMENT,
                    sensitivity=sensitivity,
                    sensitivity_label=sensitivity_label(sensitivity, self.label_scheme),
                    confidence=1.0,
                    detection_method=DetectionMethod.DOCUMENT_LABEL,
                    recommended_handling=handling,
                    authoritative=True,
                    conservative=False,
                    reasons=[
                        f"document label '{normalised}' → sensitivity "
                        f"{sensitivity.value}, handling '{handling.value}'"
                    ],
                )
            )
        else:
            fields.append(
                ClassifiedField(
                    field_name="classification",
                    resource=document_ref,
                    category=DataCategory.CONFIDENTIAL_DOCUMENT,
                    sensitivity=self.unknown_field_sensitivity,
                    sensitivity_label=sensitivity_label(
                        self.unknown_field_sensitivity, self.label_scheme
                    ),
                    confidence=0.0,
                    detection_method=DetectionMethod.CONSERVATIVE_FALLBACK,
                    recommended_handling=most_restrictive(
                        self.uncertain_handling,
                        _HANDLING_FLOOR[self.unknown_field_sensitivity],
                    ),
                    authoritative=False,
                    conservative=True,
                    reasons=[
                        f"document label {label!r} is not recognised",
                        "conservative default applied "
                        "(CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY / "
                        "CLASSIFIER_UNCERTAIN_HANDLING)",
                    ],
                )
            )

        nlp_used = False
        if summary_text:
            detections, nlp_used = self._detect(summary_text)
            fields.extend(
                self._detections_to_fields(detections, f"{document_ref}.content_summary")
            )

        highest = max(
            (item.sensitivity for item in fields),
            key=lambda level: SENSITIVITY_ORDER[level],
            default=None,
        )
        if summary_text:
            notes.append("document summary scanned for embedded PII")
        return ClassificationResult(
            source_ref=document_ref,
            source_type="document",
            fields=fields,
            highest_sensitivity=highest,
            uncertain=any(item.conservative for item in fields),
            unclassified_fields=[],
            nlp_used=nlp_used,
            notes=notes,
        )


def hash_value(value: str) -> str:
    """SHA-256 of a raw value — for audit correlation, never for logging data.

    Classification itself never needs to hash values; this helper exists
    for callers that need to record that a specific value was seen without
    storing it.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
