"""Schemas for sensitive-data classification results.

Every classification produces *structured, explainable* output: what the
data is (category), how sensitive it is (sensitivity), where it came from
(field / resource reference), how sure the classifier is (confidence),
how it was determined (detection method), and what the policy engine
should consider doing with it (recommended handling).

The recommended handling is guidance only. It is derived from the
category and the sensitivity floor and **never** replaces a policy
decision — the deterministic policy engine owns the final action.

Note on sensitivity: the canonical levels are the four stored in the
database (``low``, ``medium``, ``high``, ``restricted``). Deployments may
present them under business labels (``public``, ``internal``,
``confidential``, ``restricted``); :func:`app.services.classifier.sensitivity_label`
resolves the configured label, and :class:`ClassifiedField` carries both
the canonical level and its label. No raw data values ever appear in a
classification result.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

# Canonical sensitivity levels are defined with the database models so the
# policy engine and the schema annotations always agree.
from app.models import SensitivityLevel


class DataCategory(str, Enum):
    """Catalogue of detectable data categories.

    The first twelve values mirror the entity types from the project
    specification (names, email, phone, …); the remaining values cover
    structured business data that a text classifier cannot reliably
    identify (HR records, customer accounts, orders, internal financial
    information, confidential documents).
    """

    # ── Personal / direct identifiers ───────────────────────────────
    PERSON_NAME = "person_name"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    SSN = "ssn"
    GOVERNMENT_ID = "government_id"
    MEDICAL_RECORD = "medical_record"
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    PASSWORD = "password"
    API_KEY = "api_key"

    # ── Structured business data ────────────────────────────────────
    SALARY = "salary"
    EMPLOYEE_HR_RECORD = "employee_hr_record"
    CUSTOMER_ACCOUNT = "customer_account"
    ORDER_DATA = "order_data"
    INTERNAL_FINANCIAL = "internal_financial"
    CONFIDENTIAL_DOCUMENT = "confidential_document"

    # ── Fallback ────────────────────────────────────────────────────
    UNKNOWN = "unknown"


class DetectionMethod(str, Enum):
    """How a classification was determined.

    Ordered from most to least authoritative in the documented trust
    model: database annotations and document labels are authoritative;
    deterministic rules are high-confidence; NLP is a signal only; the
    conservative fallback is what remains when nothing else matched.
    """

    SCHEMA_ANNOTATION = "schema_annotation"
    DOCUMENT_LABEL = "document_label"
    DETERMINISTIC_RULE = "deterministic_rule"
    NLP_PRESIDIO = "presidio_nlp"
    CONSERVATIVE_FALLBACK = "conservative_fallback"


class RecommendedHandling(str, Enum):
    """Suggested minimum-disclosure posture ("what to do with it").

    Values map 1:1 to the policy engine's decision vocabulary so a
    classification can be consumed without translation. The policy engine
    may override this in either direction *only* through an explicit norm;
    it must never silently relax it.
    """

    ALLOW = "allow"
    TOKENIZE = "tokenize"
    MASK = "mask"
    GENERALIZE = "generalize"
    AGGREGATE = "aggregate"
    ESCALATE = "escalate"
    BLOCK = "block"


class ClassifiedField(BaseModel):
    """Classification of one field (or one text source).

    A single field can produce several detections when it contains free
    text; structured fields produce exactly one.
    """

    model_config = ConfigDict(extra="forbid")

    field_name: str = Field(
        description="Field name, or the source reference for free text."
    )
    resource: str | None = Field(
        default=None,
        description="Asset (resource) the field belongs to, when applicable.",
    )
    category: DataCategory
    sensitivity: SensitivityLevel = Field(
        description="Canonical sensitivity level used by the policy engine."
    )
    sensitivity_label: str = Field(
        description="Configured presentation label (e.g. 'confidential')."
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="0.0–1.0; fixed values per method for deterministic paths.",
    )
    detection_method: DetectionMethod
    recommended_handling: RecommendedHandling
    authoritative: bool = Field(
        default=False,
        description="True for schema annotations and document labels.",
    )
    conservative: bool = Field(
        default=False,
        description=(
            "True when the conservative uncertainty policy was applied "
            "(low-confidence detection or unclassified field)."
        ),
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable explanation; never contains raw values.",
    )
    notes: list[str] = Field(default_factory=list)


class ClassificationResult(BaseModel):
    """Structured classification output for a record, document, or text."""

    model_config = ConfigDict(extra="forbid")

    source_ref: str = Field(
        description="Asset name, document number, or text reference."
    )
    source_type: str = Field(
        description="structured_record | structured_field | free_text | document"
    )
    fields: list[ClassifiedField] = Field(default_factory=list)
    highest_sensitivity: SensitivityLevel | None = None
    uncertain: bool = Field(
        default=False,
        description="True when at least one field used the conservative path.",
    )
    unclassified_fields: list[str] = Field(
        default_factory=list,
        description=(
            "Fields with no schema annotation and no rule match; they were "
            "classified with the documented conservative default."
        ),
    )
    nlp_used: bool = Field(
        default=False,
        description="Whether the Presidio/spaCy detector contributed.",
    )
    notes: list[str] = Field(default_factory=list)

    def field(self, name: str) -> ClassifiedField | None:
        """Return the classification for ``name`` if present."""
        for item in self.fields:
            if item.field_name == name:
                return item
        return None
