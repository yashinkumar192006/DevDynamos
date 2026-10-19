"""Tests for the sensitive-data classification layer (Prompt 6).

Two layers are tested separately:

* the pure engine (:mod:`app.services.classifier`) — deterministic field
  rules, text patterns, document labels, the conservative uncertainty
  policy, and NLP integration with an injected fake detector (no external
  services);
* the database adapter (:mod:`app.services.classification_service`) —
  schema annotations from the seeded catalog are authoritative.

A real Presidio + spaCy test runs when the libraries and a model are
installed, and skips cleanly otherwise. No test ever asserts on raw data
values: classification output must never contain them.

Requires the migrated + seeded demo database for the service tests.
Run with::

    pytest tests/test_classifier.py -v
"""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.models import SensitivityLevel
from app.schemas.classifier import (
    DataCategory,
    DetectionMethod,
    RecommendedHandling,
)
from app.services.classification_service import ClassificationService
from app.services.classifier import (
    MAX_TEXT_SCAN_CHARS,
    FieldMetadata,
    NlpEntity,
    SensitiveDataClassifier,
    build_presidio_detector,
    category_from_alias,
    hash_value,
    match_field_rule,
    resolve_sensitivity,
    sensitivity_label,
)


# ------------------------------------------------------------------
# Fixtures & helpers
# ------------------------------------------------------------------


def _make_url() -> str:
    from app.core.config import settings

    url = str(settings.DATABASE_URL)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine(_make_url(), echo=False, poolclass=NullPool)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


def _engine() -> SensitiveDataClassifier:
    """Deterministic-only classifier — no NLP engine is ever constructed."""
    return SensitiveDataClassifier(nlp=None)


class FakeDetector:
    """Deterministic stand-in for Presidio (injectable detector protocol)."""

    name = "fake-detector"

    def __init__(self, entities):
        self._entities = list(entities)

    def analyze(self, text):  # noqa: ARG002 - accepts the scanned text
        return list(self._entities)


# ------------------------------------------------------------------
# A. Sensitivity levels and labels
# ------------------------------------------------------------------


def test_resolve_sensitivity_accepts_canonical_names_and_business_aliases():
    assert resolve_sensitivity("confidential") is SensitivityLevel.HIGH
    assert resolve_sensitivity("Internal") is SensitivityLevel.MEDIUM
    assert resolve_sensitivity("public") is SensitivityLevel.LOW
    assert (
        resolve_sensitivity(SensitivityLevel.RESTRICTED)
        is SensitivityLevel.RESTRICTED
    )
    with pytest.raises(ValueError):
        resolve_sensitivity("top-secret")


def test_sensitivity_labels_follow_configured_scheme():
    # Default scheme is business-facing unless configured otherwise.
    assert sensitivity_label(SensitivityLevel.LOW) == "public"
    assert sensitivity_label(SensitivityLevel.MEDIUM) == "internal"
    assert sensitivity_label(SensitivityLevel.HIGH) == "confidential"
    assert sensitivity_label(SensitivityLevel.RESTRICTED) == "restricted"
    assert sensitivity_label(SensitivityLevel.HIGH, "standard") == "high"


def test_hash_value_is_stable_and_irreversible():
    digest = hash_value("synthetic-value")
    assert digest == hash_value("synthetic-value")
    assert digest != hash_value("synthetic-value-2")
    assert len(digest) == 64


# ------------------------------------------------------------------
# B. Structured fields — schema annotations are authoritative
# ------------------------------------------------------------------


def test_schema_annotation_is_authoritative_over_rules():
    classifier = _engine()
    result = classifier.classify_field(
        FieldMetadata(
            name="legacy_identifier",
            sensitivity=SensitivityLevel.HIGH,
            pii_category="phone",
            asset_name="employee_records",
        )
    )
    assert result.category is DataCategory.PHONE
    assert result.sensitivity is SensitivityLevel.HIGH
    assert result.detection_method is DetectionMethod.SCHEMA_ANNOTATION
    assert result.authoritative is True
    assert result.conservative is False
    assert result.confidence == 1.0
    assert result.recommended_handling is RecommendedHandling.MASK


def test_sensitivity_floor_raises_handling_above_category_default():
    classifier = _engine()
    result = classifier.classify_field(
        FieldMetadata(
            name="work_email",
            sensitivity=SensitivityLevel.RESTRICTED,
            pii_category="email",
        )
    )
    # Email defaults to mask; a restricted annotation raises it to escalate.
    assert result.category is DataCategory.EMAIL
    assert result.recommended_handling is RecommendedHandling.ESCALATE
    assert any("floor" in reason for reason in result.reasons)


def test_deterministic_rules_cover_configured_business_fields():
    classifier = _engine()

    salary = classifier.classify_field(FieldMetadata(name="base_salary"))
    assert salary.category is DataCategory.SALARY
    assert salary.sensitivity is SensitivityLevel.RESTRICTED
    assert salary.detection_method is DetectionMethod.DETERMINISTIC_RULE
    assert salary.recommended_handling is RecommendedHandling.ESCALATE

    card = classifier.classify_field(FieldMetadata(name="credit_card_last4"))
    assert card.category is DataCategory.CREDIT_CARD
    assert card.recommended_handling is RecommendedHandling.BLOCK

    bank = classifier.classify_field(FieldMetadata(name="bank_account"))
    assert bank.category is DataCategory.BANK_ACCOUNT
    assert bank.recommended_handling is RecommendedHandling.BLOCK

    customer = classifier.classify_field(FieldMetadata(name="customer_id"))
    assert customer.category is DataCategory.CUSTOMER_ACCOUNT
    assert customer.sensitivity is SensitivityLevel.LOW
    assert customer.recommended_handling is RecommendedHandling.ALLOW

    ssn = classifier.classify_field(FieldMetadata(name="ssn"))
    assert ssn.category is DataCategory.SSN
    assert ssn.sensitivity is SensitivityLevel.RESTRICTED
    assert ssn.recommended_handling is RecommendedHandling.BLOCK


def test_unknown_field_gets_conservative_fail_closed_default():
    classifier = _engine()
    result = classifier.classify_field(
        FieldMetadata(name="zorp_metric_7", asset_name="mystery")
    )
    assert result.category is DataCategory.UNKNOWN
    assert result.sensitivity is SensitivityLevel.HIGH
    assert result.confidence == 0.0
    assert result.detection_method is DetectionMethod.CONSERVATIVE_FALLBACK
    assert result.conservative is True
    assert result.authoritative is False
    assert result.recommended_handling is RecommendedHandling.ESCALATE
    assert any(
        "CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY" in reason
        for reason in result.reasons
    )


def test_unknown_field_policy_is_configurable():
    classifier = SensitiveDataClassifier(
        nlp=None,
        unknown_field_sensitivity="restricted",
        uncertain_handling="block",
    )
    result = classifier.classify_field(FieldMetadata(name="zorp_metric_7"))
    assert result.sensitivity is SensitivityLevel.RESTRICTED
    assert result.recommended_handling is RecommendedHandling.BLOCK


def test_structured_record_aggregates_findings_and_flags_unclassified():
    classifier = _engine()
    result = classifier.classify_structured_record(
        "employee_salary",
        [
            FieldMetadata(
                name="base_salary",
                sensitivity=SensitivityLevel.RESTRICTED,
                pii_category="salary",
                asset_name="employee_salary",
            ),
            FieldMetadata(
                name="employee_id",
                sensitivity=SensitivityLevel.LOW,
                asset_name="employee_salary",
            ),
            FieldMetadata(name="mystery", asset_name="employee_salary"),
        ],
    )
    assert result.source_type == "structured_record"
    assert result.highest_sensitivity is SensitivityLevel.RESTRICTED
    assert result.uncertain is True
    assert result.unclassified_fields == ["mystery"]
    assert result.nlp_used is False
    assert result.field("base_salary").recommended_handling is RecommendedHandling.ESCALATE


# ------------------------------------------------------------------
# C. Free text — deterministic patterns
# ------------------------------------------------------------------


def test_text_detection_finds_ssn_card_and_email_without_leaking_values():
    text = (
        "Contact jane.doe@example.com; card 4242 4242 4242 4242; "
        "ssn 123-45-6789."
    )
    classifier = _engine()

    detections = classifier.detect_text(text)
    categories = {detection.category for detection in detections}
    assert DataCategory.EMAIL in categories
    assert DataCategory.CREDIT_CARD in categories
    assert DataCategory.SSN in categories

    result = classifier.classify_text(text, source_ref="ticket-1")
    by_category = {field.category: field for field in result.fields}
    assert (
        by_category[DataCategory.CREDIT_CARD].recommended_handling
        is RecommendedHandling.BLOCK
    )
    assert (
        by_category[DataCategory.SSN].recommended_handling
        is RecommendedHandling.BLOCK
    )
    assert result.highest_sensitivity is SensitivityLevel.RESTRICTED

    # The structured output must never contain the raw values.
    dumped = str(result.model_dump())
    assert "4242" not in dumped
    assert "jane.doe@example.com" not in dumped
    assert "123-45-6789" not in dumped


def test_credit_card_candidates_fail_luhn_are_rejected():
    classifier = _engine()
    detections = classifier.detect_text("reference 1234 5678 9012 3456")
    assert all(
        detection.category is not DataCategory.CREDIT_CARD
        for detection in detections
    )


def test_api_key_assignment_detection():
    classifier = _engine()
    detections = classifier.detect_text("api_key = sk-abcdef1234567890abcd")
    assert any(detection.category is DataCategory.API_KEY for detection in detections)


def test_empty_text_reports_best_effort_baseline():
    classifier = _engine()
    result = classifier.classify_text("")
    assert result.fields == []
    assert any("best-effort" in note for note in result.notes)


def test_long_text_is_truncated_at_scan_limit():
    classifier = _engine()
    result = classifier.classify_text("x" * (MAX_TEXT_SCAN_CHARS + 500))
    assert any("truncated" in note for note in result.notes)


# ------------------------------------------------------------------
# D. Uncertainty policy with an injected NLP detector
# ------------------------------------------------------------------


def _person_entity(score: float) -> NlpEntity:
    return NlpEntity(entity_type="PERSON", start=0, end=5, score=score)


def test_low_confidence_nlp_detection_escalates_conservatively():
    fake = FakeDetector([_person_entity(0.55)])
    classifier = SensitiveDataClassifier(nlp=fake)
    result = classifier.classify_text("Alice works here")

    person = next(
        field for field in result.fields if field.category is DataCategory.PERSON_NAME
    )
    assert result.nlp_used is True
    assert person.confidence == pytest.approx(0.55)
    assert person.conservative is True
    assert person.recommended_handling is RecommendedHandling.ESCALATE
    assert any("uncertainty" in reason for reason in person.reasons)
    assert result.uncertain is True


def test_high_confidence_nlp_detection_is_not_escalated():
    fake = FakeDetector([_person_entity(0.95)])
    classifier = SensitiveDataClassifier(nlp=fake)
    result = classifier.classify_text("Alice works here")

    person = next(
        field for field in result.fields if field.category is DataCategory.PERSON_NAME
    )
    assert person.conservative is False
    assert person.recommended_handling is RecommendedHandling.ALLOW
    assert result.uncertain is False


def test_detections_below_score_threshold_are_dropped():
    fake = FakeDetector([_person_entity(0.30)])
    classifier = SensitiveDataClassifier(nlp=fake)
    result = classifier.classify_text("Alice works here")
    assert result.fields == []
    assert result.nlp_used is False


def test_deterministic_patterns_win_over_overlapping_nlp_spans():
    text = "jane.doe@example.com"
    fake = FakeDetector(
        [NlpEntity(entity_type="EMAIL_ADDRESS", start=0, end=len(text), score=0.99)]
    )
    classifier = SensitiveDataClassifier(nlp=fake)
    result = classifier.classify_text(text)
    email = next(
        field for field in result.fields if field.category is DataCategory.EMAIL
    )
    assert email.detection_method is DetectionMethod.DETERMINISTIC_RULE


def test_classifier_degrades_gracefully_without_nlp():
    classifier = _engine()
    assert classifier.status()["detector"] is None
    result = classifier.classify_text("jane.doe@example.com")
    assert any(field.category is DataCategory.EMAIL for field in result.fields)
    assert any("deterministic" in note for note in result.notes)


# ------------------------------------------------------------------
# E. Documents
# ------------------------------------------------------------------


def test_document_label_is_authoritative():
    classifier = _engine()
    result = classifier.classify_document("DOC003", "restricted")
    label = result.field("classification")
    assert label is not None
    assert label.detection_method is DetectionMethod.DOCUMENT_LABEL
    assert label.sensitivity is SensitivityLevel.RESTRICTED
    assert label.recommended_handling is RecommendedHandling.BLOCK
    assert label.authoritative is True


def test_document_unrecognised_label_falls_back_conservatively():
    classifier = _engine()
    result = classifier.classify_document("DOC999", "semi-secret")
    label = result.field("classification")
    assert label is not None
    assert label.detection_method is DetectionMethod.CONSERVATIVE_FALLBACK
    assert label.conservative is True
    assert label.sensitivity is SensitivityLevel.HIGH


def test_document_summary_is_scanned_for_embedded_pii():
    classifier = _engine()
    result = classifier.classify_document(
        "DOC010", "internal", summary_text="Escalate to jane.doe@example.com"
    )
    assert any(field.category is DataCategory.EMAIL for field in result.fields)
    assert any("scanned" in note for note in result.notes)


# ------------------------------------------------------------------
# F. Catalogue helpers
# ------------------------------------------------------------------


def test_category_alias_and_field_rule_helpers():
    assert category_from_alias("ssn") is DataCategory.SSN
    assert category_from_alias("contact_phone") is DataCategory.PHONE
    assert category_from_alias("not-a-real-category") is None

    rule = match_field_rule("bank_account_last4")
    assert rule is not None
    assert rule.category is DataCategory.BANK_ACCOUNT


# ------------------------------------------------------------------
# G. Real Presidio + spaCy signal (skips when unavailable)
# ------------------------------------------------------------------


def test_presidio_spacy_detects_person_names_when_available():
    pytest.importorskip("presidio_analyzer")
    pytest.importorskip("spacy")

    from app.core.config import settings

    detector = build_presidio_detector(
        settings.CLASSIFIER_SPACY_MODEL,
        settings.CLASSIFIER_LANGUAGE,
        settings.CLASSIFIER_NLP_SCORE_THRESHOLD,
    )
    if detector is None:
        pytest.skip("no Presidio/spaCy model available in this environment")

    classifier = SensitiveDataClassifier(nlp=detector)
    result = classifier.classify_text("Please ask John Smith to resubmit the form.")
    assert result.nlp_used is True
    assert any(
        field.category is DataCategory.PERSON_NAME for field in result.fields
    )


# ------------------------------------------------------------------
# H. Database-backed ClassificationService
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_service_uses_catalog_annotations(session):
    service = ClassificationService(session, classifier=_engine())
    result = await service.classify_asset_fields("employee_salary")

    by_name = {field.field_name: field for field in result.fields}
    assert by_name["base_salary"].sensitivity is SensitivityLevel.RESTRICTED
    assert (
        by_name["base_salary"].detection_method
        is DetectionMethod.SCHEMA_ANNOTATION
    )
    assert (
        by_name["base_salary"].recommended_handling
        is RecommendedHandling.ESCALATE
    )
    assert by_name["bank_account"].category is DataCategory.BANK_ACCOUNT
    assert (
        by_name["bank_account"].recommended_handling
        is RecommendedHandling.BLOCK
    )
    assert by_name["employee_id"].sensitivity is SensitivityLevel.LOW
    assert result.highest_sensitivity is SensitivityLevel.RESTRICTED
    assert result.uncertain is False


@pytest.mark.asyncio
async def test_service_selected_fields_only(session):
    service = ClassificationService(session, classifier=_engine())
    result = await service.classify_asset_fields(
        "employee_records", ["full_name", "email"]
    )
    assert {field.field_name for field in result.fields} == {"full_name", "email"}


@pytest.mark.asyncio
async def test_service_unknown_field_is_conservative(session):
    service = ClassificationService(session, classifier=_engine())
    field = await service.classify_field("employee_salary", "nonexistent_column")
    assert field.detection_method is DetectionMethod.CONSERVATIVE_FALLBACK
    assert field.sensitivity is SensitivityLevel.HIGH
    assert field.conservative is True


@pytest.mark.asyncio
async def test_service_unknown_asset_does_not_fail_open(session):
    service = ClassificationService(session, classifier=_engine())
    result = await service.classify_asset_fields("no_such_asset", ["mystery"])
    assert any("not found" in note for note in result.notes)
    assert result.fields[0].conservative is True
    assert result.uncertain is True


@pytest.mark.asyncio
async def test_service_document_classification_and_missing_document(session):
    service = ClassificationService(session, classifier=_engine())

    doc = await service.classify_document("DOC001")
    label = doc.field("classification")
    assert label is not None
    assert label.detection_method is DetectionMethod.DOCUMENT_LABEL
    assert label.sensitivity is SensitivityLevel.HIGH
    assert label.recommended_handling is RecommendedHandling.ESCALATE

    missing = await service.classify_document("DOC404")
    label = missing.field("classification")
    assert label is not None
    assert label.conservative is True
    assert any("not found" in note for note in missing.notes)


@pytest.mark.asyncio
async def test_service_text_and_status(session):
    service = ClassificationService(session, classifier=_engine())
    result = service.classify_text("mail me at someone@example.com", source_ref="t7")
    assert any(field.category is DataCategory.EMAIL for field in result.fields)

    status = service.status()
    assert status["unknown_field_sensitivity"] == "high"
    assert status["uncertain_handling"] == "escalate"
    assert status["label_scheme"] in {"business", "standard"}
