"""Unit tests for the minimum-disclosure transformer.

Covers (Prompt 7, section B/C/F): every transformation function with real
values — mask patterns from docs/privacy-policies.md §2.3, generalization
(salary brackets, age bands, addresses), tokenization (deterministic,
session-scoped, protected resolution, expiry), and aggregation
(math + minimum group size).
"""

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from app.models import TransformationType
from app.services.policy_engine import FieldDecision, PolicyAction, ReasonCode
from app.services.transformer import (
    AggregateGuard,
    TokenVault,
    Transformer,
    compute_aggregate,
    generalize_value,
    mask_value,
)


# ------------------------------------------------------------------
# Masking — exact patterns from docs/privacy-policies.md §2.3
# ------------------------------------------------------------------


def test_mask_ssn_pattern():
    assert mask_value("123-45-6789", category="ssn") == "***-**-6789"


def test_mask_credit_card_pattern():
    assert (
        mask_value("4111-1111-1111-1234", category="credit_card")
        == "****-****-****-1234"
    )


def test_mask_bank_account_pattern():
    assert mask_value("9876543210", category="bank_account") == "******3210"


def test_mask_email_pattern():
    assert mask_value("john.doe@company.com", category="email") == "j***@company.com"


def test_mask_phone_pattern():
    assert mask_value("(555) 123-4567", category="phone") == "(***) ***-4567"


def test_mask_phone_keeps_country_code():
    assert mask_value("+1-555-0101", category="phone") == "+1-***-0101"


def test_mask_api_key_pattern():
    assert (
        mask_value("sk-abcdefghij1234567890", category="api_key")
        == "sk-****...7890"
    )


def test_mask_generic_fallback_and_none():
    assert mask_value("Acme Robotics") == "A***********s"
    assert mask_value(None) is None


# ------------------------------------------------------------------
# Generalization
# ------------------------------------------------------------------


def test_generalize_salary_bracket():
    assert (
        generalize_value(95000, category="salary", field_name="base_salary")
        == "$90,000 – $100,000"
    )
    assert (
        generalize_value(88000, category="salary", field_name="base_salary")
        == "$80,000 – $90,000"
    )


def test_generalize_date_of_birth_age_band():
    born = date(1990, 3, 15)
    today = datetime.now(timezone.utc).date()
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    band = (age // 5) * 5
    expected = f"{band}\u2013{band + 5} years old"
    assert generalize_value(born, category="date_of_birth") == expected


def test_generalize_address_to_city_region():
    assert (
        generalize_value("12 Cedar Lane, Springfield, IL 62702", category="address")
        == "Springfield, IL"
    )


def test_generalize_number_two_significant_digits():
    assert generalize_value(15400) == 15000
    assert generalize_value(897) == 900
    assert generalize_value(0) == 0


def test_generalize_unknown_text_fails_safe():
    # Unhandled free text must not be echoed raw.
    assert generalize_value("Jane Smith") == "[generalized]"
    assert generalize_value(None) is None


# ------------------------------------------------------------------
# Tokenization — protected, session-scoped vault
# ------------------------------------------------------------------


def test_tokenize_is_deterministic_within_session():
    vault = TokenVault("server-secret")
    token_a = vault.tokenize("CUS001", session_id="sess-1")
    token_b = vault.tokenize("CUS001", session_id="sess-1")
    assert token_a == token_b
    assert token_a.startswith("tok_")
    assert "CUS001" not in token_a


def test_tokenize_is_session_scoped():
    vault = TokenVault("server-secret")
    token_1 = vault.tokenize("CUS001", session_id="sess-1")
    token_2 = vault.tokenize("CUS001", session_id="sess-2")
    assert token_1 != token_2
    # Resolution is bound to the originating session.
    assert vault.resolve(token_1, session_id="sess-1") == "CUS001"
    assert vault.resolve(token_1, session_id="sess-2") is None
    assert vault.resolve("tok_unknown", session_id="sess-1") is None


def test_token_expiry_uses_ttl_clock():
    now = [1000.0]
    vault = TokenVault("server-secret", ttl_seconds=10, clock=lambda: now[0])
    token = vault.tokenize("EMP006", session_id="s")
    assert vault.resolve(token, session_id="s") == "EMP006"
    now[0] += 11  # past the TTL
    assert vault.resolve(token, session_id="s") is None
    assert vault.purge_expired() == 0  # already removed on resolve


def test_token_purge_expired_reports_count():
    now = [0.0]
    vault = TokenVault("server-secret", ttl_seconds=5, clock=lambda: now[0])
    vault.tokenize("A", session_id="s")
    vault.tokenize("B", session_id="s")
    now[0] = 6.0
    assert vault.purge_expired() == 2


# ------------------------------------------------------------------
# Aggregation math and k-anonymity
# ------------------------------------------------------------------


def test_compute_aggregate_statistics():
    stats = compute_aggregate([10, 20, 30, 40, 50], min_group_size=5)
    assert stats is not None
    assert stats.mean == 30.0
    assert stats.median == 30.0
    assert stats.count == 5
    assert stats.to_dict() == {"mean": 30.0, "median": 30.0, "count": 5, "range": [10, 50]}


def test_compute_aggregate_even_count_median():
    stats = compute_aggregate([1, 2, 3, 4], min_group_size=2)
    assert stats is not None
    assert stats.median == 2.5


def test_compute_aggregate_below_k_returns_none():
    assert compute_aggregate([1, 2, 3, 4], min_group_size=5) is None
    assert compute_aggregate([], min_group_size=5) is None


def test_aggregate_guard_repeat_limit():
    guard = AggregateGuard(repeat_limit=2, window_seconds=300)
    signature = AggregateGuard.signature(
        session_id="s", resource="employee_salary", scope="department-Engineering",
        fields=["base_salary"],
    )
    assert guard.allow(signature) is True
    assert guard.allow(signature) is True
    assert guard.allow(signature) is False  # third repeat blocked
    # A different field set is a different signature.
    other = AggregateGuard.signature(
        session_id="s", resource="employee_salary", scope="department-Engineering",
        fields=["bonus"],
    )
    assert guard.allow(other) is True


# ------------------------------------------------------------------
# Transformer plumbing
# ------------------------------------------------------------------


def _decision(action: PolicyAction, **overrides) -> FieldDecision:
    defaults = dict(
        field_name="contact_email",
        action=action,
        reason_code=ReasonCode.NORM_MATCHED,
        reason="test",
        column_name="contact_email",
        pii_category="email",
    )
    defaults.update(overrides)
    return FieldDecision(**defaults)


def test_transform_value_applies_real_transformations():
    transformer = Transformer()
    masked = transformer.transform_value(
        "natalie.brooks@acme-robotics.example",
        _decision(PolicyAction.MASK),
        session_id="s",
    )
    assert masked.value == "n***@acme-robotics.example"
    assert masked.transformation_type == TransformationType.MASK.value
    assert masked.original_hash is not None
    assert "natalie" not in str(masked.original_hash)

    tokenized = transformer.transform_value(
        "CUS001", _decision(PolicyAction.TOKENIZE, field_name="customer_id",
                            column_name="customer_number", pii_category=None),
        session_id="s",
    )
    assert tokenized.value.startswith("tok_")
    assert tokenized.transformation_type == TransformationType.TOKENIZE.value
    assert "CUS001" not in tokenized.value


def test_transform_value_block_and_escalate_return_no_value():
    transformer = Transformer()
    for action in (PolicyAction.BLOCK, PolicyAction.ESCALATE):
        outcome = transformer.transform_value("secret", _decision(action))
        assert outcome.value is None
        assert outcome.original_hash is None


def test_transform_records_drops_blocked_fields_and_internal_id():
    transformer = Transformer()
    decisions = [
        _decision(
            PolicyAction.ALLOW, field_name="company_name", column_name="company_name",
            pii_category=None,
        ),
        _decision(PolicyAction.MASK),
        _decision(PolicyAction.BLOCK, field_name="billing_address",
                  column_name="billing_address", pii_category="address"),
    ]
    records = [
        {
            "id": "internal-surrogate",
            "company_name": "Acme Robotics",
            "contact_email": "natalie.brooks@acme-robotics.example",
            "billing_address": "500 Innovation Drive, Austin, TX 78701",
        }
    ]
    output, transformed = transformer.transform_records(records, decisions, session_id="s")
    assert output == [
        {
            "company_name": "Acme Robotics",
            "contact_email": "n***@acme-robotics.example",
        }
    ]
    assert "billing_address" not in output[0]
    assert "id" not in output[0]
    assert len(transformed) == 2  # ALLOW + MASK audit entries
    # No raw sensitive value survives in the audit previews.
    assert all(
        "natalie" not in str(entry.preview) for entry in transformed
    )


def test_transform_records_all_aggregate_returns_nothing():
    transformer = Transformer()
    decisions = [
        _decision(PolicyAction.AGGREGATE, field_name="base_salary",
                  column_name="salary", pii_category="salary"),
    ]
    output, transformed = transformer.transform_records(
        [{"salary": 98000.0}], decisions, session_id="s"
    )
    assert output == []
    assert transformed == []
