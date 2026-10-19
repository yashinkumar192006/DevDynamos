"""Tests for the output privacy guard (Prompt 8).

Covers the deterministic pattern catalogue (SSN, credit card + Luhn, email,
phone, street address, date of birth, password), the permitted-disclosure
set, protected source values, redact/reject/escalate enforcement, unknown
mode fail-closed behaviour, output-length truncation, and the guarantee
that findings/redaction metadata never contain the matched text.

These are pure unit tests — no database required. Run with::

    pytest tests/test_output_guard.py -v
"""

import json

from app.services.output_guard import (
    GENERIC_REDACTION,
    GUARD_ACTION_DISABLED,
    GUARD_ACTION_ESCALATED,
    GUARD_ACTION_NONE,
    GUARD_ACTION_REDACTED,
    GUARD_ACTION_REJECTED,
    GUARD_REASON_CLEAN,
    GUARD_REASON_DISABLED,
    GUARD_REASON_ESCALATED,
    GUARD_REASON_REDACTED,
    GUARD_REASON_REJECTED,
    TRUNCATION_MARKER,
    OutputPrivacyGuard,
    placeholder_for,
)


def _guard(**kwargs) -> OutputPrivacyGuard:
    kwargs.setdefault("mode", "redact")
    return OutputPrivacyGuard(**kwargs)


# ------------------------------------------------------------------
# A. Pattern detection
# ------------------------------------------------------------------


def test_clean_text_passes_untouched():
    result = _guard().inspect("All good here — nothing sensitive.")
    assert result.text == "All good here — nothing sensitive."
    assert result.triggered is False
    assert result.action == GUARD_ACTION_NONE
    assert result.reason_code == GUARD_REASON_CLEAN
    assert result.findings == []


def test_ssn_is_redacted():
    raw = "123-45-6789"
    result = _guard().inspect(f"The employee SSN is {raw}, keep it safe.")
    assert result.triggered is True
    assert result.action == GUARD_ACTION_REDACTED
    assert result.reason_code == GUARD_REASON_REDACTED
    assert "[REDACTED-SSN]" in result.text
    assert raw not in result.text
    finding = result.findings[0]
    assert finding.category == "ssn"
    assert finding.permitted is False
    assert finding.redacted_as == "[REDACTED-SSN]"


def test_invalid_ssn_not_flagged():
    result = _guard().inspect("Reference 000-00-0000 is not an SSN.")
    assert result.triggered is False
    assert result.action == GUARD_ACTION_NONE


def test_credit_card_redacted_and_luhn_invalid_ignored():
    valid = "4242 4242 4242 4242"
    result = _guard().inspect(f"Card on file: {valid}.")
    assert "[REDACTED-CREDIT-CARD]" in result.text
    assert valid not in result.text

    invalid = "1234 5678 9012 3456"
    clean = _guard().inspect(f"Reference number {invalid} (not a card).")
    assert clean.triggered is False


def test_email_and_phone_redacted():
    result = _guard().inspect(
        "Reach James at james.wilson@contextshield.dev or +1-555-123-4567 today."
    )
    assert "[REDACTED-EMAIL]" in result.text
    assert "[REDACTED-PHONE]" in result.text
    assert "james.wilson@contextshield.dev" not in result.text
    assert "+1-555-123-4567" not in result.text
    categories = {finding.category for finding in result.findings}
    assert {"email", "phone"} <= categories


def test_street_address_redacted():
    result = _guard().inspect("Ship to 456 Oak Street, Springfield, IL 62704.")
    assert "[REDACTED-ADDRESS]" in result.text
    assert "456 Oak Street" not in result.text


def test_date_of_birth_and_password_redacted():
    result = _guard().inspect(
        "Employee DOB: 03/15/1985; password: hunter2secret"
    )
    assert "[REDACTED-DATE-OF-BIRTH]" in result.text
    assert "[REDACTED-PASSWORD]" in result.text
    assert "03/15/1985" not in result.text
    assert "hunter2secret" not in result.text


def test_multiple_findings_redacted_without_overlap_corruption():
    result = _guard().inspect(
        "Call +1-555-123-4567 or use SSN 123-45-6789 - that is all."
    )
    assert "[REDACTED-PHONE]" in result.text
    assert "[REDACTED-SSN]" in result.text
    # Both redactions landed; ordering/indices did not corrupt the rest.
    assert result.text.endswith("- that is all.")
    assert result.redacted_count == 2


# ------------------------------------------------------------------
# B. Permitted-disclosure set
# ------------------------------------------------------------------


def test_permitted_value_is_not_redacted():
    allowed = "natalie.brooks@acme-robotics.example"
    result = _guard().inspect(
        f"Contact details: {allowed} (already authorized).",
        allowed_values=[allowed],
    )
    assert result.triggered is False
    assert result.action == GUARD_ACTION_NONE
    assert allowed in result.text
    permitted = [f for f in result.findings if f.permitted]
    assert permitted and permitted[0].category == "email"


def test_permitted_masked_value_passes_untouched():
    result = _guard().inspect(
        "The phone on file is +1-***-0102.", allowed_values=["+1-***-0102"]
    )
    assert result.triggered is False
    assert "+1-***-0102" in result.text


def test_unpermitted_value_of_same_category_is_redacted():
    result = _guard().inspect(
        "Other address: 44 Harbor View Road, Boston.",
        allowed_values=["500 Innovation Drive, Austin, TX 78701"],
    )
    assert result.triggered is True
    assert "[REDACTED-ADDRESS]" in result.text
    assert "44 Harbor View Road" not in result.text


# ------------------------------------------------------------------
# C. Protected source values
# ------------------------------------------------------------------


def test_protected_source_value_is_redacted_generically():
    result = _guard().inspect(
        "The exact salary is 62000.00 per the records.",
        protected_values=["62000.00"],
    )
    assert result.triggered is True
    assert GENERIC_REDACTION in result.text
    assert "62000.00" not in result.text
    finding = result.findings[0]
    assert finding.category == "protected_value"
    assert finding.rule_id == "protected_source_value"


def test_protected_decimal_caught_in_integer_form():
    result = _guard().inspect(
        "Salary: 62000", protected_values=["62000.00"]
    )
    assert result.triggered is True
    assert "62000" not in result.text


def test_protected_value_verbatim_inside_allowed_value_is_not_leakage():
    shared = "james.wilson@contextshield.dev"
    result = _guard().inspect(
        f"Email {shared} is authorized.", 
        allowed_values=[shared],
        protected_values=[shared],
    )
    assert result.triggered is False
    assert shared in result.text


def test_short_protected_values_are_ignored():
    result = _guard().inspect("Value 42 appears here.", protected_values=["42"])
    assert result.triggered is False


# ------------------------------------------------------------------
# D. Enforcement modes
# ------------------------------------------------------------------


def test_reject_mode_withholds_the_response():
    result = _guard(mode="reject").inspect("SSN 123-45-6789")
    assert result.text is None
    assert result.triggered is True
    assert result.action == GUARD_ACTION_REJECTED
    assert result.reason_code == GUARD_REASON_REJECTED


def test_escalate_mode_withholds_the_response():
    result = _guard(mode="escalate").inspect("SSN 123-45-6789")
    assert result.text is None
    assert result.action == GUARD_ACTION_ESCALATED
    assert result.reason_code == GUARD_REASON_ESCALATED


def test_unknown_mode_fails_closed_to_reject():
    result = _guard(mode="yolo").inspect("SSN 123-45-6789")
    assert result.text is None
    assert result.action == GUARD_ACTION_REJECTED


def test_clean_text_unaffected_by_reject_mode():
    result = _guard(mode="reject").inspect("Nothing sensitive here.")
    assert result.text == "Nothing sensitive here."
    assert result.action == GUARD_ACTION_NONE


def test_disabled_guard_passes_text_through():
    result = _guard(enabled=False).inspect("SSN 123-45-6789")
    assert result.text == "SSN 123-45-6789"
    assert result.triggered is False
    assert result.action == GUARD_ACTION_DISABLED
    assert result.reason_code == GUARD_REASON_DISABLED


def test_empty_and_none_text():
    guard = _guard()
    assert guard.inspect(None).text is None
    empty = guard.inspect("")
    assert empty.text == ""
    assert empty.action == GUARD_ACTION_NONE


# ------------------------------------------------------------------
# E. Length bound, metadata hygiene, extension hook
# ------------------------------------------------------------------


def test_overlong_output_is_truncated_with_marker():
    guard = _guard(max_scan_chars=1000)
    text = "A" * 1500 + " SSN 123-45-6789"
    result = guard.inspect(text)
    assert result.triggered is True
    assert result.text is not None
    assert len(result.text) <= 1000 + len(TRUNCATION_MARKER)
    assert result.text.endswith(TRUNCATION_MARKER)
    # The unscanned tail (which contained the SSN) never comes back.
    assert "123-45-6789" not in result.text


def test_findings_and_metadata_never_contain_matched_text():
    result = _guard().inspect(
        "SSN 123-45-6789, email james.wilson@contextshield.dev",
        protected_values=["62000.00"],
    )
    serialized = json.dumps(result.to_dict())
    assert "123-45-6789" not in serialized
    assert "james.wilson@contextshield.dev" not in serialized
    for finding in result.to_dict()["findings"]:
        assert set(finding) == {
            "category",
            "rule",
            "permitted",
            "start",
            "end",
            "redacted_as",
        }


def test_placeholder_for_unknown_category_is_generic():
    assert placeholder_for("mystery") == GENERIC_REDACTION
    assert placeholder_for(None) == GENERIC_REDACTION
    assert placeholder_for("person_name") == "[REDACTED-PERSON-NAME]"


class _DetectorFinding:
    start = 0
    end = 9
    category = "custom_marker"
    rule_id = "unit_detector"


def test_detector_hook_findings_are_enforced():
    guard = _guard(detector=lambda text, occupied: [_DetectorFinding()])
    result = guard.inspect("LEAKME123 and more text.")
    assert result.triggered is True
    # Unknown categories get the generic placeholder (still never the text).
    assert result.text.startswith(GENERIC_REDACTION)
    assert "LEAKME123" not in result.text
    assert result.findings[0].rule_id == "unit_detector"
