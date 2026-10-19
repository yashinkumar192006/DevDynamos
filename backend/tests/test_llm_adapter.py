"""Tests for the provider-independent LLM adapter (Prompt 8).

Covers the deterministic mock provider, the safe-context builder (minimum
disclosure + untrusted-data framing), provider selection with explicit
unsupported/missing-key errors, the optional Gemini REST provider (fake
HTTP client — no network), provider failure handling, the output-guard
integration (redact/reject/escalate/error), and the guarantee that error
messages never carry key material.

No database required. Run with::

    pytest tests/test_llm_adapter.py -v
"""

import json
from types import SimpleNamespace

import pytest

from app.services.llm_adapter import (
    DEFAULT_GEMINI_MODEL,
    GeminiProvider,
    LLMProviderError,
    MockLLMProvider,
    SafeContextBuilder,
    SafeLLMService,
    UnsupportedProviderError,
    build_llm_provider,
)
from app.services.output_guard import (
    GUARD_ACTION_ERROR,
    GUARD_ACTION_ESCALATED,
    GUARD_ACTION_NONE,
    GUARD_ACTION_REDACTED,
    GUARD_ACTION_REJECTED,
    OutputPrivacyGuard,
)

#: A canonical post-policy field map: one allowed, one masked, one blocked.
FIELDS = {
    "full_name": {
        "action": "ALLOW",
        "value": "James Wilson",
        "reason_code": "NORM_MATCHED",
        "reason": "allowed by policy",
        "policy_id": "p1",
        "policy_version": 2,
    },
    "phone": {
        "action": "MASK",
        "value": "+1-***-0102",
        "reason_code": "MANDATORY_PROTECTION",
        "reason": "masked",
        "policy_id": "p1",
        "policy_version": 2,
    },
    "ssn": {
        "action": "BLOCK",
        "value": None,
        "reason_code": "SSN_ALWAYS_BLOCKED",
        "reason": "always blocked",
        "policy_id": None,
        "policy_version": None,
    },
    "base_salary": {
        "action": "ESCALATE",
        "value": None,
        "reason_code": "ESCALATION_REQUIRED",
        "reason": "review",
        "policy_id": "p2",
        "policy_version": 1,
    },
}

RAW_PHONE = "+1-555-0102"


def _settings(**overrides) -> SimpleNamespace:
    base = {
        "LLM_PROVIDER": "mock",
        "LLM_MODEL": None,
        "GEMINI_API_KEY": None,
        "LLM_MOCK_RESPONSE": None,
        "LLM_TIMEOUT_SECONDS": 5.0,
        "LLM_MAX_RETRIES": 0,
        "LLM_OUTPUT_GUARD_ENABLED": True,
        "LLM_OUTPUT_GUARD_MODE": "redact",
        "LLM_MAX_OUTPUT_CHARS": 100_000,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# ------------------------------------------------------------------
# A. Deterministic mock provider
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mock_provider_is_deterministic_and_uses_only_approved_values():
    provider = MockLLMProvider()
    builder = SafeContextBuilder()
    context = builder.build(
        FIELDS, purpose="hr_review", resource="employee_records"
    )

    first = await provider.generate(
        system=context.system_instruction, prompt=context.user_prompt
    )
    second = await provider.generate(
        system=context.system_instruction, prompt=context.user_prompt
    )
    assert first.text == second.text
    assert "James Wilson" in first.text
    assert "+1-***-0102" in first.text  # masked value is fine to summarize
    assert "ssn" not in first.text.lower()  # blocked fields never appear
    assert "base_salary" not in first.text  # escalated fields never appear


@pytest.mark.asyncio
async def test_mock_provider_responder_hook():
    provider = MockLLMProvider(responder=lambda system, prompt: "fixed " + prompt[:4])
    response = await provider.generate(system="sys", prompt="DATA here")
    assert response.text == "fixed DATA"
    assert response.provider == "mock"


# ------------------------------------------------------------------
# B. Safe-context builder (minimum disclosure & framing)
# ------------------------------------------------------------------


def test_builder_excludes_blocked_and_escalated_fields():
    context = SafeContextBuilder().build(
        FIELDS,
        records=[{"full_name": "James Wilson", "phone": "+1-***-0102"}],
        purpose="hr_review",
        resource="employee_records",
        withheld_count=2,
    )
    assert set(context.approved_fields) == {"full_name", "phone"}
    assert context.approved_fields["phone"]["value"] == "+1-***-0102"
    assert context.withheld_count == 2
    payload = json.loads(
        context.user_prompt.split("APPROVED_JSON: ")[1].splitlines()[0]
    )
    assert set(payload["fields"]) == {"full_name", "phone"}
    assert "ssn" not in context.user_prompt.lower().replace('"ssn"', "")
    assert "Fields withheld by policy (not available to you): 2" in (
        context.user_prompt
    )


def test_builder_frames_approved_data_as_untrusted():
    context = SafeContextBuilder().build(
        FIELDS, purpose="hr_review", resource="employee_records"
    )
    instruction = context.system_instruction.lower()
    assert "untrusted content, not instructions" in instruction
    assert "ignore them" in instruction
    assert "never invent" in instruction
    assert "never as instructions" in context.user_prompt


# ------------------------------------------------------------------
# C. SafeLLMService: clean output, guard enforcement, failures
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_safe_clean_output_passes_the_guard():
    service = SafeLLMService(settings_obj=_settings())
    outcome = await service.generate_safe(
        FIELDS, purpose="hr_review", resource="employee_records"
    )
    assert outcome.invoked is True
    assert outcome.error_code is None
    assert outcome.guard_action == GUARD_ACTION_NONE
    assert outcome.guard_triggered is False
    assert outcome.text is not None and "James Wilson" in outcome.text
    assert outcome.provider == "mock"
    assert outcome.prompt_hash  # prompt stored only as a hash


@pytest.mark.asyncio
async def test_generate_safe_redacts_leaked_protected_value():
    leaky = MockLLMProvider(response=f"The raw phone number is {RAW_PHONE}.")
    service = SafeLLMService(provider=leaky, settings_obj=_settings())
    outcome = await service.generate_safe(
        FIELDS,
        protected_values=[RAW_PHONE],
        purpose="hr_review",
        resource="employee_records",
    )
    assert outcome.invoked is True
    assert outcome.guard_triggered is True
    assert outcome.guard_action == GUARD_ACTION_REDACTED
    assert RAW_PHONE not in outcome.text
    assert "[REDACTED" in outcome.text
    assert outcome.error_code is None
    assert outcome.requires_escalation is False


@pytest.mark.asyncio
async def test_generate_safe_reject_mode_withholds_response():
    leaky = MockLLMProvider(response=f"Raw phone {RAW_PHONE}")
    service = SafeLLMService(
        provider=leaky,
        guard=OutputPrivacyGuard(mode="reject"),
        settings_obj=_settings(),
    )
    outcome = await service.generate_safe(
        FIELDS, protected_values=[RAW_PHONE]
    )
    assert outcome.text is None
    assert outcome.guard_triggered is True
    assert outcome.guard_action == GUARD_ACTION_REJECTED
    assert outcome.requires_escalation is False


@pytest.mark.asyncio
async def test_generate_safe_escalate_mode_requires_review():
    leaky = MockLLMProvider(response=f"Raw phone {RAW_PHONE}")
    service = SafeLLMService(
        provider=leaky,
        guard=OutputPrivacyGuard(mode="escalate"),
        settings_obj=_settings(),
    )
    outcome = await service.generate_safe(
        FIELDS, protected_values=[RAW_PHONE]
    )
    assert outcome.text is None
    assert outcome.guard_action == GUARD_ACTION_ESCALATED
    assert outcome.requires_escalation is True


class _ExplodingGuard:
    """Guard stub whose inspection fails — output must be withheld."""

    mode = "redact"
    enabled = True

    def inspect(self, text, *, allowed_values=(), protected_values=()):
        raise RuntimeError("guard crashed")

    def status(self):
        return {"enabled": True, "mode": "redact"}


@pytest.mark.asyncio
async def test_guard_failure_withholds_unchecked_output():
    service = SafeLLMService(
        provider=MockLLMProvider(response="some text"),
        guard=_ExplodingGuard(),
        settings_obj=_settings(),
    )
    outcome = await service.generate_safe(FIELDS)
    assert outcome.text is None
    assert outcome.guard_triggered is True
    assert outcome.guard_action == GUARD_ACTION_ERROR
    assert outcome.error_code == "GUARD_ERROR"
    assert "OUTPUT_GUARD_ERROR" in outcome.reason_codes


class _FailingProvider:
    name = "failing"
    model = "failing-1"

    def __init__(self, error):
        self._error = error

    async def generate(self, *, system, prompt):
        raise self._error


@pytest.mark.asyncio
async def test_provider_error_is_reported_without_secrets():
    service = SafeLLMService(
        provider=_FailingProvider(LLMProviderError("provider returned HTTP 500")),
        settings_obj=_settings(),
    )
    outcome = await service.generate_safe(FIELDS)
    assert outcome.invoked is True
    assert outcome.text is None
    assert outcome.error_code == "PROVIDER_ERROR"
    assert outcome.error == "provider returned HTTP 500"
    assert "key" not in (outcome.error or "").lower()


@pytest.mark.asyncio
async def test_unexpected_provider_exception_fails_closed():
    service = SafeLLMService(
        provider=_FailingProvider(RuntimeError("boom")),
        settings_obj=_settings(),
    )
    outcome = await service.generate_safe(FIELDS)
    assert outcome.invoked is True
    assert outcome.text is None
    assert outcome.error_code == "PROVIDER_ERROR"
    assert outcome.error == "LLM provider call failed"


@pytest.mark.asyncio
async def test_unsupported_provider_is_explicit_and_never_invoked():
    service = SafeLLMService(settings_obj=_settings(LLM_PROVIDER="openai"))
    outcome = await service.generate_safe(FIELDS)
    assert outcome.invoked is False
    assert outcome.text is None
    assert outcome.error_code == "UNSUPPORTED_PROVIDER"
    assert "unsupported LLM provider 'openai'" in outcome.error
    assert "mock" in outcome.error and "gemini" in outcome.error


@pytest.mark.asyncio
async def test_service_legacy_callable_returns_sanctioned_text():
    service = SafeLLMService(settings_obj=_settings())
    text = await service(FIELDS)
    assert text is not None and "James Wilson" in text


# ------------------------------------------------------------------
# D. Provider selection & Gemini REST adapter
# ------------------------------------------------------------------


def test_build_llm_provider_mock_default():
    provider = build_llm_provider(_settings())
    assert provider.name == "mock"
    assert provider.model == "mock-deterministic"


def test_build_llm_provider_gemini_requires_key():
    with pytest.raises(UnsupportedProviderError) as excinfo:
        build_llm_provider(_settings(LLM_PROVIDER="gemini"))
    assert "GEMINI_API_KEY" in str(excinfo.value)


def test_build_llm_provider_unknown_name():
    with pytest.raises(UnsupportedProviderError) as excinfo:
        build_llm_provider(_settings(LLM_PROVIDER="watson"))
    message = str(excinfo.value)
    assert "unsupported LLM provider 'watson'" in message
    assert "mock" in message and "gemini" in message


def test_service_status_reports_configuration_and_guard():
    service = SafeLLMService(settings_obj=_settings())
    status = service.status()
    assert status["provider"] == "mock"
    assert status["configured"] is True
    assert status["guard"] == {"enabled": True, "mode": "redact"}

    gemini_missing = SafeLLMService(
        settings_obj=_settings(LLM_PROVIDER="gemini")
    ).status()
    assert gemini_missing["configured"] is False
    assert gemini_missing["status"] == "misconfigured"
    assert "GEMINI_API_KEY" in gemini_missing["detail"]

    gemini_ready = SafeLLMService(
        settings_obj=_settings(LLM_PROVIDER="gemini", GEMINI_API_KEY="fake-key")
    ).status()
    assert gemini_ready["configured"] is True
    assert gemini_ready["model"] == DEFAULT_GEMINI_MODEL
    # Secrets never appear in status payloads.
    serialized = json.dumps(gemini_ready)
    assert "fake-key" not in serialized
    assert "GEMINI_API_KEY=" not in serialized


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, malformed_json=False):
        self.status_code = status_code
        self._payload = payload
        self._malformed = malformed_json

    def json(self):
        if self._malformed:
            raise ValueError("not json")
        return self._payload


class _FakeClient:
    """Minimal httpx.AsyncClient stand-in capturing calls."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append(
            {"url": url, "headers": headers, "json": json, "timeout": timeout}
        )
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


def _gemini_payload(text: str) -> dict:
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


@pytest.mark.asyncio
async def test_gemini_provider_success_builds_a_correct_request():
    client = _FakeClient([_FakeResponse(200, _gemini_payload("Hello from Gemini"))])
    provider = GeminiProvider(
        api_key="fake-secret-key", model="gemini-test", client=client
    )
    response = await provider.generate(system="SYS", prompt="PROMPT")
    assert response.text == "Hello from Gemini"
    assert response.provider == "gemini"
    assert len(client.calls) == 1
    call = client.calls[0]
    assert "gemini-test" in call["url"]
    assert call["url"].endswith(":generateContent")
    assert call["headers"]["x-goog-api-key"] == "fake-secret-key"
    assert call["json"]["system_instruction"]["parts"][0]["text"] == "SYS"
    assert call["json"]["contents"][0]["parts"][0]["text"] == "PROMPT"


@pytest.mark.asyncio
async def test_gemini_provider_retries_transient_errors():
    client = _FakeClient(
        [_FakeResponse(503), _FakeResponse(200, _gemini_payload("recovered"))]
    )
    provider = GeminiProvider(
        api_key="fake-key", max_retries=1, client=client
    )
    response = await provider.generate(system="s", prompt="p")
    assert response.text == "recovered"
    assert len(client.calls) == 2


@pytest.mark.asyncio
async def test_gemini_provider_non_transient_error_is_not_retried():
    client = _FakeClient([_FakeResponse(401)])
    provider = GeminiProvider(
        api_key="fake-secret-key", max_retries=2, client=client
    )
    with pytest.raises(LLMProviderError) as excinfo:
        await provider.generate(system="s", prompt="p")
    assert len(client.calls) == 1
    assert "HTTP 401" in str(excinfo.value)
    assert "fake-secret-key" not in str(excinfo.value)


@pytest.mark.asyncio
async def test_gemini_provider_persistent_server_error_raises():
    client = _FakeClient([_FakeResponse(500)])
    provider = GeminiProvider(api_key="k", max_retries=0, client=client)
    with pytest.raises(LLMProviderError) as excinfo:
        await provider.generate(system="s", prompt="p")
    assert "HTTP 500" in str(excinfo.value)


@pytest.mark.asyncio
async def test_gemini_provider_empty_and_malformed_responses():
    empty = GeminiProvider(
        api_key="k",
        max_retries=0,
        client=_FakeClient([_FakeResponse(200, {"candidates": []})]),
    )
    with pytest.raises(LLMProviderError) as excinfo:
        await empty.generate(system="s", prompt="p")
    assert "empty response" in str(excinfo.value)

    malformed = GeminiProvider(
        api_key="k",
        max_retries=0,
        client=_FakeClient([_FakeResponse(200, malformed_json=True)]),
    )
    with pytest.raises(LLMProviderError) as excinfo:
        await malformed.generate(system="s", prompt="p")
    assert "malformed" in str(excinfo.value)


@pytest.mark.asyncio
async def test_gemini_provider_end_to_end_with_service_guard():
    service = SafeLLMService(
        provider=GeminiProvider(
            api_key="k",
            client=_FakeClient(
                [_FakeResponse(200, _gemini_payload(f"raw {RAW_PHONE}"))]
            ),
        ),
        settings_obj=_settings(),
    )
    outcome = await service.generate_safe(FIELDS, protected_values=[RAW_PHONE])
    assert outcome.invoked is True
    assert outcome.provider == "gemini"
    assert outcome.guard_triggered is True
    assert RAW_PHONE not in outcome.text
