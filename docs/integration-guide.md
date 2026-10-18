# ContextShield — Integration Guide

> **Version:** 1.0.0  
> **Status:** Draft — Pre-implementation  
> **Last Updated:** 2026-10-18

---

## 1. Overview

ContextShield provides **two integration methods** for AI agents and applications:

1. **Python SDK** — Direct import for Python-based AI agents (lowest latency, tightest integration).
2. **HTTP REST API** — Language-agnostic integration via the FastAPI gateway (works with any language/platform).

Both methods enforce the same privacy pipeline. The SDK is a thin wrapper around the API.

---

## 2. Quick Start

### 2.1 Python SDK

```python
from contextshield import ContextShieldClient

# Initialize with API URL and credentials
client = ContextShieldClient(
    base_url="http://localhost:8000",
    email="alice.chen@contextshield.demo",
    password="Demo-Pass-123!"
)

# Make a privacy-enforced data request
result = client.secure_request(
    data_fields=["employee_name", "salary", "department"],
    purpose="performance_review",
    target_entity="employee-456"
)

# Access the per-field decisions
for field_name, decision in result.fields.items():
    print(f"{field_name}: {decision.action} → {decision.value}")

# Output for HR manager:
# employee_name: ALLOW → Jane Smith
# salary: ALLOW → 95000
# department: ALLOW → Engineering
```

### 2.2 HTTP REST API

```bash
# 1. Authenticate
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice.chen@contextshield.demo","password":"Demo-Pass-123!"}' \
  | jq -r '.access_token')

# 2. Make a privacy-enforced request
curl -s -X POST http://localhost:8000/api/v1/privacy/secure-request \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data_fields": ["employee_name", "salary", "department"],
    "purpose": "performance_review",
    "target_entity": "employee-456"
  }'
```

---

## 3. Python SDK Reference

### 3.1 Installation

```bash
# From the project root (development mode)
pip install -e ./sdk

# Or from PyPI (future)
# pip install contextshield
```

### 3.2 Client Initialization

```python
from contextshield import ContextShieldClient

# Option A: Email/password authentication
client = ContextShieldClient(
    base_url="http://localhost:8000",
    email="alice.chen@contextshield.demo",
    password="Demo-Pass-123!"
)

# Option B: Pre-existing JWT token
client = ContextShieldClient(
    base_url="http://localhost:8000",
    token="eyJhbGciOiJIUzI1NiIs..."
)
```

### 3.3 SDK Methods

#### `secure_request()`

Submit a data request through the full privacy pipeline.

```python
result = client.secure_request(
    data_fields=["employee_name", "salary"],
    purpose="performance_review",
    target_entity="employee-456",
    session_id="sess-abc123",           # Optional: mosaic tracking
    include_llm_response=False          # Optional: generate NL response
)

# result.overall_decision     → "PARTIAL_ALLOW"
# result.fields               → dict of field decisions
# result.audit_id             → UUID of the audit record
# result.guard_triggered      → bool
# result.mosaic_warning       → bool
```

#### `get_policies()`

List active privacy policies.

```python
policies = client.get_policies(limit=20, offset=0, role="hr_manager")

for policy in policies.items:
    print(f"{policy.name}: {policy.action} for {policy.allowed_roles}")
```

#### `get_audit_events()`

Query the audit trail (requires appropriate role).

```python
events = client.get_audit_events(
    limit=10,
    decision="BLOCK",
    start_date="2026-10-01"
)

for event in events.items:
    print(f"{event.timestamp}: {event.overall_decision}")
```

#### `get_audit_event()`

Get details of a specific audit event.

```python
event = client.get_audit_event("aud-789e8400-...")
print(event.decisions)
```

#### `get_system_status()`

Check system health and service status.

```python
status = client.get_system_status()
print(f"DB: {status.services.database.status}")
print(f"Active policies: {status.services.policy_engine.active_policies}")
```

### 3.4 Error Handling

```python
from contextshield.exceptions import (
    ContextShieldError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    ServerError
)

try:
    result = client.secure_request(
        data_fields=["salary"],
        purpose="performance_review",
        target_entity="employee-456"
    )
except AuthenticationError:
    print("Token expired, re-authenticating...")
    client.authenticate()
    result = client.secure_request(...)
except AuthorizationError as e:
    print(f"Access denied: {e.message}")
except ValidationError as e:
    print(f"Invalid request: {e.details}")
except ServerError as e:
    print(f"Server error: {e.request_id}")
```

### 3.5 SDK Data Models

```python
from contextshield.models import (
    SecureRequestResult,
    FieldDecision,
    PolicyInfo,
    AuditEvent
)

# SecureRequestResult
result.overall_decision: str          # "ALLOW" | "PARTIAL_ALLOW" | "BLOCK"
result.fields: dict[str, FieldDecision]
result.audit_id: str
result.guard_triggered: bool
result.mosaic_warning: bool
result.timestamp: datetime

# FieldDecision
decision.action: str     # "ALLOW" | "MASK" | "BLOCK" | ...
decision.value: Any      # The (possibly transformed) value, or None
decision.reason_code: str
decision.policy_id: str | None
decision.policy_version: int | None
```

---

## 4. Integration Patterns

### 4.1 AI Agent Middleware Pattern

The most common integration: ContextShield acts as middleware between your AI agent and its data sources.

```python
from contextshield import ContextShieldClient

class PrivacyAwareAgent:
    def __init__(self, llm, privacy_client: ContextShieldClient):
        self.llm = llm
        self.privacy = privacy_client

    def handle_query(self, user_query: str, user_token: str):
        # 1. Parse the query to identify data needs (your agent logic)
        parsed = self.parse_query(user_query)

        # 2. Run through ContextShield privacy pipeline
        result = self.privacy.secure_request(
            data_fields=parsed.fields,
            purpose=parsed.purpose,
            target_entity=parsed.target,
            include_llm_response=True  # Let ContextShield handle LLM call
        )

        # 3. Return the privacy-enforced response
        if result.overall_decision == "BLOCK":
            return "I'm sorry, I don't have permission to access that data."

        return result.llm_response  # Already privacy-safe
```

### 4.2 Pre-Query Guard Pattern

Use ContextShield to check permissions before making your own data queries.

```python
# 1. Check what the user can access
result = privacy_client.secure_request(
    data_fields=["salary", "department", "ssn"],
    purpose="performance_review",
    target_entity="employee-456",
    include_llm_response=False  # We'll handle the data ourselves
)

# 2. Build our own query using only allowed fields
allowed_fields = [
    field for field, decision in result.fields.items()
    if decision.action == "ALLOW"
]

# 3. Query our own database with scoped SELECT
data = db.query(Employee).with_only_columns(allowed_fields).filter_by(...)
```

### 4.3 Output Validation Pattern

Use ContextShield to validate LLM responses before returning them to users.

```python
# 1. Your agent generates a response with its own LLM
raw_response = your_llm.generate(prompt)

# 2. Send the response through ContextShield for PII scanning
result = privacy_client.secure_request(
    data_fields=["llm_output"],
    purpose="output_validation",
    target_entity="response-validation",
    context={"raw_text": raw_response}
)

# 3. Use the sanitized response
if result.guard_triggered:
    return result.fields["llm_output"].value  # Sanitized
else:
    return raw_response  # No PII detected
```

---

## 5. Integration with Existing Frameworks

### 5.1 LangChain Integration

```python
from langchain.tools import BaseTool
from contextshield import ContextShieldClient

class PrivacyGuardedTool(BaseTool):
    name = "employee_lookup"
    description = "Look up employee information with privacy controls"

    def __init__(self, privacy_client: ContextShieldClient):
        super().__init__()
        self.privacy = privacy_client

    def _run(self, employee_id: str, fields: list[str], purpose: str):
        result = self.privacy.secure_request(
            data_fields=fields,
            purpose=purpose,
            target_entity=employee_id
        )
        return {
            f: d.value for f, d in result.fields.items()
            if d.action in ("ALLOW", "MASK", "GENERALIZE")
        }
```

### 5.2 FastAPI Sub-Application

```python
from fastapi import FastAPI, Depends
from contextshield import ContextShieldClient

app = FastAPI()
privacy = ContextShieldClient(base_url="http://localhost:8000")

@app.get("/my-agent/employee/{employee_id}")
async def get_employee(employee_id: str, current_user = Depends(get_user)):
    result = privacy.secure_request(
        data_fields=["full_name", "department", "salary"],
        purpose="employee_lookup",
        target_entity=employee_id
    )
    return result.fields
```

---

## 6. Configuration

### 6.1 Environment Variables

| Variable                        | Default                          | Description                       |
|---------------------------------|----------------------------------|-----------------------------------|
| `CONTEXTSHIELD_BASE_URL`        | `http://localhost:8000`          | Backend API URL                   |
| `CONTEXTSHIELD_TIMEOUT`         | `30`                             | Request timeout (seconds)         |
| `CONTEXTSHIELD_RETRY_COUNT`     | `3`                              | Max retries on transient errors   |
| `CONTEXTSHIELD_VERIFY_SSL`      | `true`                           | Verify SSL certificates           |

### 6.2 SDK Configuration Object

```python
from contextshield import ContextShieldClient, ClientConfig

config = ClientConfig(
    base_url="http://localhost:8000",
    timeout=30,
    retry_count=3,
    verify_ssl=True
)

client = ContextShieldClient(config=config, email="...", password="...")
```

---

## 7. Testing Your Integration

### 7.1 Test Against Mock LLM

The backend ships with a MockLLMProvider that produces deterministic responses:

```python
# Set in .env
LLM_PROVIDER=mock

# Mock responses are deterministic, making integration tests reproducible
result = client.secure_request(
    data_fields=["salary"],
    purpose="performance_review",
    target_entity="employee-456",
    include_llm_response=True
)
assert result.llm_response is not None
assert "salary" not in result.llm_response.lower()  # Guard strips PII
```

### 7.2 Test with Demo Users

Each demo user has a specific role. Test your integration against each role to verify privacy enforcement:

```python
import pytest
from contextshield import ContextShieldClient

@pytest.fixture(params=[
    ("alice.chen@contextshield.demo", "hr_manager", True),    # Should see salary
    ("dave.kumar@contextshield.demo", "employee", False),     # Should NOT see salary
])
def user_and_expected(request):
    return request.param

def test_salary_access(user_and_expected):
    email, role, should_see = user_and_expected
    client = ContextShieldClient(
        base_url="http://localhost:8000",
        email=email,
        password="Demo-Pass-123!"
    )
    result = client.secure_request(
        data_fields=["salary"],
        purpose="performance_review",
        target_entity="employee-456"
    )
    if should_see:
        assert result.fields["salary"].action == "ALLOW"
    else:
        assert result.fields["salary"].action == "BLOCK"
```

---

## 8. Security Checklist for Integrators

- [ ] Store your ContextShield credentials in environment variables or a secrets manager, never in code.
- [ ] Always pass the authenticated user's real identity; never impersonate users.
- [ ] Handle `BLOCK` and `ESCALATION_NEEDED` decisions gracefully in your UI/agent.
- [ ] Do not cache privacy decisions — they may change as policies are updated.
- [ ] Use `session_id` for mosaic tracking if your agent makes multiple queries per user session.
- [ ] Log the `audit_id` from each response for troubleshooting and compliance.
- [ ] Test your integration against all demo user roles before deployment.
- [ ] Never bypass ContextShield by querying the database directly.
