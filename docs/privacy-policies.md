# ContextShield — Privacy Policies & Decision Framework

> **Version:** 1.0.0  
> **Status:** Draft — Pre-implementation  
> **Last Updated:** 2026-10-18

---

## 1. Conceptual Foundation: Contextual Integrity

ContextShield enforces the **Contextual Integrity** (CI) framework (Nissenbaum, 2004). CI defines privacy not as data concealment but as **appropriate information flow**. Every flow is evaluated against a **norm**:

```
Norm = (Sender, Recipient, Data Type, Purpose, Transmission Principle)
```

A flow is appropriate if and only if a matching norm permits it. If no norm matches, the flow is **blocked** (fail-closed).

---

## 2. Policy Decision Actions

Every field in a request receives exactly one of seven decisions. These are **deterministic** — the same input always produces the same output.

### 2.1 Decision Definitions

| Action         | Code   | Effect on Data                                                      | When Used                                                            |
|----------------|--------|---------------------------------------------------------------------|----------------------------------------------------------------------|
| **ALLOW**      | `AL`   | Data passes through unchanged                                       | Norm explicitly permits full access for this role + purpose          |
| **MASK**       | `MK`   | Partial reveal with redacted characters                             | Norm permits awareness but not full value (e.g., last 4 of SSN)     |
| **TOKENIZE**   | `TK`   | Replace with a reversible, server-side opaque token                 | Value needed for correlation but not human-readable (internal refs)  |
| **GENERALIZE** | `GN`   | Replace specific value with a broader category                      | Norm permits approximate data (salary range, age bracket, city)      |
| **AGGREGATE**  | `AG`   | Replace individual values with group statistics                     | Norm permits only statistical views (department average salary)      |
| **BLOCK**      | `BL`   | Field is omitted entirely from the response                         | No norm authorizes access; default decision                          |
| **ESCALATE**   | `ES`   | Request is held pending approval from an authorized reviewer        | Norm exists but requires human review (compliance, edge case)        |

### 2.2 Decision Execution Flow

```text
                  ┌──────────────┐
                  │ Policy Engine│
                  │  evaluates   │
                  │  the field   │
                  └──────┬───────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
   Decision = ALLOW  Decision = MASK  Decision = BLOCK
          │              │              │
          ▼              ▼              ▼
   ┌────────────┐ ┌────────────┐ ┌────────────┐
   │ Return raw │ │ Apply mask │ │ Omit field │
   │ value      │ │ pattern    │ │ entirely   │
   └────────────┘ └────────────┘ └────────────┘
```

### 2.3 Transformation Specifications

#### MASK Patterns

| Entity Type        | Input Example                | Masked Output                |
|--------------------|------------------------------|------------------------------|
| `SSN`              | `123-45-6789`                | `***-**-6789`                |
| `CREDIT_CARD`      | `4111-1111-1111-1234`        | `****-****-****-1234`        |
| `EMAIL`            | `john.doe@company.com`       | `j***@company.com`           |
| `PHONE_NUMBER`     | `(555) 123-4567`             | `(***) ***-4567`             |
| `BANK_ACCOUNT`     | `9876543210`                 | `******3210`                 |
| `API_KEY`          | `sk-abcdefghij1234567890`    | `sk-****...7890`             |

#### GENERALIZE Transforms

| Entity Type        | Input Example                | Generalized Output           |
|--------------------|------------------------------|------------------------------|
| `SALARY`           | `$95,000`                    | `$90,000 – $100,000`         |
| `DATE_OF_BIRTH`    | `1990-03-15`                 | `30–35 years old`            |
| `ADDRESS`          | `123 Main St, Springfield`   | `Springfield, IL`            |
| `PERSON_NAME`      | `Jane Smith`                 | `Employee in Engineering`    |

#### AGGREGATE Rules

| Metric             | Requirement                                                     |
|--------------------|-----------------------------------------------------------------|
| Minimum group size | k ≥ 5 (k-anonymity threshold)                                   |
| Below threshold    | Return `BLOCK` with reason `GROUP_TOO_SMALL`                    |
| Output format      | `{ "mean": X, "median": Y, "count": N, "range": [min, max] }`  |
| Noise (v2)         | Optional differential privacy noise for enhanced protection      |

#### TOKENIZE Behavior

| Property           | Specification                                                   |
|--------------------|-----------------------------------------------------------------|
| Token format       | `tok_<base64(SHA-256(value + server_secret)[:16])>`              |
| Reversibility      | Server-side lookup table; tokens are deterministic per value     |
| Token lifetime     | Session-scoped; tokens are not valid across sessions             |
| Use case           | Allow internal correlation (e.g., "same customer") without exposing identifiers |

---

## 3. Information-Flow Norms (Policy Rules)

### 3.1 Norm Structure

Each policy rule is stored as a database record with the following structure:

```python
class PolicyRule:
    id: UUID                    # Unique policy identifier
    version: int                # Policy version number
    name: str                   # Human-readable name
    description: str            # What this norm authorizes

    # Matching criteria (WHO + WHAT + WHY)
    allowed_roles: list[str]    # Roles that may access (e.g., ["hr_manager"])
    data_types: list[str]       # Data types covered (e.g., ["SALARY", "PERSON_NAME"])
    sensitivity_levels: list[str]  # Max sensitivity (e.g., ["RESTRICTED"])
    allowed_purposes: list[str] # Permitted purposes (e.g., ["performance_review"])

    # Decision
    action: str                 # ALLOW | MASK | TOKENIZE | GENERALIZE | AGGREGATE | ESCALATE
    transmission_principle: str # Additional condition or constraint

    # Metadata
    priority: int               # Higher priority wins on conflict
    is_active: bool             # Whether the norm is currently enforced
    effective_from: datetime    # When the norm becomes active
    effective_until: datetime | None  # When the norm expires (null = no expiry)
    created_at: datetime
    updated_at: datetime
```

### 3.2 Initial Norms

#### Norm 1: HR Salary Review

```yaml
name: hr_salary_review
description: >
  HR managers may access full salary data when conducting performance reviews.
allowed_roles: [hr_manager]
data_types: [SALARY, PERSON_NAME, DEPARTMENT]
sensitivity_levels: [RESTRICTED, HIGH, LOW]
allowed_purposes: [performance_review, compensation_planning]
action: ALLOW
transmission_principle: >
  Requester must be the target's direct HR representative or department HR lead.
priority: 100
```

#### Norm 2: HR Salary View (Generalized)

```yaml
name: hr_salary_generalized
description: >
  HR staff (non-managers) may see salary ranges but not exact values.
allowed_roles: [hr_staff]
data_types: [SALARY]
sensitivity_levels: [RESTRICTED]
allowed_purposes: [performance_review, compensation_planning]
action: GENERALIZE
transmission_principle: >
  Salary is generalized to $10,000 range brackets.
priority: 90
```

#### Norm 3: Department Statistics

```yaml
name: department_statistics
description: >
  Department managers may view aggregate statistics for their own department.
allowed_roles: [department_manager, hr_manager, executive]
data_types: [SALARY, HEADCOUNT]
sensitivity_levels: [RESTRICTED, HIGH]
allowed_purposes: [department_analytics, budget_planning]
action: AGGREGATE
transmission_principle: >
  Only for requester's own department. Minimum group size k=5.
priority: 80
```

#### Norm 4: Customer Contact for Support

```yaml
name: customer_contact_support
description: >
  Support agents may access customer contact information for active ticket resolution.
allowed_roles: [support_agent, support_lead]
data_types: [PHONE_NUMBER, EMAIL, PERSON_NAME]
sensitivity_levels: [HIGH, MEDIUM]
allowed_purposes: [ticket_resolution]
action: ALLOW
transmission_principle: >
  Only for customers with an active support ticket assigned to the requester.
priority: 100
```

#### Norm 5: Customer Contact Masked

```yaml
name: customer_contact_masked
description: >
  Support agents may see masked contact info for general customer lookup.
allowed_roles: [support_agent]
data_types: [PHONE_NUMBER, EMAIL]
sensitivity_levels: [HIGH, MEDIUM]
allowed_purposes: [customer_lookup]
action: MASK
transmission_principle: >
  Partial reveal only. Full access requires active ticket assignment.
priority: 70
```

#### Norm 6: Order Status

```yaml
name: order_status_access
description: >
  Support and sales staff may access order status and non-sensitive order details.
allowed_roles: [support_agent, support_lead, sales_rep]
data_types: [ORDER_STATUS, ORDER_DATE, ORDER_TOTAL]
sensitivity_levels: [LOW, MEDIUM]
allowed_purposes: [ticket_resolution, order_inquiry, customer_service]
action: ALLOW
transmission_principle: >
  Order financial details (total, payment) are accessible to assigned agents only.
priority: 80
```

#### Norm 7: SSN Access (Never via AI)

```yaml
name: ssn_block_always
description: >
  SSN data is never accessible through the AI agent interface, regardless of role.
allowed_roles: []
data_types: [SSN]
sensitivity_levels: [RESTRICTED]
allowed_purposes: []
action: BLOCK
transmission_principle: >
  SSN access requires direct HR system login with MFA. AI agents are never authorized.
priority: 1000   # Highest priority — overrides all other norms
```

#### Norm 8: Self-Service Employee Data

```yaml
name: self_service_employee
description: >
  Any authenticated employee may view their own basic profile information.
allowed_roles: [employee, hr_staff, hr_manager, department_manager, support_agent, executive]
data_types: [PERSON_NAME, EMAIL, DEPARTMENT, ROLE, HIRE_DATE]
sensitivity_levels: [LOW, MEDIUM]
allowed_purposes: [self_service, profile_view]
action: ALLOW
transmission_principle: >
  Only for the requester's own record (requester_id == target_entity_id).
priority: 50
```

---

## 4. Policy Evaluation Algorithm

### 4.1 Matching Logic

```text
For each requested_field:
    1. Classify the field → (entity_type, sensitivity_level)
    2. Find all active norms where:
       a. requester_role ∈ norm.allowed_roles (or norm has wildcard)
       b. entity_type ∈ norm.data_types
       c. sensitivity_level ∈ norm.sensitivity_levels
       d. stated_purpose ∈ norm.allowed_purposes
       e. norm.effective_from ≤ now ≤ norm.effective_until
    3. If multiple norms match → select highest priority
    4. If tied priority → most restrictive action wins
    5. If no norms match → BLOCK with reason "NO_MATCHING_NORM"
    6. Validate transmission_principle (e.g., "own department only")
    7. Return (field, action, reason_code, policy_id, policy_version)
```

### 4.2 Priority Resolution

| Scenario                                              | Resolution                                   |
|-------------------------------------------------------|----------------------------------------------|
| Single matching norm                                  | Apply that norm's action                     |
| Multiple norms, different priorities                  | Highest priority wins                        |
| Multiple norms, same priority, different actions      | Most restrictive wins (BLOCK > ESCALATE > AGGREGATE > GENERALIZE > MASK > TOKENIZE > ALLOW) |
| No matching norm                                      | BLOCK (fail-closed)                          |
| Evaluation error                                      | BLOCK (fail-closed)                          |

### 4.3 Restrictiveness Ordering

```text
Most restrictive                              Least restrictive
    BLOCK > ESCALATE > AGGREGATE > GENERALIZE > MASK > TOKENIZE > ALLOW
```

---

## 5. Reason Codes

Every policy decision includes a machine-readable reason code and a human-readable explanation.

| Reason Code             | Human Explanation                                              |
|-------------------------|----------------------------------------------------------------|
| `NORM_MATCHED`          | Access authorized by policy: {policy_name}                     |
| `NO_MATCHING_NORM`      | No policy authorizes this access for your role and purpose     |
| `INSUFFICIENT_ROLE`     | Your role does not have access to this data type               |
| `INVALID_PURPOSE`       | The stated purpose is not recognized or not permitted          |
| `PURPOSE_NOT_VERIFIED`  | The stated purpose could not be verified server-side           |
| `SENSITIVITY_EXCEEDED`  | The data sensitivity exceeds your clearance level              |
| `TRANSMISSION_VIOLATED` | Access condition not met (e.g., not in target's department)    |
| `GROUP_TOO_SMALL`       | Aggregate group has fewer than k members; individual risk      |
| `MOSAIC_RISK`           | Cumulative disclosures exceed re-identification threshold      |
| `SSN_ALWAYS_BLOCKED`    | SSN is never accessible through the AI agent interface         |
| `SELF_ACCESS_ONLY`      | This data is accessible only for your own record               |
| `EVALUATION_ERROR`      | Policy check encountered an error; defaulting to BLOCK         |
| `ESCALATION_REQUIRED`   | This access requires approval from a compliance reviewer       |
| `FIELD_NOT_FOUND`       | The requested field does not exist in the data source          |

---

## 6. Policy Versioning

### 6.1 Version Model

```text
PolicyRule (id=P1, version=1, action=MASK,  effective_from=2026-01-01)
PolicyRule (id=P1, version=2, action=ALLOW, effective_from=2026-07-01)
```

- Each policy rule has a `version` field (monotonically increasing integer).
- When a policy is updated, a new version is created. The old version is retained for audit trail.
- The policy engine always uses the latest active version for evaluation.
- Audit records reference the specific `policy_id + version` that was applied, ensuring historical decisions remain explainable even after policy changes.

### 6.2 Version Transition Rules

| Scenario                                    | Behavior                                          |
|---------------------------------------------|---------------------------------------------------|
| New version becomes active                  | All new evaluations use the new version            |
| Old version is deactivated                  | Retained in DB with `is_active=false` for audit    |
| Rollback needed                             | Reactivate the previous version                    |
| Conflicting active versions                 | Highest version number wins                        |

---

## 7. Audit Requirements

Every policy evaluation produces an `AuditEvent`:

```python
class AuditEvent:
    id: UUID
    timestamp: datetime
    request_id: UUID           # Correlation ID for the HTTP request
    requester_id: UUID         # Who made the request
    requester_role: str        # Role at time of request
    target_entity_id: str      # Who/what was queried
    purpose_claimed: str       # What the user said the purpose was
    purpose_verified: bool     # Whether the purpose was validated
    fields_requested: list[str]
    decisions: list[{
        field: str,
        action: str,           # ALLOW | MASK | ... | BLOCK
        reason_code: str,
        policy_id: UUID,
        policy_version: int
    }]
    overall_decision: str      # ALLOW | PARTIAL_ALLOW | BLOCK
    guard_triggered: bool      # Whether Output Privacy Guard intervened
    value_hashes: dict[str, str]  # SHA-256 hashes of actual values (never raw)
```

### 7.1 Audit Immutability

- Audit records are **append-only**. No update or delete operations are permitted.
- The database table uses a trigger or application-level check to prevent modifications.
- Audit records are indexed by `timestamp`, `requester_id`, and `overall_decision` for efficient querying.

---

## 8. Safe Error Handling in Policy Evaluation

```python
def evaluate_field(field, context) -> PolicyDecision:
    try:
        norms = find_matching_norms(field, context)
        if not norms:
            return PolicyDecision(
                action="BLOCK",
                reason_code="NO_MATCHING_NORM",
                reason="No policy authorizes this access."
            )
        selected = resolve_priority(norms)
        if not validate_transmission_principle(selected, context):
            return PolicyDecision(
                action="BLOCK",
                reason_code="TRANSMISSION_VIOLATED",
                reason="Access condition not met."
            )
        return PolicyDecision(
            action=selected.action,
            reason_code="NORM_MATCHED",
            policy_id=selected.id,
            policy_version=selected.version
        )
    except Exception:
        # FAIL-CLOSED: any error → BLOCK
        return PolicyDecision(
            action="BLOCK",
            reason_code="EVALUATION_ERROR",
            reason="Policy evaluation failed; access denied by default."
        )
```

This pattern ensures that no code path can result in an `ALLOW` decision unless a valid norm explicitly authorizes it.
