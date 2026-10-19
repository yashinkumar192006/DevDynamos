# Deterministic Policy Engine & Minimum-Disclosure Pipeline

> **Status:** Implemented (Phase 7). This document describes the
> deterministic policy engine, the minimum-disclosure transformer, the
> protected data connector, and policy administration — the modules that
> turn an analyzed request context into per-field disclosure decisions and
> real, transformed data.

The design reference remains [`privacy-policies.md`](privacy-policies.md)
(decision semantics, precedence, mask patterns, reason codes). This
document describes **how the implementation realises that design** and
where it makes explicit choices.

## 1. Modules

| Module | Role |
| --- | --- |
| `backend/app/services/policy_engine.py` | Deterministic per-field evaluator: `PolicyAction`, `ReasonCode`, `FieldDecision`, `PolicyEvaluation`, `PolicyEngine` |
| `backend/app/services/transformer.py` | Real transformations: masking, generalization, tokenization (`TokenVault`), aggregation (`compute_aggregate`), repeated-query control (`AggregateGuard`) |
| `backend/app/services/data_connector.py` | `ProtectedDataConnector`: runs the seven-step pipeline, projects only granted columns, persists decisions + audit |
| `backend/app/services/policy_admin.py` | `PolicyAdminService`: admin-only, versioned policy management with audit |
| `backend/alembic/versions/7b1e4c9d2a55_*.py` | Adds `privacy_policies.action` and `privacy_policies.priority` |

The engine never fetches data; the connector never decides. That split
keeps every decision type unit-testable without a database and keeps
retrieval fail-closed by construction.

## 2. Execution order

`ProtectedDataConnector.execute()` runs, in order:

1. **Authenticate / resolve identity** — the connector receives the
   server-verified `Principal`; anything else returns `BLOCK`.
2. **Validate request and purpose** — 1–50 fields, resource, purpose.
3. **Evaluate policy** — `ContextAnalyzer` → `PolicyEngine`; the mosaic
   guard may escalate repeated aggregate queries here.
4. **Determine permitted fields and transformations** — aggregate groups
   below the minimum size are downgraded to `BLOCK / GROUP_TOO_SMALL`
   *before* anything is assembled, so the overall decision, the response,
   and the persisted record all agree.
5. **Retrieve only permitted records and fields** — SQL projects exactly
   the granted columns. A blocked request performs **no retrieval**.
6. **Transform** — mask / tokenize / generalize applied to real values.
7. **Construct a safe result** — JSON-safe values, per-field entries,
   `ALLOW | PARTIAL_ALLOW | BLOCK | ESCALATION_NEEDED`.

The LLM callback (if any) only runs when something was granted, and only
ever receives already-transformed values. Blocked requests never call it.

## 3. Matching semantics

For every requested field the engine consults the catalog metadata
(`sensitivity`, `pii_category`, `column_name`) and the active policies
whose `resource_pattern` matches the resource.

A policy **matches a field** when all of the following hold:

* **Purpose** — the normalized purpose is listed in `allowed_purposes`
  (or the policy lists `"*"`). Purpose is an *input* to matching, never
  proof of authorization.
* **Operation** — the request operation (`read`, `aggregate`, …) is
  listed in `allowed_actions` (or `"*"`).
* **Role** — when `required_role` is set, the requester holds it. Roles
  are expanded through the configured hierarchy
  (`POLICY_ROLE_HIERARCHY`, default `hr_manager→hr_staff`,
  `sales_manager→sales_staff`, `support_lead→support_agent`). Service
  accounts contribute `role:<name>` scopes and expand the same way.
* **Ceiling** — the field's sensitivity is **at or below** the policy's
  `min_sensitivity` (its maximum authorised sensitivity). `NULL` means
  "any sensitivity". AGGREGATE operations are the exception: the output
  is statistics only, so the ceiling does not gate the source column —
  the minimum-group-size control is what protects individuals.

**Role-less policies are self-service norms.** A policy with no
`required_role` can never authorise a third-party record on a personal
asset; for those it is skipped and the field resolves to
`BLOCK / SELF_ACCESS_ONLY` unless a role-bearing policy matches.

### Conflict resolution

Multiple matching policies resolve deterministically
(`PolicyEngine._resolve_conflict`):

1. highest `priority` wins;
2. then highest `version`;
3. then the more specific resource pattern (exact beats wildcard);
4. then the most restrictive action
   (`BLOCK > ESCALATE > AGGREGATE > GENERALIZE > MASK > TOKENIZE > ALLOW`).

The mandatory layer below is evaluated **before** matching, so no
priority can override it.

## 4. The mandatory layer

Applied before or around policy matching; a more permissive policy can
never lift these:

* **Identity sanity** — unknown principal kinds fail closed.
* **RBAC pre-check** — `AnalyzedContext.operation.allowed` must be true
  (`BLOCK / INSUFFICIENT_ROLE` otherwise). Permissions and policies are
  independent gates; both must pass.
* **Purpose** — missing or unrecognised purpose → `BLOCK /
  INVALID_PURPOSE`; injection signals → `BLOCK / INJECTION_SUSPECTED`.
* **Never-disclosable categories** — every field whose `pii_category` is
  in `POLICY_MANDATORY_BLOCK_CATEGORIES` (default `ssn`) is `BLOCK /
  SSN_ALWAYS_BLOCKED` regardless of role, priority, or admin status.
* **Third-party protection floors** — when the subject is *not* the
  requester's own record, categories in
  `POLICY_MANDATORY_MASK_CATEGORIES` (default `phone,email,bank_account,
  credit_card`) can be at most `MASK`, and
  `POLICY_MANDATORY_GENERALIZE_CATEGORIES` (default
  `address,date_of_birth`) at most `GENERALIZE`. Floors only *tighten*;
  they never upgrade a decision. Self-subject disclosures are exempt
  (a person may see their own contact data if a policy allows it).
* **Transmission principle** — department-scoped requests must match the
  requester's own department (`TRANSMISSION_VIOLATED` otherwise, and
  when the requester has no department); organisation-wide disclosure of
  personal data is always blocked.
* **Destination cap** — a declared destination that cannot be trusted is
  downgraded to `ESCALATE / ESCALATION_REQUIRED`; only server-declared
  `model | tool | service` destinations are trusted.
* **Fail closed** — unknown fields (`FIELD_NOT_FOUND`), evaluation
  exceptions (`EVALUATION_ERROR`), and unrecognised policy `action`
  values all resolve to `BLOCK`. `PolicyEngine.evaluate()` catches every
  internal error and returns an all-blocked evaluation.

## 5. Decisions and their realisation

| Action | Grants | Realised by |
| --- | --- | --- |
| `ALLOW` | raw value | connector returns the fetched column |
| `MASK` | pattern-masked value | `mask_value()` per category (docs §2.3 patterns) |
| `TOKENIZE` | `tok_…` substitute | `TokenVault.tokenize()` |
| `GENERALIZE` | coarser value | salary brackets, age bands, `City, ST`, 2-significant-digit numbers |
| `AGGREGATE` | `{mean, median, count, range}` | `compute_aggregate()` with the minimum group size |
| `BLOCK` | nothing | field omitted; nothing retrieved for it |
| `ESCALATE` | nothing yet | pending-approval state; nothing retrieved when nothing else was granted |

Overall result: all fields `ALLOW`/`AGGREGATE` → `ALLOW`; all `BLOCK` →
`BLOCK`; any `ESCALATE` → `ESCALATION_NEEDED`; otherwise `PARTIAL_ALLOW`.

## 6. Aggregate safeguards

* **Minimum group size** — `POLICY_MIN_GROUP_SIZE` (default 5). Below it
  the statistics are withheld and the field becomes
  `BLOCK / GROUP_TOO_SMALL`. This also covers single-record targets
  (count 1) and small departments.
* **Repeated-query control** — `AggregateGuard` counts identical
  aggregate requests per session/resource/scope/field-set inside a
  sliding window (`POLICY_AGGREGATE_REPEAT_LIMIT`,
  `POLICY_AGGREGATE_WINDOW_SECONDS`). Exceeding the budget escalates the
  aggregate to `ESCALATE / MOSAIC_RISK` with `mosaic_warning = true`.
* **Scope integrity** — cross-department and organisation-wide
  aggregates block on the transmission principle before any retrieval.
* **No noise, no false claims** — statistics are computed exactly; this
  implementation makes **no formal differential-privacy guarantee**. The
  safeguards are k-anonymity, scope checks, and query-budget controls.

## 7. Tokenization

Format: `tok_<base64url(sha256(value ⊕ server_secret ⊕ session)[:16])>`.
Tokens are deterministic inside a session (stable correlation), differ
across sessions, and the token → value mapping lives only in the
server-side `TokenVault` (`POLICY_TOKEN_TTL_MINUTES`, default 60;
secret falls back to `JWT_SECRET`). `resolve()` refuses cross-session
resolves and expired entries, and the vault is never exposed through the
result payload.

## 8. Reason codes

`ReasonCode` carries the codes from `privacy-policies.md` §5 —
`NORM_MATCHED`, `NO_MATCHING_NORM`, `INSUFFICIENT_ROLE`,
`INVALID_PURPOSE`, `SENSITIVITY_EXCEEDED`, `TRANSMISSION_VIOLATED`,
`GROUP_TOO_SMALL`, `MOSAIC_RISK`, `SSN_ALWAYS_BLOCKED`,
`SELF_ACCESS_ONLY`, `EVALUATION_ERROR`, `ESCALATION_REQUIRED`,
`FIELD_NOT_FOUND` — plus two implementation extensions:

* `MANDATORY_PROTECTION` — a mandatory protection floor upgraded the
  matched policy's action to a safer form (keeps the policy reference).
* `INJECTION_SUSPECTED` — override/identity-claim language detected in
  the purpose claim (the unrecognised-purpose case remains
  `INVALID_PURPOSE`, matching the demo scenario).

Every field decision exposes the code, a human-readable `reason`, and the
applied `policy_id` / `policy_version`.

## 9. Policy management and versioning

* `privacy_policies.action` (ALLOW…BLOCK, `NULL` = legacy read policy →
  treated as ALLOW) and `privacy_policies.priority` give every norm an
  explicit decision and precedence. Seeded policies declare both.
* `PolicyAdminService` is the only write path: user principals need the
  `admin` role; service principals need an admin scope (`policy:admin`,
  `policies:write`, `admin`, `*`). Normal users and LLM-driven callers
  are rejected with `PolicyAdminDenied` before any change.
* Updates create a **new version** and mark the previous version
  `SUPERSEDED` (retained for audit); `set_status` provides
  activate/deactivate and rollback. Every change writes an
  `ADMIN_ACTION` audit event.
* The engine always evaluates the active set; when several versions of a
  name are active, the highest version wins (§3).

## 10. Configuration

All thresholds are environment-tunable (`backend/app/core/config.py`):
`POLICY_MIN_GROUP_SIZE`, `POLICY_AGGREGATE_REPEAT_LIMIT`,
`POLICY_AGGREGATE_WINDOW_SECONDS`, `POLICY_MANDATORY_MASK_CATEGORIES`,
`POLICY_MANDATORY_GENERALIZE_CATEGORIES`,
`POLICY_MANDATORY_BLOCK_CATEGORIES`, `POLICY_ROLE_HIERARCHY`,
`POLICY_TOKEN_SECRET`, `POLICY_TOKEN_TTL_MINUTES`.

## 11. Persistence and audit

For user principals the connector persists `PrivacyRequest`,
`PrivacyDecision` (outcome, allowed/denied fields, reason codes, flags),
and one `TransformationEvent` per (field, transformation) with a SHA-256
original hash and a safe preview — **never** raw values. An `AuditEvent`
records `DATA_ACCESS` / `DATA_DENIED` with reason codes only. Service
principals are not persisted against the user table.

## 12. Tests

| File | Covers |
| --- | --- |
| `tests/test_transformer.py` | Mask patterns, generalization, token vault (session scope, TTL), aggregate math, k-anonymity, repeat guard |
| `tests/test_policy_engine.py` | Every decision type; unauthorized salary access; approved HR access; admin cannot bypass; SSN always blocked; missing/unrecognised purpose; injection; unknown fields; ownership/self-service; sensitivity ceiling; conflicts (priority, most-restrictive tie); escalate/tokenize policies; destination trust; evaluation errors |
| `tests/test_data_connector.py` | Seven-step order; real returned values (raw salary, masked contact, generalized address, tokens, statistics); blocked requests never retrieve or call the LLM; column projection excludes `ssn_hash`; small-group suppression; repeated-query escalation; cross-department blocks; persistence; JSON-safe results |
| `tests/test_policy_admin.py` | Admin-only access, versioning/supersede, rollback, validation, audit trail, engine follows the active version |
