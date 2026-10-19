# Sensitive-Data Classification & Context Analysis

> **Status:** Implemented (Phase 2). This document describes the modules
> introduced with the classification and context layer and the
> conservative policies they follow.

## 1. Modules

| Module | Role |
| --- | --- |
| `backend/app/schemas/classifier.py` | Output schemas: `DataCategory`, `DetectionMethod`, `RecommendedHandling`, `ClassifiedField`, `ClassificationResult` |
| `backend/app/schemas/context.py` | Trust-annotated request context: `AnalyzedContext` and its components |
| `backend/app/services/classifier.py` | Pure classification engine — no database access; injectable NLP detector |
| `backend/app/services/classification_service.py` | Database adapter: loads *metadata only* from the data catalog and delegates to the engine |
| `backend/app/services/context_service.py` | `ContextAnalyzer`: builds `AnalyzedContext` for one authenticated request |

The engine/adapters split keeps classification independently testable:
`tests/test_classifier.py` exercises the engine with deterministic rules
and an injected fake detector, and the service layer against the seeded
catalog.

## 2. Classification trust model

From most to least authoritative:

1. **Schema annotations are authoritative.** A `data_fields.sensitivity`
   value (with optional `pii_category`) always wins. Detection method:
   `schema_annotation`, confidence `1.0` (0.95 when the category had to be
   inferred from the field name).
2. **Document labels are authoritative.** `business_documents.classification`
   (`internal`, `confidential`, `restricted`, …) is trusted metadata.
   Detection method: `document_label`.
3. **Deterministic rules are high-confidence.** A configured business-field
   catalogue (`salary`, `ssn`, `bank_account`, …) and precise text
   patterns (SSN, credit card + Luhn, email, phone variants, API keys,
   password assignments) cover the data an NLP model cannot identify
   reliably. Detection method: `deterministic_rule`.
4. **NLP (Presidio + spaCy) is a signal only.** It supplements the layers
   above for free text. It can never downgrade an authoritative
   classification, and deterministic spans win overlapping NLP spans.
   Detection method: `presidio_nlp`.
5. **Conservative fallback.** Anything unresolved gets the fail-closed
   default (see §4). Detection method: `conservative_fallback`.

Structured records are classified from metadata **only** — field values
are never passed to the classifier. Free-text scanning happens locally
(spaCy models run in-process); no text leaves the system. If Presidio or
a spaCy model is unavailable, the classifier logs a warning once and
degrades to deterministic-only mode — it never fails open.

## 3. Categories, sensitivity, and handling

* **Categories:** the twelve specification entity types (`person_name`,
  `email`, `phone`, `address`, `date_of_birth`, `ssn`, `government_id`,
  `medical_record`, `credit_card`, `bank_account`, `password`,
  `api_key`) plus structured business categories (`salary`,
  `employee_hr_record`, `customer_account`, `order_data`,
  `internal_financial`, `confidential_document`) and `unknown`.
* **Sensitivity levels:** the canonical database values `low`, `medium`,
  `high`, `restricted`. Deployments may present them under a label scheme
  (`public`/`internal`/`confidential`/`restricted`) configured via
  `SENSITIVITY_LABEL_SCHEME` (default `business`). Every result carries
  both the canonical level and its label.
* **Recommended handling:** `allow`, `tokenize`, `mask`, `generalize`,
  `aggregate`, `escalate`, `block` — 1:1 with the policy engine's
  decision vocabulary. The value is the **most restrictive** of the
  category default and a sensitivity floor (`high → mask`,
  `restricted → escalate`), so a mis-annotated field can never receive a
  weaker handling than its sensitivity implies.
* The recommended handling is guidance for the policy engine. The policy
  engine owns the final decision; nothing in this layer authorizes
  anything.

## 4. Conservative uncertainty policy (documented, fail-closed)

* A structured field with **no annotation and no rule match** is treated
  as `CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY` (default `high`) with
  handling at least `CLASSIFIER_UNCERTAIN_HANDLING` (default `escalate`),
  confidence `0.0`, and `conservative=True`. It is never assumed safe.
* A detection whose confidence is below
  `CLASSIFIER_UNCERTAINTY_THRESHOLD` (default `0.75`) is reported, but
  its handling is raised to at least `escalate` and the result is marked
  `uncertain`. Hard-block categories (SSN, credit card, bank account,
  password, API key, medical record, government ID) remain `block`.
* An unknown document label or a missing document/catalog entry receives
  the same conservative default instead of a "not sensitive" assumption.
* Absence of detections in free text is reported as *best-effort only* —
  it is not proof that the text is safe.

All thresholds are configurable (`app/core/config.py`) and every result
carries the `reasons` that explain it (rule id, annotation, floor
application, uncertainty escalation).

## 5. Context analysis trust model

`ContextAnalyzer.analyze(principal, ...)` returns an `AnalyzedContext`
covering: requester, agent/service identity, requested operation,
purpose, target resource, requested fields, subject scope and ownership,
destination, conversation/task metadata, policy references, and flags.

* **Identity is never client input.** The requester block is built from
  the validated credential and trusted database state. Statements like
  "I am the administrator" are scanned as *signals* (recorded by name)
  and never believed. Client metadata keys that look like authorization
  claims (`role`, `is_admin`, `clearance`, …) are recorded in
  `identity_claims_ignored` with their values dropped.
* **Purpose is an input to policy, never proof of authorization.** The
  claim is normalised, SHA-256-hashed for audit correlation, scanned for
  prompt-injection language, and pre-checked against active policies
  (`binding = "input_to_policy_engine"`).
* **Target scope is resolved server-side.** Self-vs-record scope comes
  from the trusted `employees.user_id` ownership link; department scope
  from the requester's trusted department; organisation scope from
  explicit sentinels (`*`, `all`, `organization`, …). Unscoped personal
  reads are recorded as `unknown`, never assumed `self`.
* **Unknown resources and fields fail closed.** They are reported with
  `RESOURCE_UNKNOWN` / `FIELDS_MISSING` flags and the context asks for
  clarification instead of guessing.
* **Clarification is suppressed when injection is suspected.** A request
  showing override/identity-claim language is flagged
  (`INJECTION_SUSPECTED`) and left for the policy engine to
  deny/escalate — not clarified with.

### Flags and safety

Flag details never contain raw client text; they reference signal names,
metadata key names, reason codes, and counts only. A bounded copy of the
purpose claim is retained in `purpose.claimed` (untrusted input, for
audit review); use `purpose.claimed_hash` for log correlation.

| Flag | Severity | Meaning |
| --- | --- | --- |
| `IDENTITY_CLAIM_IGNORED` | high | Authorization-looking client metadata was recorded and ignored |
| `INJECTION_SUSPECTED` | high | Override/identity-claim language in the purpose claim or detail |
| `DEPARTMENT_SCOPE_MISMATCH` | high | Department-scoped target ≠ requester's department |
| `AGENT_CLAIM_MISMATCH` | warning | Client-declared agent name ≠ authenticated service identity |
| `OPERATION_NOT_ALLOWED` | warning | RBAC/scope pre-check failed |
| `OPERATION_UNRECOGNIZED` | warning | Operation outside the recognised set |
| `RESOURCE_UNKNOWN` | warning | Resource not in the data catalog |
| `FIELDS_MISSING` | warning | Requested fields not resolvable in the catalog |
| `FIELDS_TRUNCATED` | warning | Requested field list exceeded the bound |
| `NO_POLICY_FOR_RESOURCE` | warning | No active policy covers the resource |
| `DESTINATION_UNRECOGNIZED` | warning | Server-declared destination kind not recognised |
| `OWNERSHIP_NOT_MATCHED` | info | Ownership check ran and did not match |
| `PURPOSE_MISSING` / `PURPOSE_UNRECOGNIZED` | info / warning | Purpose absent or not a recognised value |

The context marks every component as `trusted` (requester, agent,
operation authorization, catalog, ownership check, policies,
server-declared destination) or `untrusted` (purpose, requested fields,
target entity, conversation metadata, client metadata) so downstream
consumers never have to guess.

## 6. Configuration reference

| Setting | Default | Purpose |
| --- | --- | --- |
| `CLASSIFIER_NLP_ENABLED` | `true` | Allow building the Presidio/spaCy detector |
| `CLASSIFIER_SPACY_MODEL` | `en_core_web_sm` | Preferred spaCy model (falls back to installed lg/md/sm) |
| `CLASSIFIER_LANGUAGE` | `en` | Detector language |
| `CLASSIFIER_NLP_SCORE_THRESHOLD` | `0.5` | Drop NLP entities below this score |
| `CLASSIFIER_UNCERTAINTY_THRESHOLD` | `0.75` | Raise handling to escalate below this confidence |
| `CLASSIFIER_UNKNOWN_FIELD_SENSITIVITY` | `high` | Sensitivity for unresolved structured fields |
| `CLASSIFIER_UNCERTAIN_HANDLING` | `escalate` | Minimum handling for uncertain results |
| `SENSITIVITY_LABEL_SCHEME` | `business` | Presentation labels (`business` or `standard`) |

## 7. Testing

```bash
cd backend
.venv/Scripts/python -m pytest tests/test_classifier.py tests/test_context_analyzer.py -v
```

* Engine tests use `nlp=None` for deterministic behaviour and a fake
  detector for threshold/uncertainty paths — no external services.
* The real Presidio/spaCy test runs when the libraries and a model are
  installed and skips cleanly otherwise (CI downloads
  `en_core_web_sm`).
* Context tests verify that client-supplied text and metadata cannot
  elevate permissions, that ownership/department scope comes from the
  database, and that flags never carry raw claim text.
