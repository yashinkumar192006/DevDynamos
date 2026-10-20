# ContextShield — Project Specification

> **Version:** 1.1.0  
> **Status:** Reference specification — implemented; reconciled with the release  
> **Last Updated:** 2026-10-20  
> **Team:** DevDynamos — DEVHOST Hackathon 2026

---

## 1. Executive Summary

ContextShield is a **reusable, context-aware privacy enforcement SDK and API gateway** designed to be integrated with existing AI agents. It ensures that sensitive data is never disclosed inappropriately by enforcing the **Contextual Integrity** framework (Nissenbaum, 2004) — which defines privacy not as secrecy, but as *appropriate information flow*.

The product is a **backend middleware layer** that sits between AI agents (or any data-consuming client) and the data sources they access. A React-based demonstration frontend exists solely to showcase the engine's capabilities; the frontend is **not** a security boundary.

---

## 2. Problem Statement

Enterprise AI agents increasingly access sensitive data: salaries, PII, medical records, financial details, and customer information. Traditional access control uses static, binary allow/deny rules that cannot capture the contextual nuance of real-world privacy norms.

**Example:** An HR manager should see salary data during a performance review, but not when satisfying personal curiosity. A support agent should see a customer's phone number when resolving an active ticket, but not for marketing campaigns. The *same data*, the *same user*, completely different privacy requirements depending on context.

ContextShield solves this by making **every data access decision contextual** — evaluating who is asking, what they are asking for, why they are asking, and whether a relevant information-flow norm permits the disclosure.

---

## 3. Product Scope

### 3.1 In-Scope

| Capability                                | Description                                                       |
|-------------------------------------------|-------------------------------------------------------------------|
| **Python SDK**                            | Importable library for direct integration with Python AI agents   |
| **HTTP API Gateway**                      | FastAPI-based REST API for language-agnostic integration          |
| **Sensitive-Data Classification**         | Hybrid Presidio NLP + deterministic schema-annotation classifier  |
| **Context Analyzer**                      | Server-side evaluation of requester identity, role, and purpose   |
| **Deterministic Policy Engine**           | Rule-based information-flow norm evaluation (no LLM decisions)    |
| **Minimum-Disclosure Transformer**        | Field-level ALLOW / MASK / TOKENIZE / GENERALIZE / AGGREGATE / BLOCK / ESCALATE |
| **Backend LLM Adapter**                   | Provider-independent interface for LLM calls with privacy guard   |
| **Output Privacy Guard**                  | Scans LLM responses for PII leakage before returning to client    |
| **Audit & Explainability**               | Immutable audit log with reason codes and hashed values only      |
| **JWT Authentication & RBAC**            | Secure, server-side identity and role verification                |
| **Demo Frontend**                         | React/Vite dashboard showing live policy decisions and audit logs |
| **Mock LLM Provider**                     | Deterministic mock for testing; optional Gemini API integration   |

### 3.2 Out-of-Scope (v1)

- Real-time streaming LLM responses (v2)
- Multi-tenant isolation (v2)
- Mobile native SDKs (v2)
- Custom policy authoring UI (v2)
- Federated data sources across organizations (v2)

---

## 4. Functional Requirements

### FR-1: Secure Request Pipeline

The system shall accept a structured request describing: the authenticated requester, the data fields being requested, the stated purpose, and the target entity. It shall return a privacy-enforced response with per-field decisions.

### FR-2: Authentication & Authorization

- Users authenticate with email/password, receiving a JWT.
- All protected endpoints require a valid JWT.
- Roles and permissions are read from the database, never from client claims.
- Demo users are seeded for development/testing.

### FR-3: Sensitive-Data Classification

- Classify data fields using Microsoft Presidio (spaCy NLP) for free-text PII.
- Use deterministic database schema annotations as the authoritative source for structured business data.
- Support 12 entity types: `PERSON_NAME`, `EMAIL`, `PHONE_NUMBER`, `SSN`, `ADDRESS`, `DATE_OF_BIRTH`, `SALARY`, `MEDICAL_RECORD`, `CREDIT_CARD`, `BANK_ACCOUNT`, `PASSWORD`, `API_KEY`.
- Support 4 sensitivity levels: `LOW`, `MEDIUM`, `HIGH`, `RESTRICTED`.
- NLP detection is a signal; schema annotations are authoritative.

### FR-4: Context Analysis

- Resolve the authenticated requester's identity, role, department, and clearance level server-side.
- Accept a user-claimed purpose but treat it as **untrusted** until validated against allowed norms.
- Support initial scenarios: HR salary review, department statistics, customer contact lookup, order status.
- Flag ambiguous or sensitive requests for clarification or escalation.

### FR-5: Deterministic Policy Evaluation

- Evaluate requests against a set of information-flow norms defined as policy rules.
- Each policy specifies: who (roles), what (data types/sensitivity), why (purposes), and the permitted action.
- The LLM never decides its own access permissions.
- Policy decisions are deterministic and reproducible.

### FR-6: Data Transformation

- Apply per-field transformations based on policy decisions: `ALLOW`, `MASK`, `TOKENIZE`, `GENERALIZE`, `AGGREGATE`, `BLOCK`, `ESCALATE`.
- Transformations are applied before data enters any LLM prompt.
- The output transformer scans LLM responses for re-introduced PII.

### FR-7: Audit Logging

- Every privacy decision is logged immutably.
- Logs contain: request context, policy applied, action taken, reason code, timestamp.
- Logs contain **hashed values only**, never raw PII.
- Logs are queryable by time range, user, decision type, and policy.

### FR-8: LLM Integration

- A provider-independent adapter interface for making LLM calls.
- A built-in mock LLM for deterministic testing.
- Optional Gemini API integration behind feature flag.
- LLM prompts contain only privacy-enforced data (never raw PII).

### FR-9: Dashboard & Analytics

- Overview metrics: total requests, decisions by type, policy violations.
- Audit event browser with filtering and detail views.
- Data asset inventory showing classification status.

---

## 5. Non-Functional Requirements

| Category           | Requirement                                                             |
|--------------------|-------------------------------------------------------------------------|
| **Performance**    | API response latency < 500ms for 95th percentile (excluding LLM calls) |
| **Scalability**    | Stateless backend; horizontal scaling behind a load balancer            |
| **Availability**   | Graceful degradation; fail-closed on policy check failures              |
| **Security**       | See `docs/security-model.md` for complete threat model                  |
| **Observability**  | Structured JSON logging; request ID correlation; health endpoints       |
| **Testability**    | ≥80% code coverage; deterministic test fixtures; no external deps in tests |
| **Portability**    | Docker Compose for local dev; container-ready for cloud deployment      |

---

## 6. Technical Stack

| Layer              | Technology                                              |
|--------------------|---------------------------------------------------------|
| **Frontend**       | React 19, Vite 8, TypeScript, Tailwind CSS, Axios, React Router, Recharts |
| **Backend**        | Python 3.12+, FastAPI 0.115+, Pydantic 2.x, Uvicorn    |
| **Database**       | PostgreSQL 16, SQLAlchemy 2.x (async), Alembic          |
| **NLP / PII**      | Microsoft Presidio, spaCy (`en_core_web_sm`)            |
| **Auth**           | python-jose (JWT HS256), passlib (bcrypt)                |
| **Logging**        | structlog (structured JSON)                              |
| **Testing**        | pytest, pytest-asyncio, httpx, Playwright               |
| **Infrastructure** | Docker, Docker Compose, GitHub Actions CI                |

---

## 7. Assumptions and Constraints

1. The demo uses a single-tenant PostgreSQL instance. Multi-tenancy is out of scope for v1.
2. All classification happens locally — no PII is sent to external services.
3. The frontend is a **demonstration interface** and is never the security boundary.
4. Policy rules are defined in the database and seeded via migration scripts. A policy authoring UI is out of scope for v1.
5. The mock LLM provider is sufficient for demo and testing. Real LLM integration is optional.
6. The system operates on a request-response model; streaming is out of scope for v1.

---

## 8. Success Criteria

| Criterion                      | Measurement                                                  |
|--------------------------------|--------------------------------------------------------------|
| **Privacy enforcement works**  | All 4 demo scenarios produce correct per-field decisions     |
| **No PII leakage**             | Output guard catches 100% of known entity types in responses |
| **Audit completeness**         | Every request produces an audit record with hashed values    |
| **Fail-closed behavior**       | Ambiguous/errored requests default to BLOCK, never ALLOW     |
| **Tests pass**                 | pytest suite ≥80% coverage, all green in CI                  |
| **Demo is compelling**         | Frontend visualizes the pipeline clearly with real scenarios  |

---

## 9. Definitions

| Term                        | Definition                                                                 |
|-----------------------------|----------------------------------------------------------------------------|
| **Contextual Integrity**    | Framework defining privacy as appropriate information flow (Nissenbaum, 2004) |
| **Information-Flow Norm**   | A 5-tuple: (sender, recipient, data type, purpose, transmission principle) |
| **Minimum Disclosure**      | Principle that only data strictly necessary for the verified purpose is released |
| **Mosaic Effect**           | Risk of re-identification by combining individually safe disclosures       |
| **Fail-Closed**             | Default behavior that denies access when a policy check cannot be resolved |
| **Schema Annotation**       | Database-level metadata marking a column's sensitivity classification      |
| **Deterministic Policy**    | Policy evaluation that produces the same output for the same input, with no LLM involvement |
