# 🛡️ ContextShield

> **Context-Aware Data Privacy Enforcement Engine for AI Agents**

[![CI](https://github.com/yashinkumar192006/DevDynamos/actions/workflows/ci.yml/badge.svg)](https://github.com/yashinkumar192006/DevDynamos/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18%2B-61DAFB.svg)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Table of Contents

- [Problem Statement](#-problem-statement)
- [Our Solution](#-our-solution--contextshield)
- [How It Works](#-how-it-works)
- [Architecture](#-architecture)
- [Key Features](#-key-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [API Endpoints](#-api-endpoints)
- [Use Cases & Examples](#-use-cases--examples)
- [Security Principles](#-security-principles)
- [Team](#-team)

---

## 🎯 Problem Statement

As AI agents become integral to enterprise workflows — answering employee queries, generating reports, automating customer interactions — they inevitably access **sensitive data**: salaries, personal identifiable information (PII), medical records, financial details, and customer data.

**The core challenge:**

> How do you let an AI agent access the data it needs to be useful, while ensuring it **never discloses sensitive information** to unauthorized users or in inappropriate contexts?

Traditional approaches fail because they rely on **static, binary access control** (allow/deny). But privacy is **contextual** — the same data point may be appropriate to share in one context and a violation in another:

| Scenario | Data | Recipient | Context | Should Disclose? |
|----------|------|-----------|---------|------------------|
| HR manager reviewing team | Salary | HR Manager | Performance review | ✅ Yes |
| Colleague asking chatbot | Salary | Peer employee | Casual inquiry | ❌ No |
| Support agent helping customer | Phone number | Support agent | Active ticket | ✅ Yes |
| Marketing analyst | Phone number | Marketing team | Campaign targeting | ❌ No |

Static rules can't capture this nuance. **ContextShield can.**

---

## 💡 Our Solution — ContextShield

ContextShield is a **privacy enforcement middleware** that sits between AI agents and the data they access. It implements the **Contextual Integrity** framework (Nissenbaum, 2004) — a theory from information ethics that defines privacy not as secrecy, but as **appropriate information flow**.

### The Three Pillars

```
┌─────────────────────────────────────────────────────────────┐
│                      AI Agent Request                       │
│         "Show me John's salary for the Q3 review"           │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  PILLAR 1: CLASSIFY                                         │
│  ─────────────────                                          │
│  • Detect sensitive entities (salary → FINANCIAL_PII)       │
│  • Assign sensitivity level (salary → RESTRICTED)           │
│  • Use NLP (Presidio + spaCy) + deterministic schema rules  │
│  • Trust database annotations over NLP guesses              │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  PILLAR 2: CONTEXTUALIZE                                    │
│  ────────────────────────                                   │
│  • WHO is asking? (role, department, clearance)             │
│  • WHY are they asking? (purpose: review, curiosity, task)  │
│  • WHAT norm applies? (HR can see salary for reviews)       │
│  • Verify purpose claims server-side — never trust client   │
│  • Flag ambiguous requests for clarification                │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  PILLAR 3: ENFORCE                                          │
│  ────────────────                                           │
│  • Apply minimum-disclosure: redact, mask, aggregate        │
│  • Return only what the context authorizes                  │
│  • Log every decision for audit (with hashed values only)   │
│  • Detect mosaic effects (combining safe data = unsafe)     │
│  • Never send raw PII to external LLMs or classifiers       │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    Safe AI Agent Response                    │
│      "John's compensation is in the $XX,XXX range.          │
│       Full details are available in the HR portal."         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 How It Works

### Step-by-Step Flow

1. **AI Agent Intercept** — When an AI agent (chatbot, copilot, automation) prepares to access or return data, it sends the request through ContextShield's API.

2. **Sensitive Data Classification** — ContextShield scans the data using a hybrid approach:
   - **Microsoft Presidio + spaCy** for NLP-based entity recognition (names, emails, phone numbers, SSNs)
   - **Deterministic rules** for domain-specific fields (salary, medical codes, financial accounts)
   - **Database schema annotations** as the trusted source of truth — if a column is marked `sensitivity: restricted`, that overrides any NLP result

3. **Context Analysis** — The system evaluates the full context:
   - **Requester identity** — verified server-side from JWT claims, never from user input
   - **Requester role & permissions** — looked up from the database (HR, manager, support, etc.)
   - **Stated purpose** — treated as an *untrusted claim* until validated against allowed scenarios
   - **Data sensitivity level** — matched against the requester's clearance

4. **Policy Evaluation** — Context is checked against information flow norms:
   - "HR managers MAY access salary data WHEN conducting performance reviews"
   - "Support agents MAY access customer phone numbers WHEN resolving active tickets"
   - "No one MAY access raw SSNs through the AI agent interface"

5. **Privacy Enforcement** — Based on the policy decision:
   - **ALLOW** — data passes through unchanged
   - **REDACT** — sensitive fields are removed entirely
   - **MASK** — partial data shown (e.g., `***-**-1234` for SSN)
   - **AGGREGATE** — individual values replaced with ranges or averages
   - **DENY** — request blocked with explanation

6. **Audit Logging** — Every decision is logged with:
   - Request context (who, what, why, when)
   - Policy that was applied
   - Action taken (allow/redact/mask/deny)
   - Hashed data values only — **never raw PII in logs**

7. **Mosaic Effect Detection** — ContextShield tracks what data has been disclosed across a session. Even if each individual disclosure is safe, the *combination* might not be:
   - Name + Department + Salary range → Could identify an individual
   - The system flags these compound risks and may require escalation

---

## 🏗️ Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│   Frontend   │────▶│   Backend    │────▶│     PostgreSQL       │
│  React/Vite  │◀────│   FastAPI    │◀────│  Users, Policies,    │
│  TypeScript  │     │   Python     │     │  Audit Logs, Data    │
└──────────────┘     └──────┬───────┘     └──────────────────────┘
                            │
                    ┌───────┴────────┐
                    │  ContextShield │
                    │    Engine      │
                    ├────────────────┤
                    │ ┌────────────┐ │
                    │ │ Classifier │ │  ← Presidio + spaCy + Rules
                    │ └─────┬──────┘ │
                    │ ┌─────▼──────┐ │
                    │ │  Context   │ │  ← Contextual Integrity
                    │ │  Analyzer  │ │
                    │ └─────┬──────┘ │
                    │ ┌─────▼──────┐ │
                    │ │  Privacy   │ │  ← Redact / Mask / Aggregate
                    │ │   Guard    │ │
                    │ └─────┬──────┘ │
                    │ ┌─────▼──────┐ │
                    │ │   Audit    │ │  ← Immutable decision log
                    │ │   Logger   │ │
                    │ └────────────┘ │
                    └────────────────┘
```

### Backend Architecture (Clean Layered Design)

| Layer | Responsibility | Example |
|-------|---------------|---------|
| **API Routes** (`api/v1/`) | HTTP request handling, input validation | `POST /api/v1/analyze` |
| **Schemas** (`schemas/`) | Pydantic request/response models | `ContextRequest`, `PolicyDecision` |
| **Services** (`services/`) | Business logic, orchestration | `ClassifierService`, `ContextAnalyzer` |
| **Repositories** (`repositories/`) | Database queries, data access | `UserRepository`, `PolicyRepository` |
| **Models** (`models/`) | SQLAlchemy ORM table definitions | `User`, `AccessPolicy`, `AuditLog` |
| **Core** (`core/`) | Config, security, logging, middleware | JWT handling, structured logging |

---

## ✨ Key Features

### 🔍 Intelligent Data Classification
- **12 entity types** supported: names, emails, phone numbers, SSNs, addresses, dates of birth, salary, medical records, credit cards, bank accounts, passwords, API keys
- **4 sensitivity levels**: Low, Medium, High, Restricted
- **Hybrid detection**: NLP catches free-text PII; deterministic rules handle structured business data
- **Schema-first trust model**: Database annotations are authoritative — NLP is a signal, not a decision

### 🧠 Context-Aware Authorization
- Evaluates the full context tuple: *(sender, recipient, data type, purpose, transmission principle)*
- Supports predefined scenarios: HR salary review, department statistics, customer support, order status
- **Purpose verification**: User-claimed purposes are validated against server-side policy, never blindly trusted
- **Ambiguity handling**: Unclear requests trigger clarification prompts, not silent denials

### 🔒 Privacy Enforcement
- **Minimum disclosure principle**: Only the data necessary for the stated purpose is released
- **Multiple enforcement actions**: Allow, Redact, Mask, Aggregate, Deny
- **Mosaic effect detection**: Tracks cumulative disclosures to prevent re-identification through data combination
- **Zero external data transfer**: Raw PII is never sent to external LLMs, APIs, or classifier services

### 📊 Audit & Compliance
- Every privacy decision is logged immutably
- Logs contain **hashed values only** — never raw sensitive data
- Full request context preserved for compliance review
- Dashboard for reviewing access patterns and policy violations

### 🔐 Authentication & Authorization
- JWT-based authentication (HS256)
- Role-based access control (RBAC) with database-backed roles
- Server-side authorization checks on every protected endpoint
- Secure password hashing with bcrypt
- Demo user seeding for development and testing

---

## 🛠️ Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| **Backend API** | FastAPI (Python) | Async, auto-docs, Pydantic validation |
| **Database** | PostgreSQL 16 | ACID compliance, JSONB for flexible policies |
| **ORM** | SQLAlchemy 2.x (async) | Type-safe queries, Alembic migrations |
| **NLP / PII** | Microsoft Presidio + spaCy | Production-grade entity recognition |
| **Auth** | python-jose (JWT) + passlib | Industry-standard token auth |
| **Frontend** | React + Vite + TypeScript | Fast dev experience, type safety |
| **Logging** | structlog | Structured, context-aware JSON logging |
| **Containers** | Docker + Docker Compose | Reproducible environments |
| **CI/CD** | GitHub Actions | Automated testing on every push |

---

## 📁 Project Structure

```
contextshield/
├── frontend/                  # React + Vite + TypeScript SPA
│
├── backend/
│   ├── app/
│   │   ├── api/v1/            # Versioned API route handlers
│   │   ├── core/              # Config, security, logging, middleware
│   │   ├── models/            # SQLAlchemy ORM models
│   │   ├── schemas/           # Pydantic request/response schemas
│   │   ├── repositories/      # Database access layer (queries)
│   │   ├── services/          # Business logic & orchestration
│   │   │   ├── classifier.py  # Sensitive data classification engine
│   │   │   └── context_service.py  # Context analyzer
│   │   └── main.py            # FastAPI application entry point
│   ├── alembic/               # Database migration scripts
│   ├── tests/                 # Backend unit & integration tests
│   ├── requirements.txt       # Python dependencies
│   └── Dockerfile
│
├── sdk/                       # Reusable client library / SDK
├── policies/                  # Privacy policy definition files
├── database/seed/             # Database seed scripts (demo data)
├── examples/                  # Usage examples & tutorials
├── docs/                      # Project documentation
├── tests/                     # End-to-end / integration tests
│
├── .github/workflows/ci.yml   # GitHub Actions CI pipeline
├── .env.example               # Environment variable template
├── .gitignore                 # Git ignore rules
├── docker-compose.yml         # Multi-service orchestration
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Minimum Version |
|-------------|----------------|
| Python | 3.12+ |
| Node.js | 20 LTS+ |
| PostgreSQL | 16+ |
| Docker Desktop | Latest (optional) |

### 1. Clone the Repository

```bash
git clone https://github.com/yashinkumar192006/DevDynamos.git
cd DevDynamos
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your database credentials and JWT secret
```

### 3. Backend Setup

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

# Start the API server
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`.

API documentation: `http://localhost:8000/docs` (Swagger UI).

### 4. Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

The UI will be available at `http://localhost:5173`.

### 5. Docker (Alternative — All Services)

```bash
docker compose up --build
```

This starts PostgreSQL, the backend, and the frontend in containers.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/api/v1/auth/login` | Authenticate and receive JWT |
| `POST` | `/api/v1/auth/logout` | Invalidate session |
| `POST` | `/api/v1/analyze` | Analyze a data request for privacy compliance |
| `POST` | `/api/v1/classify` | Classify data fields for sensitivity |
| `GET` | `/api/v1/policies` | List active privacy policies |
| `GET` | `/api/v1/audit/logs` | Query audit trail |
| `POST` | `/api/v1/session/reset` | Reset session tracking (mosaic detection) |

### Example: Analyze Request

```json
POST /api/v1/analyze
Authorization: Bearer <jwt_token>

{
  "requester_id": "user-123",
  "data_fields": ["employee_name", "salary", "department"],
  "purpose": "quarterly_performance_review",
  "target_entity": "employee-456"
}
```

**Response (authorized HR manager):**
```json
{
  "decision": "PARTIAL_ALLOW",
  "fields": {
    "employee_name": { "action": "ALLOW", "value": "Jane Smith" },
    "salary": { "action": "ALLOW", "value": 95000 },
    "department": { "action": "ALLOW", "value": "Engineering" }
  },
  "policy_applied": "hr_salary_review_norm",
  "audit_id": "aud-789"
}
```

**Response (unauthorized peer employee):**
```json
{
  "decision": "PARTIAL_DENY",
  "fields": {
    "employee_name": { "action": "ALLOW", "value": "Jane Smith" },
    "salary": { "action": "DENY", "reason": "Salary data requires HR role with review purpose" },
    "department": { "action": "ALLOW", "value": "Engineering" }
  },
  "policy_applied": "default_employee_norm",
  "audit_id": "aud-790"
}
```

---

## 🔬 Use Cases & Examples

### Use Case 1: HR Salary Review
An HR manager asks the AI assistant: *"What is John's current salary? I'm preparing his annual review."*

- **Classifier** detects `salary` → `FINANCIAL_PII` → sensitivity: `RESTRICTED`
- **Context Analyzer** verifies: requester = HR manager, purpose = performance review ✅
- **Policy** matches: "HR MAY access salary FOR performance reviews"
- **Result**: Salary disclosed. Audit log created.

### Use Case 2: Curious Colleague
A software engineer asks: *"Hey, what does Sarah in marketing make?"*

- **Classifier** detects `salary` → `FINANCIAL_PII` → sensitivity: `RESTRICTED`
- **Context Analyzer** verifies: requester = engineer, purpose = unspecified ❌
- **Policy** matches: No norm authorizes salary disclosure to peers
- **Result**: Request denied with explanation. Audit log created.

### Use Case 3: Customer Support
A support agent asks: *"I need the customer's phone number to call them about ticket #4521."*

- **Classifier** detects `phone_number` → `CONTACT_PII` → sensitivity: `HIGH`
- **Context Analyzer** verifies: requester = support agent, purpose = active ticket resolution ✅
- **Policy** matches: "Support MAY access contact info FOR active ticket resolution"
- **Result**: Phone number disclosed. Audit log created.

### Use Case 4: Mosaic Effect Detection
Over multiple queries, a user obtains: department → role → salary range → name.

- **Aggregator** tracks session disclosures
- **Mosaic detector** flags: combination of department + salary range + name = potential re-identification risk
- **Result**: Warning issued, escalation required for further queries.

---

## 🔐 Security Principles

1. **Never trust the client** — All authorization decisions are made server-side. User-supplied purpose claims are validated, never blindly accepted.

2. **Schema annotations are authoritative** — Database field metadata (sensitivity levels, classifications) override NLP detection. NLP is a signal, not a decision-maker.

3. **Minimum disclosure** — Only the data strictly necessary for the verified purpose is released. When in doubt, redact.

4. **No external PII transfer** — Raw sensitive data is never sent to external LLMs, third-party classifiers, or any external API. All classification happens locally.

5. **Audit everything** — Every access decision is logged immutably. Logs contain hashed values only — never raw PII.

6. **Defense in depth** — Multiple layers of protection: authentication → role check → context validation → policy evaluation → output filtering.

7. **Fail closed** — If context is ambiguous or a policy can't be resolved, the default action is DENY, not ALLOW.

---

## 👥 Team

**DevDynamos** — DEVHOST Hackathon 2026

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
