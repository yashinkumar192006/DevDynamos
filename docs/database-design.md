# ContextShield — Database Design

> **Version:** 1.0.0  
> **Status:** Draft — conceptual design. The implemented schema lives in `backend/app/models/` and is managed by the Alembic `initial schema` migration; it includes RBAC tables (`users`, `roles`, `permissions`, `user_roles`), metadata tables (`data_assets`, `data_fields`, `data_classifications`), privacy tables (`privacy_policies`, `privacy_requests`, `request_contexts`, `privacy_decisions`), enforcement tables (`transformation_events`, `ai_interactions`, `output_inspections`), audit tables (`audit_events`, `session_disclosures`), protected business data (`employees`, `customers`, `orders`, `business_documents`), and machine identities for AI agents/SDK clients (`service_accounts`, added by the `add service accounts` migration). Operational setup is documented in [`database-setup.md`](./database-setup.md); authentication mechanics in [`authentication.md`](./authentication.md).  
> **Last Updated:** 2026-10-18

---

## 1. Overview

ContextShield uses **PostgreSQL 16** with **SQLAlchemy 2.x** (async mode via `asyncpg`) and **Alembic** for schema migrations. The database stores:

- User accounts and roles (authentication & RBAC)
- Business data for the demo scenarios (employees, customers, orders)
- Privacy policies and policy versions
- Audit events (immutable log)
- Data asset metadata (field-level classification)

---

## 2. Entity-Relationship Diagram

```text
┌─────────────┐       ┌──────────────────┐       ┌────────────────┐
│    users     │       │   employees      │       │   customers    │
├─────────────┤       ├──────────────────┤       ├────────────────┤
│ id (PK)     │──┐    │ id (PK)          │       │ id (PK)        │
│ email       │  │    │ user_id (FK)     │───┐   │ full_name      │
│ hashed_pw   │  │    │ full_name        │   │   │ email          │
│ full_name   │  │    │ email            │   │   │ phone          │
│ role        │  │    │ phone            │   │   │ address        │
│ department  │  ├───▶│ ssn_hash         │   │   │ account_tier   │
│ clearance   │  │    │ salary           │   │   │ created_at     │
│ is_active   │  │    │ department       │   │   └───────┬────────┘
│ created_at  │  │    │ hire_date        │   │           │
│ updated_at  │  │    │ manager_id (FK)  │   │   ┌───────▼────────┐
└─────────────┘  │    │ created_at       │   │   │    orders      │
                 │    └──────────────────┘   │   ├────────────────┤
                 │                           │   │ id (PK)        │
                 │    ┌──────────────────┐   │   │ customer_id(FK)│
                 │    │  access_policies │   │   │ order_number   │
                 │    ├──────────────────┤   │   │ status         │
                 │    │ id (PK)          │   │   │ total_amount   │
                 │    │ version          │   │   │ items (JSONB)  │
                 │    │ name             │   │   │ created_at     │
                 │    │ description      │   │   │ updated_at     │
                 │    │ allowed_roles    │   │   └────────────────┘
                 │    │ data_types       │   │
                 │    │ sensitivity_lvls │   │   ┌────────────────┐
                 │    │ allowed_purposes │   │   │  audit_events  │
                 │    │ action           │   │   ├────────────────┤
                 │    │ transmission_pr  │   │   │ id (PK)        │
                 │    │ priority         │   │   │ request_id     │
                 │    │ is_active        │   │   │ requester_id   │
                 │    │ effective_from   │   │   │ requester_role │
                 │    │ effective_until  │   │   │ target_entity  │
                 │    │ created_at       │   │   │ purpose        │
                 │    │ updated_at       │   │   │ purpose_valid  │
                 │    └──────────────────┘   │   │ fields_req     │
                 │                           │   │ decisions(JSON)│
                 │    ┌──────────────────┐   │   │ overall_dec    │
                 │    │   data_assets    │   │   │ guard_triggered│
                 │    ├──────────────────┤   │   │ value_hashes   │
                 │    │ id (PK)          │   │   │ mosaic_warning │
                 │    │ name             │   │   │ session_id     │
                 │    │ description      │   │   │ created_at     │
                 │    │ table_name       │   │   └────────────────┘
                 │    │ fields (JSONB)   │   │
                 │    │ record_count     │   │
                 │    │ created_at       │   │
                 │    │ updated_at       │   │
                 │    └──────────────────┘   │
                 └──────────────────────────┘
```

---

## 3. Table Definitions

### 3.1 `users`

The authentication and authorization table. Every human account in the system.

| Column           | Type                    | Constraints                     | Description                          |
|------------------|-------------------------|---------------------------------|--------------------------------------|
| `id`             | `UUID`                  | PK, default `gen_random_uuid()` | Unique user identifier               |
| `email`          | `VARCHAR(255)`          | UNIQUE, NOT NULL                | Login email address                  |
| `hashed_password`| `VARCHAR(255)`          | NOT NULL                        | bcrypt hash (never plaintext)        |
| `full_name`      | `VARCHAR(255)`          | NOT NULL                        | Display name                         |
| `role`           | `VARCHAR(50)`           | NOT NULL, CHECK constraint      | One of: `employee`, `hr_staff`, `hr_manager`, `department_manager`, `support_agent`, `support_lead`, `sales_rep`, `executive`, `admin` |
| `department`     | `VARCHAR(100)`          | NOT NULL                        | Department name                      |
| `clearance_level`| `VARCHAR(20)`           | NOT NULL, DEFAULT `'low'`       | One of: `low`, `medium`, `high`, `restricted` |
| `is_active`      | `BOOLEAN`               | NOT NULL, DEFAULT `true`        | Whether the account is enabled       |
| `created_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Account creation timestamp           |
| `updated_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Last modification timestamp          |

**Indexes:**
- `idx_users_email` — UNIQUE on `email`
- `idx_users_role` — on `role`
- `idx_users_department` — on `department`

**Valid Roles (CHECK constraint):**
```sql
CHECK (role IN (
  'employee', 'hr_staff', 'hr_manager',
  'department_manager', 'support_agent', 'support_lead',
  'sales_rep', 'executive', 'admin'
))
```

---

### 3.2 `employees`

Business data table representing employee records. This is the **protected data** that the privacy engine guards.

| Column           | Type                    | Constraints                     | Description                              |
|------------------|-------------------------|---------------------------------|------------------------------------------|
| `id`             | `UUID`                  | PK, default `gen_random_uuid()` | Unique employee record identifier        |
| `user_id`        | `UUID`                  | FK → `users.id`, UNIQUE, NULL   | Link to user account (if exists)         |
| `employee_number`| `VARCHAR(20)`           | UNIQUE, NOT NULL                | Human-readable employee ID               |
| `full_name`      | `VARCHAR(255)`          | NOT NULL                        | Full legal name *[sensitivity: MEDIUM]*  |
| `email`          | `VARCHAR(255)`          | NOT NULL                        | Work email *[sensitivity: MEDIUM]*       |
| `phone`          | `VARCHAR(50)`           | NULL                            | Phone number *[sensitivity: HIGH]*       |
| `ssn_hash`       | `VARCHAR(255)`          | NULL                            | SHA-256 hash of SSN *[sensitivity: RESTRICTED]* |
| `date_of_birth`  | `DATE`                  | NULL                            | DOB *[sensitivity: HIGH]*               |
| `salary`         | `NUMERIC(12,2)`         | NOT NULL                        | Annual salary *[sensitivity: RESTRICTED]*|
| `department`     | `VARCHAR(100)`          | NOT NULL                        | Department *[sensitivity: LOW]*          |
| `title`          | `VARCHAR(100)`          | NOT NULL                        | Job title *[sensitivity: LOW]*           |
| `hire_date`      | `DATE`                  | NOT NULL                        | Hire date *[sensitivity: LOW]*           |
| `manager_id`     | `UUID`                  | FK → `employees.id`, NULL       | Direct manager (self-referencing)        |
| `is_active`      | `BOOLEAN`               | NOT NULL, DEFAULT `true`        | Employment status                        |
| `created_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Record creation                          |
| `updated_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Last update                              |

**Indexes:**
- `idx_employees_user_id` — on `user_id`
- `idx_employees_department` — on `department`
- `idx_employees_manager_id` — on `manager_id`
- `idx_employees_employee_number` — UNIQUE on `employee_number`

**Security Note:** The `ssn` field is **never stored in plaintext**. Only the bcrypt/SHA-256 hash is kept. The raw SSN is never retrievable through the application, even by administrators.

---

### 3.3 `customers`

Protected customer data for the support scenario.

| Column           | Type                    | Constraints                     | Description                              |
|------------------|-------------------------|---------------------------------|------------------------------------------|
| `id`             | `UUID`                  | PK, default `gen_random_uuid()` | Unique customer identifier               |
| `customer_number`| `VARCHAR(20)`           | UNIQUE, NOT NULL                | Human-readable customer ID               |
| `full_name`      | `VARCHAR(255)`          | NOT NULL                        | Full name *[sensitivity: MEDIUM]*        |
| `email`          | `VARCHAR(255)`          | NOT NULL                        | Email *[sensitivity: MEDIUM]*            |
| `phone`          | `VARCHAR(50)`           | NULL                            | Phone *[sensitivity: HIGH]*              |
| `address`        | `TEXT`                  | NULL                            | Mailing address *[sensitivity: HIGH]*    |
| `account_tier`   | `VARCHAR(20)`           | NOT NULL, DEFAULT `'standard'`  | `standard`, `premium`, `enterprise`      |
| `is_active`      | `BOOLEAN`               | NOT NULL, DEFAULT `true`        | Active customer                          |
| `created_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Created                                  |
| `updated_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Updated                                  |

**Indexes:**
- `idx_customers_customer_number` — UNIQUE on `customer_number`
- `idx_customers_email` — on `email`

---

### 3.4 `orders`

Order data linked to customers.

| Column           | Type                    | Constraints                     | Description                              |
|------------------|-------------------------|---------------------------------|------------------------------------------|
| `id`             | `UUID`                  | PK, default `gen_random_uuid()` | Unique order identifier                  |
| `customer_id`    | `UUID`                  | FK → `customers.id`, NOT NULL   | Owning customer                          |
| `order_number`   | `VARCHAR(20)`           | UNIQUE, NOT NULL                | Human-readable order ID                  |
| `status`         | `VARCHAR(30)`           | NOT NULL                        | `pending`, `processing`, `shipped`, `delivered`, `cancelled` |
| `total_amount`   | `NUMERIC(12,2)`         | NOT NULL                        | Order total *[sensitivity: MEDIUM]*      |
| `items`          | `JSONB`                 | NOT NULL, DEFAULT `'[]'`        | Line items array                         |
| `shipping_address`| `TEXT`                 | NULL                            | Delivery address *[sensitivity: HIGH]*   |
| `created_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Order placed                             |
| `updated_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Last status change                       |

**Indexes:**
- `idx_orders_customer_id` — on `customer_id`
- `idx_orders_order_number` — UNIQUE on `order_number`
- `idx_orders_status` — on `status`

---

### 3.5 `access_policies`

Information-flow norms used by the deterministic policy engine.

| Column                | Type                    | Constraints                     | Description                              |
|-----------------------|-------------------------|---------------------------------|------------------------------------------|
| `id`                  | `UUID`                  | PK, default `gen_random_uuid()` | Unique policy identifier                 |
| `version`             | `INTEGER`               | NOT NULL, DEFAULT `1`           | Monotonically increasing version         |
| `name`                | `VARCHAR(100)`          | NOT NULL                        | Human-readable policy name               |
| `description`         | `TEXT`                  | NOT NULL                        | Detailed description                     |
| `allowed_roles`       | `JSONB`                 | NOT NULL                        | Array of role strings                    |
| `data_types`          | `JSONB`                 | NOT NULL                        | Array of entity type strings             |
| `sensitivity_levels`  | `JSONB`                 | NOT NULL                        | Array of sensitivity level strings       |
| `allowed_purposes`    | `JSONB`                 | NOT NULL                        | Array of purpose strings                 |
| `action`              | `VARCHAR(20)`           | NOT NULL                        | `ALLOW`, `MASK`, `TOKENIZE`, `GENERALIZE`, `AGGREGATE`, `BLOCK`, `ESCALATE` |
| `transmission_principle` | `TEXT`               | NULL                            | Additional constraint text               |
| `priority`            | `INTEGER`               | NOT NULL, DEFAULT `50`          | Higher wins on conflict                  |
| `is_active`           | `BOOLEAN`               | NOT NULL, DEFAULT `true`        | Whether currently enforced               |
| `effective_from`      | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | When norm becomes active                 |
| `effective_until`     | `TIMESTAMPTZ`           | NULL                            | When norm expires (null = no expiry)     |
| `created_at`          | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Created                                  |
| `updated_at`          | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Updated                                  |

**Indexes:**
- `idx_policies_name_version` — UNIQUE on `(name, version)`
- `idx_policies_is_active` — on `is_active`
- `idx_policies_action` — on `action`

**JSONB Column Conventions:**
```json
// allowed_roles
["hr_manager", "executive"]

// data_types
["SALARY", "PERSON_NAME", "DEPARTMENT"]

// sensitivity_levels
["RESTRICTED", "HIGH"]

// allowed_purposes
["performance_review", "compensation_planning"]
```

---

### 3.6 `audit_events`

Immutable audit log. **No UPDATE or DELETE operations are permitted.**

| Column                | Type                    | Constraints                     | Description                              |
|-----------------------|-------------------------|---------------------------------|------------------------------------------|
| `id`                  | `UUID`                  | PK, default `gen_random_uuid()` | Unique audit event identifier            |
| `request_id`          | `UUID`                  | NOT NULL                        | Correlation ID for the HTTP request      |
| `requester_id`        | `UUID`                  | FK → `users.id`, NOT NULL       | Who made the request                     |
| `requester_role`      | `VARCHAR(50)`           | NOT NULL                        | Role at time of request                  |
| `requester_department`| `VARCHAR(100)`          | NOT NULL                        | Department at time of request            |
| `target_entity_id`    | `VARCHAR(100)`          | NOT NULL                        | Entity being queried                     |
| `purpose_claimed`     | `VARCHAR(100)`          | NOT NULL                        | Stated purpose                           |
| `purpose_verified`    | `BOOLEAN`               | NOT NULL                        | Whether purpose was validated            |
| `fields_requested`    | `JSONB`                 | NOT NULL                        | Array of field names requested           |
| `decisions`           | `JSONB`                 | NOT NULL                        | Array of per-field decision objects       |
| `overall_decision`    | `VARCHAR(30)`           | NOT NULL                        | `ALLOW`, `PARTIAL_ALLOW`, `BLOCK`, `ESCALATION_NEEDED` |
| `guard_triggered`     | `BOOLEAN`               | NOT NULL, DEFAULT `false`       | Whether Output Guard intervened          |
| `value_hashes`        | `JSONB`                 | NOT NULL, DEFAULT `'{}'`        | SHA-256 hashes of actual values          |
| `mosaic_warning`      | `BOOLEAN`               | NOT NULL, DEFAULT `false`       | Whether mosaic risk was detected         |
| `session_id`          | `VARCHAR(100)`          | NULL                            | Session for mosaic tracking              |
| `created_at`          | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Event timestamp                          |

**Indexes:**
- `idx_audit_requester_id` — on `requester_id`
- `idx_audit_created_at` — on `created_at`
- `idx_audit_overall_decision` — on `overall_decision`
- `idx_audit_target_entity` — on `target_entity_id`

**Immutability enforcement:**
```sql
-- Application-level: no UPDATE/DELETE methods in the repository
-- Database-level (optional, recommended for production):
CREATE RULE audit_no_update AS ON UPDATE TO audit_events DO INSTEAD NOTHING;
CREATE RULE audit_no_delete AS ON DELETE TO audit_events DO INSTEAD NOTHING;
```

---

### 3.7 `data_assets`

Metadata about available data sources and their field-level classifications.

| Column           | Type                    | Constraints                     | Description                              |
|------------------|-------------------------|---------------------------------|------------------------------------------|
| `id`             | `UUID`                  | PK, default `gen_random_uuid()` | Unique data asset identifier             |
| `name`           | `VARCHAR(100)`          | UNIQUE, NOT NULL                | Asset name (e.g., "Employee Records")    |
| `description`    | `TEXT`                  | NOT NULL                        | What this asset contains                 |
| `table_name`     | `VARCHAR(100)`          | NOT NULL                        | Corresponding database table             |
| `fields`         | `JSONB`                 | NOT NULL                        | Array of field metadata objects           |
| `record_count`   | `INTEGER`               | NOT NULL, DEFAULT `0`           | Approximate row count                    |
| `created_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Created                                  |
| `updated_at`     | `TIMESTAMPTZ`           | NOT NULL, DEFAULT `now()`       | Updated                                  |

**Field metadata JSONB structure:**
```json
[
  {
    "name": "salary",
    "entity_type": "SALARY",
    "sensitivity": "RESTRICTED",
    "data_type": "NUMERIC",
    "description": "Annual compensation",
    "source": "schema_annotation"
  },
  {
    "name": "full_name",
    "entity_type": "PERSON_NAME",
    "sensitivity": "MEDIUM",
    "data_type": "VARCHAR",
    "description": "Employee full legal name",
    "source": "schema_annotation"
  }
]
```

---

## 4. Migration Strategy

### 4.1 Alembic Configuration

```
backend/
├── alembic/
│   ├── env.py           # Async engine configuration
│   ├── script.py.mako   # Migration template
│   └── versions/
│       ├── 001_initial_schema.py
│       ├── 002_seed_demo_users.py
│       ├── 003_seed_employees.py
│       ├── 004_seed_customers_orders.py
│       ├── 005_seed_policies.py
│       └── 006_seed_data_assets.py
```

### 4.2 Migration Commands

```bash
# Generate a new migration
alembic revision --autogenerate -m "description"

# Apply all migrations
alembic upgrade head

# Rollback one step
alembic downgrade -1

# Show current revision
alembic current
```

### 4.3 Seed Data Strategy

- Migrations `002`–`006` are seed scripts that insert demo data.
- Seed scripts are **idempotent** — they check for existence before inserting.
- All seed passwords are hashed with bcrypt (never plaintext in migration files).
- SSN values are stored as SHA-256 hashes only.

---

## 5. Demo Seed Data

### 5.1 Demo Users

| Email                                  | Name            | Role               | Department        | Clearance    |
|----------------------------------------|-----------------|--------------------|--------------------|--------------|
| `admin@contextshield.demo`             | Admin User      | `admin`            | IT                 | `restricted` |
| `alice.chen@contextshield.demo`        | Alice Chen      | `hr_manager`       | Human Resources    | `restricted` |
| `bob.wilson@contextshield.demo`        | Bob Wilson      | `hr_staff`         | Human Resources    | `high`       |
| `carol.davis@contextshield.demo`       | Carol Davis     | `department_manager`| Engineering       | `high`       |
| `dave.kumar@contextshield.demo`        | Dave Kumar      | `employee`         | Engineering        | `low`        |
| `eve.johnson@contextshield.demo`       | Eve Johnson     | `support_agent`    | Customer Support   | `medium`     |
| `frank.miller@contextshield.demo`      | Frank Miller    | `support_lead`     | Customer Support   | `high`       |
| `grace.lee@contextshield.demo`         | Grace Lee       | `sales_rep`        | Sales              | `medium`     |
| `henry.taylor@contextshield.demo`      | Henry Taylor    | `executive`        | Executive          | `restricted` |

**All demo passwords:** `Demo-Pass-123!` (hashed with bcrypt in the seed script)

### 5.2 Demo Employees

25 employee records across departments: Engineering (8), Human Resources (4), Customer Support (5), Sales (4), Executive (2), Finance (2).

### 5.3 Demo Customers

10 customer records with varying account tiers (`standard`, `premium`, `enterprise`) and associated orders.

### 5.4 Demo Orders

20 orders across different statuses and customers.

---

## 6. Performance Considerations

| Area                    | Strategy                                                  |
|-------------------------|-----------------------------------------------------------|
| **Connection pooling**  | SQLAlchemy async pool, `pool_size=10`, `max_overflow=20`  |
| **Query optimization**  | Indexes on all FK and frequently filtered columns         |
| **Audit table growth**  | `created_at` index for efficient time-range queries; partition by month in production |
| **JSONB queries**       | GIN indexes on `access_policies.allowed_roles` and `data_types` for efficient norm matching |
| **Read replicas**       | Audit reads can target a read replica in production       |

---

## 7. Security Constraints

| Constraint                                | Implementation                                    |
|-------------------------------------------|---------------------------------------------------|
| No plaintext passwords                    | `hashed_password` column, bcrypt only              |
| No plaintext SSNs                         | `ssn_hash` column, SHA-256 only                    |
| Audit immutability                        | No UPDATE/DELETE in repository; DB rules optional  |
| Minimum privilege DB user                 | App user has SELECT/INSERT/UPDATE (no DROP, no DELETE on audit) |
| Connection encryption                     | `sslmode=require` in production DATABASE_URL       |
| Environment-based credentials             | DB credentials in `.env`, never in code            |
