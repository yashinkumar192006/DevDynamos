"""Idempotent seed script for ContextShield demo data.

Usage::

    # From backend/
    python -m app.seed

The script is safe to re-run: it checks for existing records before
inserting.  All identifiers are synthetic (EMP001, CUS001, ORD0001, …)
and no real employee or customer data is imported.  Raw SSNs are never
stored — only SHA-256 hashes.
"""

import asyncio
import hashlib
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

# Ensure the backend package is importable when run from any directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Windows consoles default to a legacy code page; force UTF-8 output so the
# progress messages render instead of raising UnicodeEncodeError.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models import (
    Base,
    User,
    Role,
    Permission,
    UserRole,
    DataAsset,
    DataField,
    DataClassification,
    PrivacyPolicy,
    AuditEvent,
    AuditAction,
    SensitivityLevel,
    PolicyStatus,
    Employee,
    Customer,
    Order,
    BusinessDocument,
)


def _hash_password(password: str) -> str:
    """Create a bcrypt hash of the given password."""
    from app.core.security import hash_password

    return hash_password(password)


def _hash_ssn(ssn: str) -> str:
    """SHA-256 hash of a synthetic SSN — the raw value is never stored."""
    return hashlib.sha256(ssn.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _d(value: str) -> date:
    """Parse an ISO date string from the seed definitions."""
    return date.fromisoformat(value)


# ──────────────────────────────────────────────────────────────────────
# Demo data definitions — identities & access control
# ──────────────────────────────────────────────────────────────────────

ROLES = [
    {"name": "admin", "description": "Full system administrator"},
    {"name": "hr_manager", "description": "HR department manager – access to employee records and salaries"},
    {"name": "hr_staff", "description": "HR department staff – access to non-salary employee info"},
    {"name": "finance_manager", "description": "Finance department manager – access to financial documents"},
    {"name": "sales_manager", "description": "Sales department manager – access to customer records"},
    {"name": "sales_staff", "description": "Sales department staff – limited customer access"},
    {"name": "analyst", "description": "Data analyst – aggregated data only"},
    {"name": "viewer", "description": "Read-only viewer with minimal access"},
    # Demo roles from the scenario catalogue (example definitions only —
    # authorization always rests on the permissions/scopes behind them).
    {"name": "support_agent", "description": "Customer support agent – reads customer records for service purposes"},
    {"name": "marketing_intern", "description": "Marketing intern – aggregated/anonymised data only"},
    {"name": "customer", "description": "External customer – access limited to their own records"},
    {"name": "external_user", "description": "External collaborator – no standing data access"},
]

USERS = [
    {
        "username": "admin",
        "email": "admin@contextshield.dev",
        "full_name": "System Administrator",
        "department": "IT",
        "employee_id": "EMP000",
        "password": "Admin@2024!",
        "roles": ["admin"],
    },
    {
        "username": "sarah.chen",
        "email": "sarah.chen@contextshield.dev",
        "full_name": "Sarah Chen",
        "department": "Human Resources",
        "employee_id": "EMP001",
        "password": "SarahHR@2024!",
        "roles": ["hr_manager"],
    },
    {
        "username": "james.wilson",
        "email": "james.wilson@contextshield.dev",
        "full_name": "James Wilson",
        "department": "Human Resources",
        "employee_id": "EMP002",
        "password": "JamesHR@2024!",
        "roles": ["hr_staff"],
    },
    {
        "username": "maria.garcia",
        "email": "maria.garcia@contextshield.dev",
        "full_name": "Maria Garcia",
        "department": "Finance",
        "employee_id": "EMP003",
        "password": "MariaFin@2024!",
        "roles": ["finance_manager"],
    },
    {
        "username": "david.johnson",
        "email": "david.johnson@contextshield.dev",
        "full_name": "David Johnson",
        "department": "Sales",
        "employee_id": "EMP004",
        "password": "DavidSales@2024!",
        "roles": ["sales_manager"],
    },
    {
        "username": "emily.davis",
        "email": "emily.davis@contextshield.dev",
        "full_name": "Emily Davis",
        "department": "Sales",
        "employee_id": "EMP005",
        "password": "EmilySales@2024!",
        "roles": ["sales_staff"],
    },
    {
        "username": "alex.kumar",
        "email": "alex.kumar@contextshield.dev",
        "full_name": "Alex Kumar",
        "department": "Engineering",
        "employee_id": "EMP006",
        "password": "AlexEng@2024!",
        "roles": ["analyst"],
    },
    {
        "username": "lisa.wang",
        "email": "lisa.wang@contextshield.dev",
        "full_name": "Lisa Wang",
        "department": "Marketing",
        "employee_id": "EMP007",
        "password": "LisaMkt@2024!",
        "roles": ["viewer"],
    },
    {
        "username": "eve.johnson",
        "email": "eve.johnson@contextshield.dev",
        "full_name": "Eve Johnson",
        "department": "Customer Support",
        "employee_id": None,
        "password": "EveSupport@2024!",
        "roles": ["support_agent"],
    },
    {
        "username": "mia.torres",
        "email": "mia.torres@contextshield.dev",
        "full_name": "Mia Torres",
        "department": "Marketing",
        "employee_id": None,
        "password": "MiaIntern@2024!",
        "roles": ["marketing_intern"],
    },
]

PERMISSIONS = {
    "admin": [
        ("*", "read"),
        ("*", "write"),
        ("*", "delete"),
        ("*", "aggregate"),
    ],
    "hr_manager": [
        ("employee_records", "read"),
        ("employee_salary", "read"),
        ("employee_contact", "read"),
        ("employee_records", "write"),
        ("employee_salary", "aggregate"),
    ],
    "hr_staff": [
        ("employee_records", "read"),
        ("employee_contact", "read"),
    ],
    "finance_manager": [
        ("financial_docs", "read"),
        ("employee_salary", "aggregate"),
        ("financial_docs", "write"),
        ("order_records", "read"),
    ],
    "sales_manager": [
        ("customer_records", "read"),
        ("customer_contact", "read"),
        ("order_records", "read"),
        ("order_records", "write"),
        ("customer_records", "aggregate"),
    ],
    "sales_staff": [
        ("customer_records", "read"),
        ("order_records", "read"),
    ],
    "analyst": [
        ("employee_salary", "aggregate"),
        ("customer_records", "aggregate"),
        ("order_records", "aggregate"),
    ],
    "viewer": [
        ("employee_records", "read"),
    ],
    "support_agent": [
        ("customer_records", "read"),
        ("customer_contact", "read"),
        ("order_records", "read"),
    ],
    "marketing_intern": [
        ("customer_records", "aggregate"),
    ],
    # Customers have no standing permissions — self-service reads are
    # granted per-record through ownership checks, never through roles.
    "customer": [],
    "external_user": [],
}

# ──────────────────────────────────────────────────────────────────────
# Demo data definitions — data assets, fields & classifications
# ──────────────────────────────────────────────────────────────────────

DATA_ASSETS = [
    {
        "name": "employee_records",
        "description": "Employee personal and employment information",
        "asset_type": "employee_records",
        "owner_department": "Human Resources",
        "table_name": "employees",
        "fields": [
            {"field_name": "employee_id", "column_name": "employee_number", "field_type": "string",
             "sensitivity": "low", "pii_category": None, "description": "Synthetic employee identifier"},
            {"field_name": "full_name", "field_type": "string", "sensitivity": "medium", "pii_category": "person_name",
             "description": "Employee full name"},
            {"field_name": "email", "field_type": "string", "sensitivity": "medium", "pii_category": "email",
             "description": "Work email address"},
            {"field_name": "phone", "field_type": "string", "sensitivity": "high", "pii_category": "phone",
             "description": "Personal phone number"},
            {"field_name": "ssn", "column_name": "ssn_hash", "field_type": "string", "sensitivity": "restricted",
             "pii_category": "ssn", "description": "SSN (SHA-256 hash only — raw value never stored)"},
            {"field_name": "department", "field_type": "string", "sensitivity": "low", "pii_category": None,
             "description": "Department assignment"},
            {"field_name": "title", "field_type": "string", "sensitivity": "low", "pii_category": None,
             "description": "Job title"},
            {"field_name": "hire_date", "field_type": "date", "sensitivity": "low", "pii_category": None,
             "description": "Date of hire"},
            {"field_name": "address", "field_type": "string", "sensitivity": "high", "pii_category": "address",
             "description": "Home address"},
            {"field_name": "date_of_birth", "field_type": "date", "sensitivity": "high",
             "pii_category": "date_of_birth", "description": "Date of birth"},
        ],
    },
    {
        "name": "employee_salary",
        "description": "Employee compensation and payroll data",
        "asset_type": "employee_records",
        "owner_department": "Human Resources",
        "table_name": "employees",
        "fields": [
            {"field_name": "employee_id", "column_name": "employee_number", "field_type": "string",
             "sensitivity": "low", "pii_category": None, "description": "Synthetic employee identifier"},
            {"field_name": "base_salary", "column_name": "salary", "field_type": "number", "sensitivity": "restricted",
             "pii_category": "salary", "description": "Annual base salary"},
            {"field_name": "bonus", "field_type": "number", "sensitivity": "restricted", "pii_category": "salary",
             "description": "Annual bonus amount"},
            {"field_name": "pay_grade", "field_type": "string", "sensitivity": "high", "pii_category": None,
             "description": "Pay grade classification"},
            {"field_name": "bank_account", "column_name": "bank_account_last4", "field_type": "string",
             "sensitivity": "restricted", "pii_category": "bank_account",
             "description": "Bank account (last 4 digits only)"},
        ],
    },
    {
        "name": "customer_records",
        "description": "Customer account and contact information",
        "asset_type": "customer_records",
        "owner_department": "Sales",
        "table_name": "customers",
        "fields": [
            {"field_name": "customer_id", "column_name": "customer_number", "field_type": "string",
             "sensitivity": "low", "pii_category": None, "description": "Synthetic customer identifier"},
            {"field_name": "company_name", "field_type": "string", "sensitivity": "low", "pii_category": None,
             "description": "Company / organisation name"},
            {"field_name": "contact_name", "field_type": "string", "sensitivity": "medium",
             "pii_category": "person_name", "description": "Primary contact full name"},
            {"field_name": "contact_email", "field_type": "string", "sensitivity": "medium", "pii_category": "email",
             "description": "Primary contact email"},
            {"field_name": "contact_phone", "field_type": "string", "sensitivity": "high", "pii_category": "phone",
             "description": "Primary contact phone number"},
            {"field_name": "billing_address", "field_type": "string", "sensitivity": "high",
             "pii_category": "address", "description": "Billing address"},
            {"field_name": "credit_card_last4", "field_type": "string", "sensitivity": "high",
             "pii_category": "credit_card", "description": "Last 4 digits of card on file"},
            {"field_name": "account_status", "column_name": "is_active", "field_type": "boolean", "sensitivity": "low",
             "pii_category": None, "description": "Active or inactive customer"},
        ],
    },
    {
        "name": "order_records",
        "description": "Customer orders and transactions",
        "asset_type": "customer_records",
        "owner_department": "Sales",
        "table_name": "orders",
        "fields": [
            {"field_name": "order_id", "column_name": "order_number", "field_type": "string", "sensitivity": "low",
             "pii_category": None, "description": "Unique order identifier"},
            {"field_name": "customer_id", "column_name": "customer_id", "field_type": "string", "sensitivity": "low",
             "pii_category": None, "description": "Reference to customer"},
            {"field_name": "order_date", "field_type": "date", "sensitivity": "low", "pii_category": None,
             "description": "Date order was placed"},
            {"field_name": "total_amount", "field_type": "number", "sensitivity": "medium", "pii_category": None,
             "description": "Order total in USD"},
            {"field_name": "shipping_address", "field_type": "string", "sensitivity": "high",
             "pii_category": "address", "description": "Delivery address"},
            {"field_name": "status", "field_type": "string", "sensitivity": "low", "pii_category": None,
             "description": "pending, processing, shipped, delivered, cancelled"},
        ],
    },
    {
        "name": "financial_docs",
        "description": "Internal financial and business documents",
        "asset_type": "financial_docs",
        "owner_department": "Finance",
        "table_name": "business_documents",
        "fields": [
            {"field_name": "doc_id", "column_name": "document_number", "field_type": "string", "sensitivity": "low",
             "pii_category": None, "description": "Document identifier"},
            {"field_name": "title", "field_type": "string", "sensitivity": "low", "pii_category": None,
             "description": "Document title"},
            {"field_name": "content_summary", "field_type": "string", "sensitivity": "high", "pii_category": None,
             "description": "Summary of document content"},
            {"field_name": "classification", "field_type": "string", "sensitivity": "medium", "pii_category": None,
             "description": "internal, confidential, restricted"},
            {"field_name": "author", "column_name": "author_employee_number", "field_type": "string",
             "sensitivity": "low", "pii_category": None, "description": "Author employee ID"},
            {"field_name": "revenue_figures", "column_name": "revenue_amount", "field_type": "number",
             "sensitivity": "restricted", "pii_category": None,
             "description": "Revenue numbers when present"},
        ],
    },
]


POLICIES = [
    {
        "name": "salary_access_policy",
        "version": 1,
        "description": "Controls who may view individual salary data",
        "policy_text": (
            "Individual salary records are RESTRICTED. Only HR managers may access them "
            "for HR review purposes. Analysts may access aggregated salary statistics only."
        ),
        "resource_pattern": "employee_salary",
        "required_role": "hr_manager",
        "min_sensitivity": "restricted",
        "allowed_purposes": json.dumps(["hr_review"]),
        "allowed_actions": json.dumps(["read"]),
        "status": "active",
    },
    {
        "name": "salary_aggregate_policy",
        "version": 1,
        "description": "Allows aggregated salary queries for analysts and finance",
        "policy_text": (
            "Aggregated salary statistics (averages, medians by department) may be "
            "accessed by analysts and finance managers. Individual records are not included."
        ),
        "resource_pattern": "employee_salary",
        "required_role": "analyst",
        "min_sensitivity": "high",
        "allowed_purposes": json.dumps(["department_statistics", "analytics"]),
        "allowed_actions": json.dumps(["aggregate"]),
        "status": "active",
    },
    {
        "name": "employee_contact_policy",
        "version": 1,
        "description": "Controls access to employee PII contact fields",
        "policy_text": (
            "Employee contact information (phone, address) is HIGH sensitivity. "
            "HR staff may view work email; only HR managers may view personal phone and address."
        ),
        "resource_pattern": "employee_contact",
        "required_role": "hr_staff",
        "min_sensitivity": "high",
        "allowed_purposes": json.dumps(["hr_review"]),
        "allowed_actions": json.dumps(["read"]),
        "status": "active",
    },
    {
        "name": "customer_contact_policy",
        "version": 1,
        "description": "Controls access to customer PII fields",
        "policy_text": (
            "Customer contact data may be viewed by sales staff for customer service. "
            "Billing address and credit-card info require sales_manager role."
        ),
        "resource_pattern": "customer_contact",
        "required_role": "sales_staff",
        "min_sensitivity": "high",
        "allowed_purposes": json.dumps(["customer_service", "order_status"]),
        "allowed_actions": json.dumps(["read"]),
        "status": "active",
    },
    {
        "name": "customer_billing_policy",
        "version": 1,
        "description": "Restricts customer billing details to sales managers",
        "policy_text": (
            "Customer billing address and payment details require the sales_manager role "
            "and an explicit customer_service purpose."
        ),
        "resource_pattern": "customer_*",
        "required_role": "sales_manager",
        "min_sensitivity": "high",
        "allowed_purposes": json.dumps(["customer_service"]),
        "allowed_actions": json.dumps(["read"]),
        "status": "active",
    },
    {
        "name": "financial_docs_policy",
        "version": 1,
        "description": "Controls access to internal financial documents",
        "policy_text": (
            "Financial documents are accessible only to finance managers. "
            "Revenue figures are RESTRICTED and must not appear in AI outputs."
        ),
        "resource_pattern": "financial_docs",
        "required_role": "finance_manager",
        "min_sensitivity": "restricted",
        "allowed_purposes": json.dumps(["compliance", "analytics"]),
        "allowed_actions": json.dumps(["read"]),
        "status": "active",
    },
    {
        "name": "salary_access_policy",
        "version": 2,
        "description": "Updated salary policy — adds compliance purpose",
        "policy_text": (
            "Individual salary records are RESTRICTED. HR managers may access them for "
            "HR review. Compliance officers may access them for compliance audits."
        ),
        "resource_pattern": "employee_salary",
        "required_role": "hr_manager",
        "min_sensitivity": "restricted",
        "allowed_purposes": json.dumps(["hr_review", "compliance"]),
        "allowed_actions": json.dumps(["read"]),
        "status": "active",
    },
]

# ──────────────────────────────────────────────────────────────────────
# Demo data definitions — synthetic protected records
#
# Every record below is fictional.  SSNs are hashed before insert and
# bank/card values are truncated to last-4 digits.
# ──────────────────────────────────────────────────────────────────────

EMPLOYEES = [
    {"employee_number": "EMP000", "full_name": "System Administrator", "email": "admin@contextshield.dev",
     "department": "IT", "title": "System Administrator", "salary": 120000, "bonus": None, "pay_grade": "G7",
     "hire_date": "2022-01-10", "date_of_birth": "1985-05-12", "phone": "+1-555-0100",
     "address": "1 Admin Way, Springfield, IL 62701", "ssn": "900-10-0000", "bank_last4": "0001",
     "user": "admin", "manager": None},
    {"employee_number": "EMP001", "full_name": "Sarah Chen", "email": "sarah.chen@contextshield.dev",
     "department": "Human Resources", "title": "HR Manager", "salary": 98000, "bonus": 12000, "pay_grade": "G6",
     "hire_date": "2019-03-04", "date_of_birth": "1986-11-22", "phone": "+1-555-0101",
     "address": "12 Cedar Lane, Springfield, IL 62702", "ssn": "900-10-0001", "bank_last4": "0002",
     "user": "sarah.chen", "manager": "EMP000"},
    {"employee_number": "EMP002", "full_name": "James Wilson", "email": "james.wilson@contextshield.dev",
     "department": "Human Resources", "title": "HR Specialist", "salary": 62000, "bonus": 4000, "pay_grade": "G4",
     "hire_date": "2021-06-14", "date_of_birth": "1991-02-08", "phone": "+1-555-0102",
     "address": "48 Birch Street, Springfield, IL 62703", "ssn": "900-10-0002", "bank_last4": "0003",
     "user": "james.wilson", "manager": "EMP001"},
    {"employee_number": "EMP003", "full_name": "Maria Garcia", "email": "maria.garcia@contextshield.dev",
     "department": "Finance", "title": "Finance Manager", "salary": 105000, "bonus": 15000, "pay_grade": "G6",
     "hire_date": "2018-09-03", "date_of_birth": "1984-07-30", "phone": "+1-555-0103",
     "address": "9 Willow Court, Springfield, IL 62704", "ssn": "900-10-0003", "bank_last4": "0004",
     "user": "maria.garcia", "manager": "EMP022"},
    {"employee_number": "EMP004", "full_name": "David Johnson", "email": "david.johnson@contextshield.dev",
     "department": "Sales", "title": "Sales Manager", "salary": 99000, "bonus": 14000, "pay_grade": "G6",
     "hire_date": "2019-01-07", "date_of_birth": "1983-09-15", "phone": "+1-555-0104",
     "address": "77 Aspen Drive, Springfield, IL 62705", "ssn": "900-10-0004", "bank_last4": "0005",
     "user": "david.johnson", "manager": "EMP021"},
    {"employee_number": "EMP005", "full_name": "Emily Davis", "email": "emily.davis@contextshield.dev",
     "department": "Sales", "title": "Sales Representative", "salary": 58000, "bonus": 3000, "pay_grade": "G3",
     "hire_date": "2022-04-11", "date_of_birth": "1994-12-01", "phone": "+1-555-0105",
     "address": "203 Elm Avenue, Springfield, IL 62706", "ssn": "900-10-0005", "bank_last4": "0006",
     "user": "emily.davis", "manager": "EMP004"},
    {"employee_number": "EMP006", "full_name": "Alex Kumar", "email": "alex.kumar@contextshield.dev",
     "department": "Engineering", "title": "Data Analyst", "salary": 88000, "bonus": 6000, "pay_grade": "G5",
     "hire_date": "2020-10-19", "date_of_birth": "1990-03-25", "phone": "+1-555-0106",
     "address": "31 Spruce Way, Springfield, IL 62707", "ssn": "900-10-0006", "bank_last4": "0007",
     "user": "alex.kumar", "manager": "EMP008"},
    {"employee_number": "EMP007", "full_name": "Lisa Wang", "email": "lisa.wang@contextshield.dev",
     "department": "Marketing", "title": "Marketing Coordinator", "salary": 56000, "bonus": 2500, "pay_grade": "G3",
     "hire_date": "2023-02-06", "date_of_birth": "1996-08-17", "phone": "+1-555-0107",
     "address": "5 Poplar Place, Springfield, IL 62708", "ssn": "900-10-0007", "bank_last4": "0008",
     "user": "lisa.wang", "manager": "EMP015"},
    {"employee_number": "EMP008", "full_name": "Priya Sharma", "email": "priya.sharma@contextshield.dev",
     "department": "Engineering", "title": "Engineering Manager", "salary": 138000, "bonus": 20000, "pay_grade": "G7",
     "hire_date": "2017-05-22", "date_of_birth": "1981-01-19", "phone": "+1-555-0108",
     "address": "88 Hackberry Road, Springfield, IL 62709", "ssn": "900-10-0008", "bank_last4": "0009",
     "user": None, "manager": "EMP021"},
    {"employee_number": "EMP009", "full_name": "Daniel Lee", "email": "daniel.lee@contextshield.dev",
     "department": "Engineering", "title": "Senior Software Engineer", "salary": 128000, "bonus": 18000,
     "pay_grade": "G6", "hire_date": "2018-08-13", "date_of_birth": "1987-06-05", "phone": "+1-555-0109",
     "address": "17 Magnolia Street, Springfield, IL 62710", "ssn": "900-10-0009", "bank_last4": "0010",
     "user": None, "manager": "EMP008"},
    {"employee_number": "EMP010", "full_name": "John Park", "email": "john.park@contextshield.dev",
     "department": "Engineering", "title": "Software Engineer", "salary": 95000, "bonus": 9000, "pay_grade": "G5",
     "hire_date": "2020-03-16", "date_of_birth": "1992-04-28", "phone": "+1-555-0110",
     "address": "64 Juniper Lane, Springfield, IL 62711", "ssn": "900-10-0010", "bank_last4": "0011",
     "user": None, "manager": "EMP008"},
    {"employee_number": "EMP011", "full_name": "Mei Tanaka", "email": "mei.tanaka@contextshield.dev",
     "department": "Engineering", "title": "QA Engineer", "salary": 82000, "bonus": 5000, "pay_grade": "G4",
     "hire_date": "2021-09-06", "date_of_birth": "1993-10-14", "phone": "+1-555-0111",
     "address": "39 Sycamore Drive, Springfield, IL 62712", "ssn": "900-10-0011", "bank_last4": "0012",
     "user": None, "manager": "EMP008"},
    {"employee_number": "EMP012", "full_name": "Omar Haddad", "email": "omar.haddad@contextshield.dev",
     "department": "Engineering", "title": "DevOps Engineer", "salary": 112000, "bonus": 11000, "pay_grade": "G6",
     "hire_date": "2019-11-04", "date_of_birth": "1988-12-30", "phone": "+1-555-0112",
     "address": "92 Cottonwood Circle, Springfield, IL 62713", "ssn": "900-10-0012", "bank_last4": "0013",
     "user": None, "manager": "EMP008"},
    {"employee_number": "EMP013", "full_name": "Sofia Rossi", "email": "sofia.rossi@contextshield.dev",
     "department": "Engineering", "title": "Software Engineer", "salary": 68000, "bonus": 3000, "pay_grade": "G3",
     "hire_date": "2023-07-10", "date_of_birth": "1997-05-21", "phone": "+1-555-0113",
     "address": "8 Beechwood Terrace, Springfield, IL 62714", "ssn": "900-10-0013", "bank_last4": "0014",
     "user": None, "manager": "EMP008"},
    {"employee_number": "EMP014", "full_name": "Grace Kim", "email": "grace.kim@contextshield.dev",
     "department": "Engineering", "title": "Engineering Intern", "salary": 42000, "bonus": None, "pay_grade": "G1",
     "hire_date": "2025-06-02", "date_of_birth": "2003-03-09", "phone": "+1-555-0114",
     "address": "3 Larkspur Court, Springfield, IL 62715", "ssn": "900-10-0014", "bank_last4": "0015",
     "user": None, "manager": "EMP008"},
    {"employee_number": "EMP015", "full_name": "Sarah Lopez", "email": "sarah.lopez@contextshield.dev",
     "department": "Marketing", "title": "Marketing Manager", "salary": 92000, "bonus": 10000, "pay_grade": "G5",
     "hire_date": "2018-04-02", "date_of_birth": "1986-09-26", "phone": "+1-555-0115",
     "address": "55 Chestnut Street, Springfield, IL 62716", "ssn": "900-10-0015", "bank_last4": "0016",
     "user": None, "manager": "EMP021"},
    {"employee_number": "EMP016", "full_name": "Tom Becker", "email": "tom.becker@contextshield.dev",
     "department": "Customer Support", "title": "Support Agent", "salary": 54000, "bonus": 2000, "pay_grade": "G3",
     "hire_date": "2022-01-17", "date_of_birth": "1995-07-11", "phone": "+1-555-0116",
     "address": "11 Redwood Run, Springfield, IL 62717", "ssn": "900-10-0016", "bank_last4": "0017",
     "user": None, "manager": "EMP018"},
    {"employee_number": "EMP017", "full_name": "Nina Patel", "email": "nina.patel@contextshield.dev",
     "department": "Customer Support", "title": "Support Agent", "salary": 55000, "bonus": 2000, "pay_grade": "G3",
     "hire_date": "2021-11-08", "date_of_birth": "1994-01-03", "phone": "+1-555-0117",
     "address": "26 Mulberry Main, Springfield, IL 62718", "ssn": "900-10-0017", "bank_last4": "0018",
     "user": None, "manager": "EMP018"},
    {"employee_number": "EMP018", "full_name": "Liam O'Brien", "email": "liam.obrien@contextshield.dev",
     "department": "Customer Support", "title": "Support Lead", "salary": 72000, "bonus": 6000, "pay_grade": "G5",
     "hire_date": "2020-05-25", "date_of_birth": "1989-08-19", "phone": "+1-555-0118",
     "address": "70 Persimmon Path, Springfield, IL 62719", "ssn": "900-10-0018", "bank_last4": "0019",
     "user": None, "manager": "EMP021"},
    {"employee_number": "EMP019", "full_name": "Ava Brooks", "email": "ava.brooks@contextshield.dev",
     "department": "Customer Support", "title": "Support Specialist", "salary": 58000, "bonus": 3500, "pay_grade": "G4",
     "hire_date": "2022-08-29", "date_of_birth": "1996-02-14", "phone": "+1-555-0119",
     "address": "14 Dogwood Drive, Springfield, IL 62720", "ssn": "900-10-0019", "bank_last4": "0020",
     "user": None, "manager": "EMP018"},
    {"employee_number": "EMP020", "full_name": "Noah Fischer", "email": "noah.fischer@contextshield.dev",
     "department": "Customer Support", "title": "Support Agent", "salary": 53000, "bonus": 1500, "pay_grade": "G3",
     "hire_date": "2023-05-15", "date_of_birth": "1998-11-27", "phone": "+1-555-0120",
     "address": "41 Holly Hollow, Springfield, IL 62721", "ssn": "900-10-0020", "bank_last4": "0021",
     "user": None, "manager": "EMP018"},
    {"employee_number": "EMP021", "full_name": "Henry Taylor", "email": "henry.taylor@contextshield.dev",
     "department": "Executive", "title": "Chief Executive Officer", "salary": 240000, "bonus": 60000, "pay_grade": "G9",
     "hire_date": "2016-02-01", "date_of_birth": "1974-04-04", "phone": "+1-555-0121",
     "address": "1 Summit Ridge, Springfield, IL 62722", "ssn": "900-10-0021", "bank_last4": "0022",
     "user": None, "manager": None},
    {"employee_number": "EMP022", "full_name": "Charlotte Reed", "email": "charlotte.reed@contextshield.dev",
     "department": "Executive", "title": "Chief Financial Officer", "salary": 210000, "bonus": 45000, "pay_grade": "G9",
     "hire_date": "2017-03-20", "date_of_birth": "1979-10-08", "phone": "+1-555-0122",
     "address": "6 Summit Ridge, Springfield, IL 62723", "ssn": "900-10-0022", "bank_last4": "0023",
     "user": None, "manager": "EMP021"},
    {"employee_number": "EMP023", "full_name": "Ethan Brooks", "email": "ethan.brooks@contextshield.dev",
     "department": "Finance", "title": "Financial Analyst", "salary": 78000, "bonus": 5000, "pay_grade": "G4",
     "hire_date": "2021-07-12", "date_of_birth": "1993-06-23", "phone": "+1-555-0123",
     "address": "23 Foxglove Lane, Springfield, IL 62724", "ssn": "900-10-0023", "bank_last4": "0024",
     "user": None, "manager": "EMP003"},
    {"employee_number": "EMP024", "full_name": "Maya Singh", "email": "maya.singh@contextshield.dev",
     "department": "Human Resources", "title": "HR Business Partner", "salary": 86000, "bonus": 7000, "pay_grade": "G5",
     "hire_date": "2020-09-14", "date_of_birth": "1990-11-16", "phone": "+1-555-0124",
     "address": "34 Ivy Inlet, Springfield, IL 62725", "ssn": "900-10-0024", "bank_last4": "0025",
     "user": None, "manager": "EMP001"},
    {"employee_number": "EMP025", "full_name": "Lucas Meyer", "email": "lucas.meyer@contextshield.dev",
     "department": "Sales", "title": "Account Executive", "salary": 74000, "bonus": 12000, "pay_grade": "G4",
     "hire_date": "2021-02-08", "date_of_birth": "1991-09-07", "phone": "+1-555-0125",
     "address": "52 Kingfisher Court, Springfield, IL 62726", "ssn": "900-10-0025", "bank_last4": "0026",
     "user": None, "manager": "EMP004"},
    {"employee_number": "EMP026", "full_name": "Zoe Carter", "email": "zoe.carter@contextshield.dev",
     "department": "Sales", "title": "Sales Development Representative", "salary": 52000, "bonus": 2000,
     "pay_grade": "G2", "hire_date": "2023-10-02", "date_of_birth": "1999-01-25", "phone": "+1-555-0126",
     "address": "19 Laurel Loop, Springfield, IL 62727", "ssn": "900-10-0026", "bank_last4": "0027",
     "user": None, "manager": "EMP004"},
    {"employee_number": "EMP027", "full_name": "Olivia Chen", "email": "olivia.chen@contextshield.dev",
     "department": "Human Resources", "title": "HR Coordinator", "salary": 60000, "bonus": 2500, "pay_grade": "G3",
     "hire_date": "2022-06-20", "date_of_birth": "1997-03-31", "phone": "+1-555-0127",
     "address": "7 Marigold Mews, Springfield, IL 62728", "ssn": "900-10-0027", "bank_last4": "0028",
     "user": None, "manager": "EMP001"},
]

CUSTOMERS = [
    {"customer_number": "CUS001", "company_name": "Acme Robotics", "contact_name": "Natalie Brooks",
     "contact_email": "natalie.brooks@acme-robotics.example", "contact_phone": "+1-555-0201",
     "billing_address": "500 Innovation Drive, Austin, TX 78701", "credit_card_last4": "4242",
     "account_tier": "enterprise", "is_active": True},
    {"customer_number": "CUS002", "company_name": "Globex Manufacturing", "contact_name": "Victor Okafor",
     "contact_email": "victor.okafor@globex-mfg.example", "contact_phone": "+1-555-0202",
     "billing_address": "1200 Foundry Road, Detroit, MI 48201", "credit_card_last4": "1881",
     "account_tier": "enterprise", "is_active": True},
    {"customer_number": "CUS003", "company_name": "Initech Software", "contact_name": "Milton Waddams",
     "contact_email": "milton.waddams@initech-soft.example", "contact_phone": "+1-555-0203",
     "billing_address": "4120 Freidrich Lane, Austin, TX 78744", "credit_card_last4": "5077",
     "account_tier": "standard", "is_active": True},
    {"customer_number": "CUS004", "company_name": "Nimbus Health", "contact_name": "Dr. Amara Osei",
     "contact_email": "amara.osei@nimbus-health.example", "contact_phone": "+1-555-0204",
     "billing_address": "88 Wellness Way, Denver, CO 80202", "credit_card_last4": "6721",
     "account_tier": "premium", "is_active": True},
    {"customer_number": "CUS005", "company_name": "Vertex Logistics", "contact_name": "Pavel Novak",
     "contact_email": "pavel.novak@vertex-logistics.example", "contact_phone": "+1-555-0205",
     "billing_address": "300 Freight Terminal Blvd, Memphis, TN 38103", "credit_card_last4": "0422",
     "account_tier": "premium", "is_active": True},
    {"customer_number": "CUS006", "company_name": "BluePeak Analytics", "contact_name": "Hana Kobayashi",
     "contact_email": "hana.kobayashi@bluepeak-analytics.example", "contact_phone": "+1-555-0206",
     "billing_address": "17 Data Mesa Court, Seattle, WA 98101", "credit_card_last4": "9330",
     "account_tier": "standard", "is_active": True},
    {"customer_number": "CUS007", "company_name": "Cedar & Co Retail", "contact_name": "Grace Miller",
     "contact_email": "grace.miller@cedarco-retail.example", "contact_phone": "+1-555-0207",
     "billing_address": "220 Market Street, Portland, OR 97204", "credit_card_last4": "7715",
     "account_tier": "standard", "is_active": True},
    {"customer_number": "CUS008", "company_name": "Orbit Media Group", "contact_name": "Felix Duarte",
     "contact_email": "felix.duarte@orbit-media.example", "contact_phone": "+1-555-0208",
     "billing_address": "900 Broadcast Plaza, New York, NY 10019", "credit_card_last4": "3557",
     "account_tier": "premium", "is_active": True},
    {"customer_number": "CUS009", "company_name": "Lakeside Foods", "contact_name": "Ingrid Larsen",
     "contact_email": "ingrid.larsen@lakeside-foods.example", "contact_phone": "+1-555-0209",
     "billing_address": "44 Harbor View Road, Milwaukee, WI 53202", "credit_card_last4": "6108",
     "account_tier": "standard", "is_active": False},
    {"customer_number": "CUS010", "company_name": "Summit Financial", "contact_name": "Marcus Bell",
     "contact_email": "marcus.bell@summit-financial.example", "contact_phone": "+1-555-0210",
     "billing_address": "1 Summit Tower, Charlotte, NC 28202", "credit_card_last4": "2246",
     "account_tier": "enterprise", "is_active": True},
]

ORDERS = [
    {"order_number": "ORD0001", "customer": "CUS001", "order_date": "2026-08-04", "status": "delivered",
     "total_amount": 15400.00, "shipping_address": "500 Innovation Drive, Austin, TX 78701",
     "items": [{"sku": "RB-100", "qty": 10, "price": 1200.00}, {"sku": "RB-210", "qty": 2, "price": 1700.00}]},
    {"order_number": "ORD0002", "customer": "CUS001", "order_date": "2026-09-18", "status": "shipped",
     "total_amount": 4800.00, "shipping_address": "500 Innovation Drive, Austin, TX 78701",
     "items": [{"sku": "RB-100", "qty": 4, "price": 1200.00}]},
    {"order_number": "ORD0003", "customer": "CUS002", "order_date": "2026-07-22", "status": "delivered",
     "total_amount": 22750.00, "shipping_address": "1200 Foundry Road, Detroit, MI 48201",
     "items": [{"sku": "MFG-500", "qty": 5, "price": 4550.00}]},
    {"order_number": "ORD0004", "customer": "CUS002", "order_date": "2026-10-01", "status": "processing",
     "total_amount": 9100.00, "shipping_address": "1200 Foundry Road, Detroit, MI 48201",
     "items": [{"sku": "MFG-500", "qty": 2, "price": 4550.00}]},
    {"order_number": "ORD0005", "customer": "CUS003", "order_date": "2026-06-11", "status": "delivered",
     "total_amount": 299.00, "shipping_address": "4120 Freidrich Lane, Austin, TX 78744",
     "items": [{"sku": "SW-LIC-1", "qty": 1, "price": 299.00}]},
    {"order_number": "ORD0006", "customer": "CUS003", "order_date": "2026-09-30", "status": "pending",
     "total_amount": 897.00, "shipping_address": "4120 Freidrich Lane, Austin, TX 78744",
     "items": [{"sku": "SW-LIC-1", "qty": 3, "price": 299.00}]},
    {"order_number": "ORD0007", "customer": "CUS004", "order_date": "2026-05-15", "status": "delivered",
     "total_amount": 12600.00, "shipping_address": "88 Wellness Way, Denver, CO 80202",
     "items": [{"sku": "HL-MON-9", "qty": 3, "price": 4200.00}]},
    {"order_number": "ORD0008", "customer": "CUS004", "order_date": "2026-09-05", "status": "shipped",
     "total_amount": 8400.00, "shipping_address": "88 Wellness Way, Denver, CO 80202",
     "items": [{"sku": "HL-MON-9", "qty": 2, "price": 4200.00}]},
    {"order_number": "ORD0009", "customer": "CUS005", "order_date": "2026-08-19", "status": "delivered",
     "total_amount": 36000.00, "shipping_address": "300 Freight Terminal Blvd, Memphis, TN 38103",
     "items": [{"sku": "LOG-FLT-1", "qty": 1, "price": 36000.00}]},
    {"order_number": "ORD0010", "customer": "CUS005", "order_date": "2026-10-06", "status": "processing",
     "total_amount": 18000.00, "shipping_address": "300 Freight Terminal Blvd, Memphis, TN 38103",
     "items": [{"sku": "LOG-FLT-1", "qty": 1, "price": 18000.00}]},
    {"order_number": "ORD0011", "customer": "CUS006", "order_date": "2026-07-07", "status": "delivered",
     "total_amount": 5400.00, "shipping_address": "17 Data Mesa Court, Seattle, WA 98101",
     "items": [{"sku": "AN-DASH-2", "qty": 3, "price": 1800.00}]},
    {"order_number": "ORD0012", "customer": "CUS006", "order_date": "2026-10-12", "status": "pending",
     "total_amount": 1800.00, "shipping_address": "17 Data Mesa Court, Seattle, WA 98101",
     "items": [{"sku": "AN-DASH-2", "qty": 1, "price": 1800.00}]},
    {"order_number": "ORD0013", "customer": "CUS007", "order_date": "2026-06-27", "status": "delivered",
     "total_amount": 2450.00, "shipping_address": "220 Market Street, Portland, OR 97204",
     "items": [{"sku": "RT-POS-4", "qty": 5, "price": 490.00}]},
    {"order_number": "ORD0014", "customer": "CUS007", "order_date": "2026-09-23", "status": "cancelled",
     "total_amount": 980.00, "shipping_address": "220 Market Street, Portland, OR 97204",
     "items": [{"sku": "RT-POS-4", "qty": 2, "price": 490.00}]},
    {"order_number": "ORD0015", "customer": "CUS008", "order_date": "2026-08-30", "status": "delivered",
     "total_amount": 7350.00, "shipping_address": "900 Broadcast Plaza, New York, NY 10019",
     "items": [{"sku": "MED-CAM-7", "qty": 7, "price": 1050.00}]},
    {"order_number": "ORD0016", "customer": "CUS008", "order_date": "2026-10-10", "status": "shipped",
     "total_amount": 3150.00, "shipping_address": "900 Broadcast Plaza, New York, NY 10019",
     "items": [{"sku": "MED-CAM-7", "qty": 3, "price": 1050.00}]},
    {"order_number": "ORD0017", "customer": "CUS009", "order_date": "2026-04-14", "status": "delivered",
     "total_amount": 1980.00, "shipping_address": "44 Harbor View Road, Milwaukee, WI 53202",
     "items": [{"sku": "FD-CLD-3", "qty": 6, "price": 330.00}]},
    {"order_number": "ORD0018", "customer": "CUS009", "order_date": "2026-07-03", "status": "cancelled",
     "total_amount": 660.00, "shipping_address": "44 Harbor View Road, Milwaukee, WI 53202",
     "items": [{"sku": "FD-CLD-3", "qty": 2, "price": 330.00}]},
    {"order_number": "ORD0019", "customer": "CUS010", "order_date": "2026-05-29", "status": "delivered",
     "total_amount": 48000.00, "shipping_address": "1 Summit Tower, Charlotte, NC 28202",
     "items": [{"sku": "FIN-SEC-1", "qty": 1, "price": 48000.00}]},
    {"order_number": "ORD0020", "customer": "CUS010", "order_date": "2026-10-14", "status": "processing",
     "total_amount": 12000.00, "shipping_address": "1 Summit Tower, Charlotte, NC 28202",
     "items": [{"sku": "FIN-AUD-1", "qty": 1, "price": 12000.00}]},
]

DOCUMENTS = [
    {"document_number": "DOC001", "title": "Q3 2026 Revenue Forecast", "classification": "confidential",
     "content_summary": "Projected revenue by product line and region for Q3 2026.",
     "author_employee_number": "EMP022", "revenue_amount": 4200000.00, "document_date": "2026-07-01"},
    {"document_number": "DOC002", "title": "Annual Budget 2026", "classification": "internal",
     "content_summary": "Departmental budgets and planned expenditure for fiscal year 2026.",
     "author_employee_number": "EMP023", "revenue_amount": None, "document_date": "2026-01-15"},
    {"document_number": "DOC003", "title": "Series B Fundraising Memo", "classification": "restricted",
     "content_summary": "Summary of fundraising terms, valuation, and investor commitments.",
     "author_employee_number": "EMP021", "revenue_amount": 25000000.00, "document_date": "2026-03-22"},
    {"document_number": "DOC004", "title": "FY2025 Audited Financial Statements", "classification": "restricted",
     "content_summary": "Audited balance sheet, income statement, and cash-flow statement for FY2025.",
     "author_employee_number": "EMP022", "revenue_amount": 18250000.00, "document_date": "2026-02-28"},
    {"document_number": "DOC005", "title": "Supplier Contract Summary", "classification": "confidential",
     "content_summary": "Key terms and renewal dates for top-10 supplier agreements.",
     "author_employee_number": "EMP003", "revenue_amount": None, "document_date": "2026-04-18"},
    {"document_number": "DOC006", "title": "Marketing Spend Plan Q4", "classification": "internal",
     "content_summary": "Planned campaign budgets and channel allocation for Q4 2026.",
     "author_employee_number": "EMP015", "revenue_amount": 340000.00, "document_date": "2026-09-12"},
    {"document_number": "DOC007", "title": "Payroll Variance Report", "classification": "confidential",
     "content_summary": "Month-over-month payroll cost variance by department.",
     "author_employee_number": "EMP003", "revenue_amount": None, "document_date": "2026-08-05"},
    {"document_number": "DOC008", "title": "Board Meeting Minutes — September 2026", "classification": "restricted",
     "content_summary": "Board resolutions, executive updates, and strategic initiatives.",
     "author_employee_number": "EMP021", "revenue_amount": None, "document_date": "2026-09-25"},
]


# ──────────────────────────────────────────────────────────────────────
# Seed helpers
# ──────────────────────────────────────────────────────────────────────

async def _get_or_create(session: AsyncSession, model, defaults: dict, **lookup):
    """Return existing row if found, otherwise insert and return new."""
    stmt = select(model).filter_by(**lookup)
    result = await session.execute(stmt)
    instance = result.scalar_one_or_none()
    if instance is not None:
        return instance, False
    instance = model(**{**lookup, **defaults})
    session.add(instance)
    await session.flush()
    return instance, True


async def seed_roles(session: AsyncSession) -> dict[str, Role]:
    """Seed roles and return a name→Role mapping."""
    role_map: dict[str, Role] = {}
    for r in ROLES:
        role, created = await _get_or_create(
            session, Role, {"description": r["description"]}, name=r["name"]
        )
        role_map[r["name"]] = role
        if created:
            print(f"  ✓ Role: {r['name']}")
    return role_map


async def seed_users(session: AsyncSession, role_map: dict[str, Role]) -> dict[str, User]:
    """Seed users with hashed passwords and role assignments."""
    user_map: dict[str, User] = {}
    for u in USERS:
        user, created = await _get_or_create(
            session,
            User,
            {
                "email": u["email"],
                "full_name": u["full_name"],
                "hashed_password": _hash_password(u["password"]),
                "department": u["department"],
                "employee_id": u["employee_id"],
                "is_active": True,
            },
            username=u["username"],
        )
        user_map[u["username"]] = user
        if created:
            print(f"  ✓ User: {u['username']} ({u['employee_id']})")

        # Assign roles
        for role_name in u["roles"]:
            role = role_map.get(role_name)
            if role:
                _, role_created = await _get_or_create(
                    session, UserRole, {"granted_at": _utcnow()}, user_id=user.id, role_id=role.id
                )
                if role_created:
                    print(f"    → assigned role '{role_name}'")
    return user_map


async def seed_permissions(session: AsyncSession, role_map: dict[str, Role]):
    """Seed permissions for each role."""
    for role_name, perms in PERMISSIONS.items():
        role = role_map.get(role_name)
        if not role:
            continue
        for resource, action in perms:
            _, created = await _get_or_create(
                session, Permission, {"conditions": None}, role_id=role.id, resource=resource, action=action
            )
            if created:
                print(f"  ✓ Permission: {role_name} → {resource}:{action}")


async def seed_data_assets(session: AsyncSession) -> dict[str, DataAsset]:
    """Seed data assets and their fields."""
    asset_map: dict[str, DataAsset] = {}
    for a in DATA_ASSETS:
        asset, created = await _get_or_create(
            session,
            DataAsset,
            {
                "description": a["description"],
                "asset_type": a["asset_type"],
                "owner_department": a["owner_department"],
                "table_name": a.get("table_name"),
            },
            name=a["name"],
        )
        asset_map[a["name"]] = asset
        if created:
            print(f"  ✓ DataAsset: {a['name']} (→ {a.get('table_name')})")

        for f in a["fields"]:
            sens = SensitivityLevel(f["sensitivity"])
            field, f_created = await _get_or_create(
                session,
                DataField,
                {
                    "column_name": f.get("column_name", f["field_name"]),
                    "field_type": f["field_type"],
                    "sensitivity": sens,
                    "pii_category": f["pii_category"],
                    "description": f["description"],
                },
                asset_id=asset.id,
                field_name=f["field_name"],
            )
            if f_created:
                print(f"    → field: {f['field_name']} ({f['sensitivity']})")
                # Add an initial classification record
                session.add(DataClassification(
                    field_id=field.id,
                    classified_by="schema_annotation",
                    sensitivity=sens,
                    confidence="high",
                    entity_type=f["pii_category"],
                    notes="Initial classification from schema annotations",
                ))
    return asset_map


async def seed_policies(session: AsyncSession):
    """Seed versioned privacy policies."""
    for p in POLICIES:
        status = PolicyStatus(p["status"])  # type: ignore[arg-type]
        # If this is a v2 policy, mark v1 as superseded
        if p["version"] > 1:
            stmt = select(PrivacyPolicy).filter_by(name=p["name"], version=p["version"] - 1)
            result = await session.execute(stmt)
            prev = result.scalar_one_or_none()
            if prev and prev.status != PolicyStatus.SUPERSEDED:
                prev.status = PolicyStatus.SUPERSEDED
                print(f"  ↻ Superseded: {p['name']} v{p['version'] - 1}")

        _, created = await _get_or_create(
            session,
            PrivacyPolicy,
            {
                "description": p["description"],
                "policy_text": p["policy_text"],
                "resource_pattern": p["resource_pattern"],
                "required_role": p.get("required_role"),
                "min_sensitivity": p.get("min_sensitivity"),
                "allowed_purposes": p.get("allowed_purposes"),
                "allowed_actions": p.get("allowed_actions"),
                "status": status,
            },
            name=p["name"],
            version=p["version"],
        )
        if created:
            print(f"  ✓ Policy: {p['name']} v{p['version']} [{p['status']}]")


async def seed_employees(session: AsyncSession, user_map: dict[str, User]) -> dict[str, Employee]:
    """Seed synthetic employee records (SSNs hashed, manager links resolved)."""
    employee_map: dict[str, Employee] = {}
    for e in EMPLOYEES:
        user = user_map.get(e["user"]) if e.get("user") else None
        employee, created = await _get_or_create(
            session,
            Employee,
            {
                "user_id": user.id if user else None,
                "full_name": e["full_name"],
                "email": e["email"],
                "phone": e["phone"],
                "address": e["address"],
                "date_of_birth": _d(e["date_of_birth"]),
                "ssn_hash": _hash_ssn(e["ssn"]),
                "salary": e["salary"],
                "bonus": e["bonus"],
                "pay_grade": e["pay_grade"],
                "bank_account_last4": e["bank_last4"],
                "department": e["department"],
                "title": e["title"],
                "hire_date": _d(e["hire_date"]),
                "is_active": True,
            },
            employee_number=e["employee_number"],
        )
        employee_map[e["employee_number"]] = employee
        if created:
            print(f"  ✓ Employee: {e['employee_number']} {e['full_name']} ({e['department']})")

    # Resolve manager links (second pass — managers may appear later in the list)
    for e in EMPLOYEES:
        if not e.get("manager"):
            continue
        employee = employee_map[e["employee_number"]]
        manager = employee_map.get(e["manager"])
        if manager is not None and employee.manager_id != manager.id:
            employee.manager_id = manager.id
            print(f"    ↳ {e['employee_number']} reports to {e['manager']}")
    return employee_map


async def seed_customers(session: AsyncSession) -> dict[str, Customer]:
    """Seed synthetic customer records."""
    customer_map: dict[str, Customer] = {}
    for c in CUSTOMERS:
        customer, created = await _get_or_create(
            session,
            Customer,
            {
                "company_name": c["company_name"],
                "contact_name": c["contact_name"],
                "contact_email": c["contact_email"],
                "contact_phone": c["contact_phone"],
                "billing_address": c["billing_address"],
                "credit_card_last4": c["credit_card_last4"],
                "account_tier": c["account_tier"],
                "is_active": c["is_active"],
            },
            customer_number=c["customer_number"],
        )
        customer_map[c["customer_number"]] = customer
        if created:
            print(f"  ✓ Customer: {c['customer_number']} {c['company_name']}")
    return customer_map


async def seed_orders(session: AsyncSession, customer_map: dict[str, Customer]):
    """Seed synthetic orders linked to customers."""
    for o in ORDERS:
        customer = customer_map.get(o["customer"])
        if customer is None:
            continue
        _, created = await _get_or_create(
            session,
            Order,
            {
                "customer_id": customer.id,
                "order_date": _d(o["order_date"]),
                "status": o["status"],
                "total_amount": o["total_amount"],
                "shipping_address": o["shipping_address"],
                "items": json.dumps(o["items"]),
            },
            order_number=o["order_number"],
        )
        if created:
            print(f"  ✓ Order: {o['order_number']} → {o['customer']} ({o['status']})")


async def seed_documents(session: AsyncSession):
    """Seed internal financial / business documents."""
    for d in DOCUMENTS:
        _, created = await _get_or_create(
            session,
            BusinessDocument,
            {
                "title": d["title"],
                "content_summary": d["content_summary"],
                "classification": d["classification"],
                "author_employee_number": d["author_employee_number"],
                "revenue_amount": d["revenue_amount"],
                "document_date": _d(d["document_date"]),
            },
            document_number=d["document_number"],
        )
        if created:
            print(f"  ✓ Document: {d['document_number']} [{d['classification']}] {d['title']}")


async def seed_audit_event(session: AsyncSession, admin_user: User | None):
    """Record a single audit event for the seed operation."""
    actor_id = admin_user.id if admin_user else None
    session.add(AuditEvent(
        actor_id=actor_id,
        action=AuditAction.SEED_DATA,
        resource="seed_script",
        outcome="success",
        detail=json.dumps({"message": "Synthetic demo data seeded successfully"}),
    ))
    print("  ✓ Audit: seed_data event recorded")


# ──────────────────────────────────────────────────────────────────────
# Main entry-point
# ──────────────────────────────────────────────────────────────────────

async def run_seed():
    """Execute the full seed workflow inside a single transaction."""
    db_url = str(settings.DATABASE_URL)
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    engine = create_async_engine(db_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    print("\n╔══════════════════════════════════════════════╗")
    print("║   ContextShield — Seeding Demo Data          ║")
    print("╚══════════════════════════════════════════════╝\n")

    async with async_session() as session:
        async with session.begin():
            print("[1/10] Seeding roles …")
            role_map = await seed_roles(session)

            print("\n[2/10] Seeding users …")
            user_map = await seed_users(session, role_map)

            print("\n[3/10] Seeding permissions …")
            await seed_permissions(session, role_map)

            print("\n[4/10] Seeding data assets & fields …")
            await seed_data_assets(session)

            print("\n[5/10] Seeding privacy policies …")
            await seed_policies(session)

            print("\n[6/10] Seeding employee records …")
            await seed_employees(session, user_map)

            print("\n[7/10] Seeding customers …")
            customer_map = await seed_customers(session)

            print("\n[8/10] Seeding orders …")
            await seed_orders(session, customer_map)

            print("\n[9/10] Seeding business documents …")
            await seed_documents(session)

            print("\n[10/10] Recording audit event …")
            await seed_audit_event(session, user_map.get("admin"))

    await engine.dispose()
    print("\n✅ Seed complete.\n")


def main():
    asyncio.run(run_seed())


if __name__ == "__main__":
    main()
