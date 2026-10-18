"""Tests for database models, seed idempotency, and repository queries.

Run with::

    pytest backend/tests/test_database.py -v

These tests require a running PostgreSQL server with a ``contextshield``
(or ``contextshield_test``) database. Set ``DATABASE_URL`` accordingly.
"""

import json
import pytest
import pytest_asyncio
from datetime import datetime, timezone

from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


def _make_url() -> str:
    """Build async database URL from settings."""
    from app.core.config import settings

    url = str(settings.DATABASE_URL)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine(_make_url(), echo=False, poolclass=NullPool)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session(engine):
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as sess:
        yield sess


# ------------------------------------------------------------------
# A. Database connectivity
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_database_connectivity(engine):
    """Can we connect and run SELECT 1?"""
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT 1"))
        assert result.scalar_one() == 1


@pytest.mark.asyncio
async def test_tables_exist(engine):
    """All expected tables should exist after migrations."""
    expected = {
        "users",
        "roles",
        "permissions",
        "user_roles",
        "data_assets",
        "data_fields",
        "data_classifications",
        "privacy_policies",
        "privacy_requests",
        "request_contexts",
        "privacy_decisions",
        "transformation_events",
        "ai_interactions",
        "output_inspections",
        "audit_events",
        "session_disclosures",
        "employees",
        "customers",
        "orders",
        "business_documents",
    }
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public'"
            )
        )
        actual = {row[0] for row in result.fetchall()}
    missing = expected - actual
    assert not missing, f"Missing tables: {missing}"


# ------------------------------------------------------------------
# B. Foreign-key integrity
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_role_fk_integrity(session: AsyncSession):
    """user_roles should reference valid users and roles."""
    result = await session.execute(
        text(
            "SELECT ur.id FROM user_roles ur "
            "LEFT JOIN users u ON ur.user_id = u.id "
            "LEFT JOIN roles r ON ur.role_id = r.id "
            "WHERE u.id IS NULL OR r.id IS NULL"
        )
    )
    orphans = result.fetchall()
    assert len(orphans) == 0, f"Orphaned user_roles: {orphans}"


@pytest.mark.asyncio
async def test_permission_fk_integrity(session: AsyncSession):
    """permissions should reference valid roles."""
    result = await session.execute(
        text(
            "SELECT p.id FROM permissions p "
            "LEFT JOIN roles r ON p.role_id = r.id "
            "WHERE r.id IS NULL"
        )
    )
    orphans = result.fetchall()
    assert len(orphans) == 0, f"Orphaned permissions: {orphans}"


@pytest.mark.asyncio
async def test_data_field_fk_integrity(session: AsyncSession):
    """data_fields should reference valid data_assets."""
    result = await session.execute(
        text(
            "SELECT df.id FROM data_fields df "
            "LEFT JOIN data_assets da ON df.asset_id = da.id "
            "WHERE da.id IS NULL"
        )
    )
    orphans = result.fetchall()
    assert len(orphans) == 0, f"Orphaned data_fields: {orphans}"


@pytest.mark.asyncio
async def test_employee_fk_integrity(session: AsyncSession):
    """employees.user_id and employees.manager_id must reference valid rows."""
    result = await session.execute(
        text(
            "SELECT e.employee_number FROM employees e "
            "LEFT JOIN users u ON e.user_id = u.id "
            "LEFT JOIN employees m ON e.manager_id = m.id "
            "WHERE (e.user_id IS NOT NULL AND u.id IS NULL) "
            "   OR (e.manager_id IS NOT NULL AND m.id IS NULL)"
        )
    )
    orphans = result.fetchall()
    assert len(orphans) == 0, f"Orphaned employee links: {orphans}"


@pytest.mark.asyncio
async def test_order_fk_integrity(session: AsyncSession):
    """orders.customer_id must reference valid customers."""
    result = await session.execute(
        text(
            "SELECT o.order_number FROM orders o "
            "LEFT JOIN customers c ON o.customer_id = c.id "
            "WHERE c.id IS NULL"
        )
    )
    orphans = result.fetchall()
    assert len(orphans) == 0, f"Orphaned orders: {orphans}"


# ------------------------------------------------------------------
# C. Seed data verification
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seed_users_exist(session: AsyncSession):
    """The seed script should have created demo users."""
    from app.models import User

    result = await session.execute(select(User))
    users = result.scalars().all()
    assert len(users) >= 8, f"Expected ≥8 users, got {len(users)}"

    usernames = {u.username for u in users}
    expected_names = {"admin", "sarah.chen", "james.wilson", "maria.garcia"}
    assert expected_names.issubset(usernames)


@pytest.mark.asyncio
async def test_seed_roles_exist(session: AsyncSession):
    """The seed script should have created all demo roles."""
    from app.models import Role

    result = await session.execute(select(Role))
    roles = result.scalars().all()
    role_names = {r.name for r in roles}
    expected = {"admin", "hr_manager", "hr_staff", "finance_manager", "sales_manager", "sales_staff", "analyst", "viewer"}
    assert expected.issubset(role_names)


@pytest.mark.asyncio
async def test_seed_data_assets_exist(session: AsyncSession):
    """The seed script should have created data assets."""
    from app.models import DataAsset

    result = await session.execute(select(DataAsset))
    assets = result.scalars().all()
    asset_names = {a.name for a in assets}
    assert "employee_records" in asset_names
    assert "customer_records" in asset_names
    assert "employee_salary" in asset_names


@pytest.mark.asyncio
async def test_seed_privacy_policies_exist(session: AsyncSession):
    """The seed script should have created privacy policies."""
    from app.models import PrivacyPolicy

    result = await session.execute(select(PrivacyPolicy))
    policies = result.scalars().all()
    assert len(policies) >= 6


@pytest.mark.asyncio
async def test_seed_employees_exist(session: AsyncSession):
    """The seed script should have created synthetic employee records."""
    from app.models import Employee

    result = await session.execute(select(Employee))
    employees = result.scalars().all()
    assert len(employees) >= 25, f"Expected ≥25 employees, got {len(employees)}"

    numbers = {e.employee_number for e in employees}
    assert {"EMP001", "EMP010", "EMP021"}.issubset(numbers)

    # SSNs must never be stored in raw form — only hashes.
    for e in employees:
        if e.ssn_hash:
            assert len(e.ssn_hash) == 64, "ssn_hash should be a SHA-256 hex digest"
            assert not e.ssn_hash.startswith("900-"), "Raw SSN pattern leaked into ssn_hash"


@pytest.mark.asyncio
async def test_seed_scenario_targets_exist(session: AsyncSession):
    """Demo-scenario target records should be present."""
    from app.models import Employee

    result = await session.execute(select(Employee).where(Employee.full_name == "John Park"))
    john = result.scalar_one_or_none()
    assert john is not None
    assert float(john.salary) == 95000.0


@pytest.mark.asyncio
async def test_seed_customers_orders_documents_exist(session: AsyncSession):
    from app.models import BusinessDocument, Customer, Order

    customers = (await session.execute(select(Customer))).scalars().all()
    assert len(customers) >= 10

    orders = (await session.execute(select(Order))).scalars().all()
    assert len(orders) >= 20

    documents = (await session.execute(select(BusinessDocument))).scalars().all()
    assert len(documents) >= 8


@pytest.mark.asyncio
async def test_seed_idempotency(session: AsyncSession):
    """Running seed twice should not duplicate records."""
    from app.models import User, Role

    result1 = await session.execute(text("SELECT COUNT(*) FROM users"))
    count_before = result1.scalar_one()

    result2 = await session.execute(text("SELECT COUNT(*) FROM roles"))
    role_count_before = result2.scalar_one()

    protected_before = {}
    for tbl in ("employees", "customers", "orders", "business_documents"):
        r = await session.execute(text(f"SELECT COUNT(*) FROM {tbl}"))
        protected_before[tbl] = r.scalar_one()

    # Re-run seed
    from app.seed import run_seed
    await run_seed()

    # Re-read counts in a fresh query
    result3 = await session.execute(text("SELECT COUNT(*) FROM users"))
    count_after = result3.scalar_one()

    result4 = await session.execute(text("SELECT COUNT(*) FROM roles"))
    role_count_after = result4.scalar_one()

    assert count_after == count_before, "Seed created duplicate users"
    assert role_count_after == role_count_before, "Seed created duplicate roles"

    for tbl, before in protected_before.items():
        r = await session.execute(text(f"SELECT COUNT(*) FROM {tbl}"))
        after = r.scalar_one()
        assert after == before, f"Seed created duplicate rows in {tbl}"


# ------------------------------------------------------------------
# D. Repository queries
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_repo_get_by_username(session: AsyncSession):
    from app.repositories import UserRepository

    repo = UserRepository(session)
    user = await repo.get_by_username("admin")
    assert user is not None
    assert user.username == "admin"


@pytest.mark.asyncio
async def test_user_repo_get_user_roles(session: AsyncSession):
    from app.repositories import UserRepository

    repo = UserRepository(session)
    user = await repo.get_by_username("sarah.chen")
    assert user is not None

    roles = await repo.get_user_roles(user.id)
    role_names = {r.name for r in roles}
    assert "hr_manager" in role_names


@pytest.mark.asyncio
async def test_user_repo_has_permission(session: AsyncSession):
    from app.repositories import UserRepository

    repo = UserRepository(session)

    # Admin should have wildcard permission
    admin = await repo.get_by_username("admin")
    assert admin is not None
    assert await repo.has_permission(admin.id, "employee_salary", "read") is True

    # Viewer should NOT have salary access
    viewer = await repo.get_by_username("lisa.wang")
    assert viewer is not None
    assert await repo.has_permission(viewer.id, "employee_salary", "read") is False


@pytest.mark.asyncio
async def test_data_asset_repo_get_by_name(session: AsyncSession):
    from app.repositories import DataAssetRepository

    repo = DataAssetRepository(session)
    asset = await repo.get_by_name("employee_records")
    assert asset is not None
    assert asset.name == "employee_records"


@pytest.mark.asyncio
async def test_data_asset_repo_with_fields(session: AsyncSession):
    from app.repositories import DataAssetRepository

    repo = DataAssetRepository(session)
    asset = await repo.get_by_name_with_fields("employee_records")
    assert asset is not None
    assert len(asset.fields) >= 8
    field_names = {f.field_name for f in asset.fields}
    assert "ssn" in field_names
    assert "full_name" in field_names


@pytest.mark.asyncio
async def test_data_field_repo_permitted_fields(session: AsyncSession):
    """get_permitted_fields should enforce field-name and sensitivity filters."""
    from app.repositories import DataFieldRepository
    from app.models import SensitivityLevel

    repo = DataFieldRepository(session)

    # Only low-sensitivity fields
    low_fields = await repo.get_permitted_fields(
        "employee_records",
        max_sensitivity=SensitivityLevel.LOW,
    )
    for f in low_fields:
        assert f.sensitivity == SensitivityLevel.LOW

    # Explicit whitelist
    whitelisted = await repo.get_permitted_fields(
        "employee_records",
        allowed_field_names=["full_name", "department"],
    )
    names = {f.field_name for f in whitelisted}
    assert names == {"full_name", "department"}


@pytest.mark.asyncio
async def test_data_field_repo_restricted_not_leaked(session: AsyncSession):
    """Restricted fields should not appear when max_sensitivity is HIGH."""
    from app.repositories import DataFieldRepository
    from app.models import SensitivityLevel

    repo = DataFieldRepository(session)
    fields = await repo.get_permitted_fields(
        "employee_salary",
        max_sensitivity=SensitivityLevel.HIGH,
    )
    for f in fields:
        assert f.sensitivity != SensitivityLevel.RESTRICTED


@pytest.mark.asyncio
async def test_policy_repo_active_policies(session: AsyncSession):
    from app.repositories import PrivacyPolicyRepository

    repo = PrivacyPolicyRepository(session)
    active = await repo.get_active_policies()
    assert len(active) >= 5


@pytest.mark.asyncio
async def test_policy_repo_resource_match(session: AsyncSession):
    from app.repositories import PrivacyPolicyRepository

    repo = PrivacyPolicyRepository(session)
    matched = await repo.get_policies_for_resource("employee_salary")
    assert len(matched) >= 1
    for p in matched:
        assert "salary" in p.resource_pattern


@pytest.mark.asyncio
async def test_policy_repo_wildcard_match(session: AsyncSession):
    from app.repositories import PrivacyPolicyRepository

    repo = PrivacyPolicyRepository(session)
    matched = await repo.get_policies_for_resource("customer_contact")
    # Should match "customer_contact" exact and "customer_*" wildcard
    resource_patterns = {p.resource_pattern for p in matched}
    assert any("customer" in r for r in resource_patterns)


@pytest.mark.asyncio
async def test_policy_repo_latest_version(session: AsyncSession):
    from app.repositories import PrivacyPolicyRepository

    repo = PrivacyPolicyRepository(session)
    latest = await repo.get_latest_version("salary_access_policy")
    assert latest is not None
    assert latest.version == 2  # v2 is the latest


@pytest.mark.asyncio
async def test_audit_repo_log_event(session: AsyncSession):
    from app.repositories import AuditRepository, UserRepository
    from app.models import AuditAction

    user_repo = UserRepository(session)
    admin = await user_repo.get_by_username("admin")
    assert admin is not None

    audit_repo = AuditRepository(session)
    event = await audit_repo.log_event(
        actor_id=admin.id,
        action=AuditAction.DATA_ACCESS,
        resource="employee_salary",
        outcome="success",
        detail=json.dumps({"test": True}),
    )
    assert event.id is not None
    assert event.action == AuditAction.DATA_ACCESS


@pytest.mark.asyncio
async def test_audit_repo_get_by_actor(session: AsyncSession):
    from app.repositories import AuditRepository, UserRepository

    user_repo = UserRepository(session)
    admin = await user_repo.get_by_username("admin")
    assert admin is not None

    audit_repo = AuditRepository(session)
    events = await audit_repo.get_by_actor(admin.id)
    assert len(events) >= 1  # at least the seed event


# ------------------------------------------------------------------
# E. Model constraints
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unique_username_constraint(session: AsyncSession):
    """Inserting a duplicate username should fail."""
    from sqlalchemy.exc import IntegrityError
    from app.models import User

    duplicate = User(
        username="admin",
        email="duplicate@test.dev",
        full_name="Dup Admin",
        hashed_password="fake_hash",
    )
    session.add(duplicate)
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


@pytest.mark.asyncio
async def test_unique_role_name_constraint(session: AsyncSession):
    """Inserting a duplicate role name should fail."""
    from sqlalchemy.exc import IntegrityError
    from app.models import Role

    duplicate = Role(name="admin", description="Dup")
    session.add(duplicate)
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


@pytest.mark.asyncio
async def test_timestamps_are_set(session: AsyncSession):
    """Models should automatically have created_at and updated_at."""
    from app.models import User

    result = await session.execute(select(User).limit(1))
    user = result.scalar_one_or_none()
    assert user is not None
    assert user.created_at is not None
    assert user.updated_at is not None


@pytest.mark.asyncio
async def test_sensitivity_enum_values(session: AsyncSession):
    """Data fields should use valid sensitivity enum values."""
    from app.models import DataField, SensitivityLevel

    result = await session.execute(select(DataField))
    fields = result.scalars().all()
    valid = {s.value for s in SensitivityLevel}
    for f in fields:
        assert f.sensitivity.value in valid, f"Invalid sensitivity: {f.sensitivity}"


# ------------------------------------------------------------------
# F. Protected-data repositories (field-level SQL projection)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_employee_repo_get_by_employee_number(session: AsyncSession):
    from app.repositories import EmployeeRepository

    repo = EmployeeRepository(session)
    emp = await repo.get_by_employee_number("EMP010")
    assert emp is not None
    assert emp.full_name == "John Park"


@pytest.mark.asyncio
async def test_employee_repo_projects_only_permitted_fields(session: AsyncSession):
    """The SELECT must contain only permitted columns — no extra data leaks."""
    from app.repositories import EmployeeRepository

    repo = EmployeeRepository(session)
    rows = await repo.fetch_permitted_records(
        ["employee_number", "full_name", "salary"],
        employee_number="EMP010",
    )
    assert len(rows) == 1
    assert set(rows[0].keys()) == {"id", "employee_number", "full_name", "salary"}
    # Restricted fields that were not permitted must be absent entirely.
    assert "ssn_hash" not in rows[0]
    assert "bonus" not in rows[0]
    assert "bank_account_last4" not in rows[0]
    assert rows[0]["full_name"] == "John Park"


@pytest.mark.asyncio
async def test_employee_repo_empty_permission_is_fail_closed(session: AsyncSession):
    from app.repositories import EmployeeRepository

    repo = EmployeeRepository(session)
    rows = await repo.fetch_permitted_records([], employee_number="EMP010")
    assert rows == []


@pytest.mark.asyncio
async def test_employee_repo_rejects_unknown_field(session: AsyncSession):
    from app.repositories import EmployeeRepository

    repo = EmployeeRepository(session)
    with pytest.raises(ValueError):
        await repo.fetch_permitted_records(["password"], employee_number="EMP010")


@pytest.mark.asyncio
async def test_employee_repo_self_service_scoping(session: AsyncSession):
    """A self-service query is scoped by user_id at the SQL level."""
    from app.repositories import EmployeeRepository, UserRepository

    user_repo = UserRepository(session)
    sarah = await user_repo.get_by_username("sarah.chen")
    assert sarah is not None

    repo = EmployeeRepository(session)
    rows = await repo.fetch_permitted_records(
        ["employee_number", "full_name", "email"],
        user_id=sarah.id,
    )
    assert len(rows) == 1
    assert rows[0]["employee_number"] == "EMP001"

    # A different user must not see Sarah's row through the same query shape.
    viewer = await user_repo.get_by_username("lisa.wang")
    rows_other = await repo.fetch_permitted_records(
        ["employee_number", "full_name", "email"],
        user_id=viewer.id,
    )
    assert all(r["employee_number"] != "EMP001" for r in rows_other)


@pytest.mark.asyncio
async def test_employee_repo_department_scope(session: AsyncSession):
    from app.repositories import EmployeeRepository

    repo = EmployeeRepository(session)
    rows = await repo.fetch_permitted_records(
        ["employee_number", "department"],
        department="Engineering",
    )
    assert len(rows) >= 8
    assert all(r["department"] == "Engineering" for r in rows)


@pytest.mark.asyncio
async def test_customer_repo_projects_permitted_fields(session: AsyncSession):
    from app.repositories import CustomerRepository

    repo = CustomerRepository(session)
    rows = await repo.fetch_permitted_records(
        ["customer_number", "company_name", "contact_email"],
        customer_number="CUS001",
    )
    assert len(rows) == 1
    assert set(rows[0].keys()) == {"id", "customer_number", "company_name", "contact_email"}
    assert "billing_address" not in rows[0]
    assert "credit_card_last4" not in rows[0]


@pytest.mark.asyncio
async def test_order_repo_status_lookup(session: AsyncSession):
    """S13-style order-status lookup should return status fields only."""
    from app.repositories import OrderRepository

    repo = OrderRepository(session)
    rows = await repo.fetch_permitted_records(
        ["order_number", "status", "total_amount"],
        order_number="ORD0012",
    )
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
    assert "shipping_address" not in rows[0]


@pytest.mark.asyncio
async def test_order_repo_scoped_to_customer(session: AsyncSession):
    from app.repositories import OrderRepository

    repo = OrderRepository(session)
    rows = await repo.fetch_permitted_records(
        ["order_number", "status"],
        customer_number="CUS006",
    )
    numbers = {r["order_number"] for r in rows}
    assert numbers == {"ORD0011", "ORD0012"}


@pytest.mark.asyncio
async def test_business_document_repo_projects_permitted_fields(session: AsyncSession):
    from app.repositories import BusinessDocumentRepository

    repo = BusinessDocumentRepository(session)
    rows = await repo.fetch_permitted_records(
        ["document_number", "title", "classification"],
        document_number="DOC001",
    )
    assert len(rows) == 1
    assert rows[0]["classification"] == "confidential"
    # Revenue figures are RESTRICTED and were not permitted.
    assert "revenue_amount" not in rows[0]
    assert "content_summary" not in rows[0]
