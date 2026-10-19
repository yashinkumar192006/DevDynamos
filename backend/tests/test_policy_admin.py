"""Tests for policy administration access control and versioning.

Prompt-7 requirements (section E): versioned policies, readable reason
codes, and access controls ensuring normal users (or LLM-driven callers)
cannot change authorization rules. Covers admin-only access, version
creation with supersede semantics, rollback, validation, and audit
trails for administrative actions.

Requires the migrated + seeded demo database. Run with::

    pytest tests/test_policy_admin.py -v
"""

import json
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.models import AuditAction, AuditEvent, PolicyStatus, PrivacyPolicy


def _make_url() -> str:
    from app.core.config import settings

    url = str(settings.DATABASE_URL)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine(_make_url(), echo=False, poolclass=NullPool)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


async def _principal_for_user(session: AsyncSession, username: str):
    from app.repositories import UserRepository
    from app.services import Principal

    repo = UserRepository(session)
    user = await repo.get_by_username(username)
    assert user is not None, f"seed user '{username}' not found"
    roles = frozenset(r.name for r in await repo.get_user_roles(user.id))
    return Principal(
        id=user.id,
        kind="user",
        display_name=user.full_name,
        username=user.username,
        roles=roles,
        user=user,
    )


def _service_principal(scopes: frozenset[str]):
    from app.services import Principal

    return Principal(
        id="svc-policy-admin-test",
        kind="service",
        display_name="Policy Admin Test Agent",
        scopes=scopes,
    )


async def _policy_count(session: AsyncSession) -> int:
    return (
        await session.execute(select(func.count()).select_from(PrivacyPolicy))
    ).scalar_one()


async def _create_policy(session, principal, **overrides):
    from app.services import PolicyAdminService

    defaults = dict(
        name=f"test_admin_policy_{uuid4().hex[:10]}",
        description="admin service test",
        policy_text="admin service test policy",
        resource_pattern="employee_salary",
        action="MASK",
        required_role="hr_manager",
        min_sensitivity="restricted",
        allowed_purposes=("hr_review",),
        allowed_actions=("read",),
        priority=42,
    )
    defaults.update(overrides)
    return await PolicyAdminService(session).create_policy(principal, **defaults)


# ------------------------------------------------------------------
# Access control — only administrators may change rules
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_normal_user_cannot_administer_policies(session):
    from app.services import PolicyAdminDenied, PolicyAdminService

    sarah = await _principal_for_user(session, "sarah.chen")
    service = PolicyAdminService(session)
    before = await _policy_count(session)

    with pytest.raises(PolicyAdminDenied):
        await service.create_policy(
            sarah,
            name=f"test_denied_{uuid4().hex[:8]}",
            description=None,
            policy_text="should never exist",
            resource_pattern="employee_salary",
            action="ALLOW",
            required_role="viewer",
            min_sensitivity="restricted",
            allowed_purposes=("hr_review",),
            allowed_actions=("read",),
            priority=9999,
        )
    with pytest.raises(PolicyAdminDenied):
        await service.list_policies(sarah)
    with pytest.raises(PolicyAdminDenied):
        await service.set_status(sarah, "any-id", PolicyStatus.ARCHIVED)

    assert await _policy_count(session) == before  # nothing changed


@pytest.mark.asyncio
async def test_viewer_and_adminless_service_are_denied(session):
    from app.services import PolicyAdminDenied, PolicyAdminService

    lisa = await _principal_for_user(session, "lisa.wang")
    service = PolicyAdminService(session)

    with pytest.raises(PolicyAdminDenied):
        await service.list_policies(lisa)
    with pytest.raises(PolicyAdminDenied):
        await service.list_policies(_service_principal(frozenset()))


@pytest.mark.asyncio
async def test_service_with_policy_admin_scope_is_allowed(session):
    from app.services import PolicyAdminService

    agent = _service_principal(frozenset({"policy:admin"}))
    service = PolicyAdminService(session)
    policy = await service.create_policy(
        agent,
        name=f"test_service_admin_{uuid4().hex[:8]}",
        description=None,
        policy_text="service-created policy",
        resource_pattern="order_records",
        action="ALLOW",
        required_role="support_agent",
        min_sensitivity="medium",
        allowed_purposes=("order_status",),
        allowed_actions=("read",),
        priority=5,
    )
    try:
        assert policy.version == 1
        assert policy.status == PolicyStatus.ACTIVE
    finally:
        await session.delete(policy)
        await session.commit()


@pytest.mark.asyncio
async def test_admin_and_normal_user_see_different_surfaces(session):
    from app.services import PolicyAdminService

    admin = await _principal_for_user(session, "admin")
    service = PolicyAdminService(session)
    active = await service.list_policies(admin)
    everything = await service.list_policies(admin, include_inactive=True)
    assert all(p.status == PolicyStatus.ACTIVE for p in active)
    assert len(everything) >= len(active)


# ------------------------------------------------------------------
# Versioning, supersede and rollback
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_update_creates_new_version_and_supersedes(session):
    from app.repositories import AuditRepository
    from app.services import PolicyAdminService

    admin = await _principal_for_user(session, "admin")
    service = PolicyAdminService(session)
    v1 = await _create_policy(session, admin)
    try:
        v2 = await service.update_policy(
            admin, v1.id, description="second version", priority=77
        )
        try:
            assert v2.version == 2
            assert v2.status == PolicyStatus.ACTIVE
            assert v2.priority == 77
            # Unspecified fields are inherited from the source version.
            assert v2.action == "MASK"
            assert json.loads(v2.allowed_purposes) == ["hr_review"]
            # The previous version is retained for the audit trail.
            assert v1.status == PolicyStatus.SUPERSEDED

            audits = await AuditRepository(session).get_by_action(
                AuditAction.ADMIN_ACTION, limit=10
            )
            assert any(v1.name in (event.detail or "") for event in audits)
        finally:
            await session.delete(v2)
            await session.commit()
    finally:
        await session.delete(v1)
        await session.commit()


@pytest.mark.asyncio
async def test_admin_can_roll_back_by_reactivating_old_version(session):
    from app.repositories import PrivacyPolicyRepository
    from app.services import PolicyAdminService

    admin = await _principal_for_user(session, "admin")
    service = PolicyAdminService(session)
    v1 = await _create_policy(session, admin)
    try:
        v2 = await service.update_policy(admin, v1.id, priority=90)
        try:
            # Roll back: v1 becomes active again, v2 archived.
            await service.set_status(admin, v2.id, PolicyStatus.ARCHIVED)
            rolled_back = await service.set_status(
                admin, v1.id, PolicyStatus.ACTIVE
            )
            assert rolled_back.status == PolicyStatus.ACTIVE
            latest = await PrivacyPolicyRepository(session).get_latest_version(
                v1.name
            )
            assert latest is not None and latest.version == 2  # history kept
        finally:
            await session.delete(v2)
            await session.commit()
    finally:
        await session.delete(v1)
        await session.commit()


# ------------------------------------------------------------------
# Validation — bad definitions never enter the store
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validation_rejects_bad_definitions(session):
    from app.services import PolicyAdminService, PolicyValidationError

    admin = await _principal_for_user(session, "admin")
    service = PolicyAdminService(session)

    with pytest.raises(PolicyValidationError):
        await _create_policy(session, admin, action="SUPER_ALLOW")
    with pytest.raises(PolicyValidationError):
        await _create_policy(session, admin, min_sensitivity="top-secret")
    with pytest.raises(PolicyValidationError):
        await _create_policy(session, admin, allowed_purposes=("do_whatever",))
    with pytest.raises(PolicyValidationError):
        await _create_policy(session, admin, allowed_actions=("sudo",))
    with pytest.raises(PolicyValidationError):
        await _create_policy(session, admin, policy_text="")


@pytest.mark.asyncio
async def test_create_rejects_duplicate_name(session):
    from app.services import PolicyAdminService, PolicyValidationError

    admin = await _principal_for_user(session, "admin")
    service = PolicyAdminService(session)
    with pytest.raises(PolicyValidationError):
        await service.create_policy(
            admin,
            name="salary_access_policy",  # already exists (versioned)
            description=None,
            policy_text="duplicate",
            resource_pattern="employee_salary",
            action="ALLOW",
            required_role="hr_manager",
            min_sensitivity="restricted",
            allowed_purposes=("hr_review",),
            allowed_actions=("read",),
            priority=1,
        )


@pytest.mark.asyncio
async def test_update_unknown_policy_fails(session):
    from app.services import PolicyAdminService, PolicyValidationError

    admin = await _principal_for_user(session, "admin")
    with pytest.raises(PolicyValidationError):
        await PolicyAdminService(session).update_policy(
            admin, "does-not-exist", description="x"
        )


@pytest.mark.asyncio
async def test_updated_policy_is_what_the_engine_enforces(session):
    """The engine honours the newest active version (decision follows rules)."""
    from app.services import ContextAnalyzer, PolicyAdminService, PolicyEngine

    admin = await _principal_for_user(session, "admin")
    service = PolicyAdminService(session)
    # Priority 150 beats the seeded salary_access_policy (priority 100).
    v1 = await _create_policy(
        session,
        admin,
        name=f"test_enforced_{uuid4().hex[:8]}",
        action="BLOCK",
        priority=150,
    )
    sarah = await _principal_for_user(session, "sarah.chen")
    context = await ContextAnalyzer(session).analyze(
        sarah,
        resource="employee_salary",
        requested_fields=["base_salary"],
        purpose="hr_review",
        target_entity="EMP002",
    )
    evaluation = await PolicyEngine(session).evaluate(context)
    entry = evaluation.entry_for("base_salary")
    assert entry.action.value == "BLOCK"
    assert entry.policy_id == v1.id

    # Activate a new version that allows the flow → the engine follows it.
    v2 = await service.update_policy(admin, v1.id, action="ALLOW", priority=150)
    try:
        # v1 is superseded; only the newest active version is enforced.
        evaluation = await PolicyEngine(session).evaluate(context)
        entry = evaluation.entry_for("base_salary")
        assert entry.action.value == "ALLOW"
        assert entry.policy_id == v2.id
    finally:
        await session.delete(v2)
        await session.commit()
    await session.delete(v1)
    await session.commit()
