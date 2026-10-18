"""Repositories for protected business data.

Every read path that can return protected values goes through
``fetch_permitted_records`` (or an equivalent).  Attributes:

* Callers pass the field list a policy decision explicitly permitted.
  The SQL ``SELECT`` only includes those columns — unauthorized fields
  are never fetched, so they cannot leak downstream.
* An empty permission list returns no rows (fail closed).
* Unknown field names raise ``ValueError`` instead of being ignored.
* Ownership is enforced with SQL predicates (e.g. ``user_id``),
  never by filtering in Python or by asking an LLM to hide records.
"""

from typing import Any, Sequence

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import BusinessDocument, Customer, Employee, Order
from .base import BaseRepository

#: Hard cap so a compromised caller cannot request the whole table.
MAX_ROWS = 500


class _PermittedProjectionMixin:
    """Column-level projection shared by protected-data repositories."""

    model: Any

    def _resolve_columns(
        self,
        permitted_fields: Sequence[str],
        *,
        always_include: Sequence[str] = ("id",),
    ) -> list[Any]:
        """Map permitted field names to ORM columns; reject unknown names."""
        known = {column.key for column in self.model.__mapper__.columns}
        resolved: list[Any] = []
        seen: set[str] = set()
        for name in list(always_include) + list(permitted_fields):
            if name in seen:
                continue
            if name not in known:
                raise ValueError(
                    f"Unknown field '{name}' for {self.model.__name__}; "
                    f"known fields: {sorted(known)}"
                )
            resolved.append(getattr(self.model, name))
            seen.add(name)
        return resolved

    async def _fetch_permitted(
        self,
        permitted_fields: Sequence[str],
        *,
        where: Sequence[Any] = (),
        order_by: Any | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Select only permitted columns, constrained by ``where`` clauses."""
        if not permitted_fields:
            return []  # fail closed: nothing was permitted
        columns = self._resolve_columns(permitted_fields)
        stmt: Select = select(*columns)
        if where:
            stmt = stmt.where(*where)
        if order_by is not None:
            stmt = stmt.order_by(order_by)
        stmt = stmt.limit(min(max(int(limit), 1), MAX_ROWS))
        result = await self.session.execute(stmt)
        return [dict(row) for row in result.mappings().all()]


class EmployeeRepository(BaseRepository[Employee], _PermittedProjectionMixin):
    model = Employee

    async def get_by_employee_number(self, employee_number: str) -> Employee | None:
        stmt = select(Employee).where(Employee.employee_number == employee_number)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_user_id(self, user_id: str) -> Employee | None:
        """Return the employee record linked to a user account (self-service)."""
        stmt = select(Employee).where(Employee.user_id == user_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_department(
        self, department: str, *, include_inactive: bool = False, limit: int = 100
    ) -> Sequence[Employee]:
        stmt = select(Employee).where(Employee.department == department)
        if not include_inactive:
            stmt = stmt.where(Employee.is_active.is_(True))
        stmt = stmt.order_by(Employee.employee_number).limit(min(limit, MAX_ROWS))
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def fetch_permitted_records(
        self,
        permitted_fields: Sequence[str],
        *,
        employee_number: str | None = None,
        user_id: str | None = None,
        department: str | None = None,
        include_inactive: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return employee rows with only ``permitted_fields`` selected.

        ``employee_number`` pins one record (target lookup);
        ``user_id`` pins the caller's own record (ownership);
        ``department`` scopes a manager/analyst query.
        """
        where: list[Any] = []
        if employee_number is not None:
            where.append(Employee.employee_number == employee_number)
        if user_id is not None:
            where.append(Employee.user_id == user_id)
        if department is not None:
            where.append(Employee.department == department)
        if not include_inactive:
            where.append(Employee.is_active.is_(True))
        return await self._fetch_permitted(
            permitted_fields, where=where, order_by=Employee.employee_number, limit=limit
        )


class CustomerRepository(BaseRepository[Customer], _PermittedProjectionMixin):
    model = Customer

    async def get_by_customer_number(self, customer_number: str) -> Customer | None:
        stmt = select(Customer).where(Customer.customer_number == customer_number)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def fetch_permitted_records(
        self,
        permitted_fields: Sequence[str],
        *,
        customer_number: str | None = None,
        include_inactive: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return customer rows with only ``permitted_fields`` selected."""
        where: list[Any] = []
        if customer_number is not None:
            where.append(Customer.customer_number == customer_number)
        if not include_inactive:
            where.append(Customer.is_active.is_(True))
        return await self._fetch_permitted(
            permitted_fields, where=where, order_by=Customer.customer_number, limit=limit
        )


class OrderRepository(BaseRepository[Order], _PermittedProjectionMixin):
    model = Order

    async def get_by_order_number(self, order_number: str) -> Order | None:
        stmt = select(Order).where(Order.order_number == order_number)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_customer(
        self, customer_number: str, *, limit: int = 100
    ) -> Sequence[Order]:
        stmt = (
            select(Order)
            .join(Customer, Order.customer_id == Customer.id)
            .where(Customer.customer_number == customer_number)
            .order_by(Order.order_number)
            .limit(min(limit, MAX_ROWS))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def fetch_permitted_records(
        self,
        permitted_fields: Sequence[str],
        *,
        order_number: str | None = None,
        customer_number: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return order rows with only ``permitted_fields`` selected."""
        where: list[Any] = []
        if order_number is not None:
            where.append(Order.order_number == order_number)
        if status is not None:
            where.append(Order.status == status)
        if customer_number is not None:
            where.append(
                Order.customer_id.in_(
                    select(Customer.id).where(Customer.customer_number == customer_number)
                )
            )
        return await self._fetch_permitted(
            permitted_fields, where=where, order_by=Order.order_number, limit=limit
        )


class BusinessDocumentRepository(BaseRepository[BusinessDocument], _PermittedProjectionMixin):
    model = BusinessDocument

    async def get_by_document_number(self, document_number: str) -> BusinessDocument | None:
        stmt = select(BusinessDocument).where(
            BusinessDocument.document_number == document_number
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_classification(
        self, classification: str, *, limit: int = 100
    ) -> Sequence[BusinessDocument]:
        stmt = (
            select(BusinessDocument)
            .where(BusinessDocument.classification == classification)
            .order_by(BusinessDocument.document_number)
            .limit(min(limit, MAX_ROWS))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def fetch_permitted_records(
        self,
        permitted_fields: Sequence[str],
        *,
        document_number: str | None = None,
        classification: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return document rows with only ``permitted_fields`` selected."""
        where: list[Any] = []
        if document_number is not None:
            where.append(BusinessDocument.document_number == document_number)
        if classification is not None:
            where.append(BusinessDocument.classification == classification)
        return await self._fetch_permitted(
            permitted_fields,
            where=where,
            order_by=BusinessDocument.document_number,
            limit=limit,
        )
