"""Protected business-data models: employees, customers, orders, documents.

These tables hold the synthetic demo records that the privacy engine
guards.  Sensitive values follow the same rules as the rest of the
schema:

* Raw SSNs are never stored â€” only a SHA-256 hash.
* Bank accounts and credit cards are stored as last-4 digits only.
* Reads must go through :mod:`app.repositories.protected_data_repo`,
  which projects only the columns a policy decision permitted.
"""

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .base import Base


class Employee(Base):
    """Synthetic employee record (the protected data in HR scenarios)."""

    __tablename__ = "employees"

    user_id = Column(
        String(32),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
        index=True,
    )
    employee_number = Column(String(20), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    phone = Column(String(50), nullable=True)
    address = Column(Text, nullable=True)
    date_of_birth = Column(Date, nullable=True)
    # SHA-256 hash of the raw SSN â€” the raw value is never persisted.
    ssn_hash = Column(String(128), nullable=True)
    salary = Column(Numeric(12, 2), nullable=False)
    bonus = Column(Numeric(12, 2), nullable=True)
    pay_grade = Column(String(10), nullable=True)
    # Only the last 4 digits of the bank account are stored.
    bank_account_last4 = Column(String(4), nullable=True)
    department = Column(String(100), nullable=False, index=True)
    title = Column(String(100), nullable=False)
    hire_date = Column(Date, nullable=False)
    manager_id = Column(
        String(32),
        ForeignKey("employees.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    user = relationship("User", backref="employee_record")
    manager = relationship("Employee", remote_side="Employee.id", back_populates="reports")
    reports = relationship("Employee", back_populates="manager")

    __table_args__ = (
        Index("ix_employee_department_active", "department", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<Employee {self.employee_number} {self.full_name}>"


class Customer(Base):
    """Synthetic customer account (the protected data in support scenarios)."""

    __tablename__ = "customers"

    customer_number = Column(String(20), unique=True, nullable=False, index=True)
    company_name = Column(String(255), nullable=False)
    contact_name = Column(String(255), nullable=False)
    contact_email = Column(String(255), nullable=False, index=True)
    contact_phone = Column(String(50), nullable=True)
    billing_address = Column(Text, nullable=True)
    # Only the last 4 digits of the card on file are stored.
    credit_card_last4 = Column(String(4), nullable=True)
    account_tier = Column(String(20), default="standard", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    orders = relationship("Order", back_populates="customer", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Customer {self.customer_number} {self.company_name}>"


class Order(Base):
    """Customer order (linked to :class:`Customer`)."""

    __tablename__ = "orders"

    customer_id = Column(
        String(32),
        ForeignKey("customers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    order_number = Column(String(20), unique=True, nullable=False, index=True)
    order_date = Column(Date, nullable=False)
    status = Column(String(30), nullable=False, index=True)  # pending/processing/shipped/delivered/cancelled
    total_amount = Column(Numeric(12, 2), nullable=False)
    shipping_address = Column(Text, nullable=True)
    items = Column(Text, nullable=True)  # JSON-encoded line items

    # Relationships
    customer = relationship("Customer", back_populates="orders")

    def __repr__(self) -> str:
        return f"<Order {self.order_number} {self.status}>"


class BusinessDocument(Base):
    """Internal financial / business document."""

    __tablename__ = "business_documents"

    document_number = Column(String(20), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    content_summary = Column(Text, nullable=True)
    classification = Column(String(20), default="internal", nullable=False, index=True)
    author_employee_number = Column(String(20), nullable=True)
    revenue_amount = Column(Numeric(14, 2), nullable=True)
    document_date = Column(Date, nullable=True)

    def __repr__(self) -> str:
        return f"<BusinessDocument {self.document_number} {self.classification}>"
