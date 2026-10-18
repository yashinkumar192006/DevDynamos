"""Data-asset and field classification models."""

from sqlalchemy import (
    Column,
    Enum as SAEnum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .base import Base
import enum


class SensitivityLevel(str, enum.Enum):
    """Sensitivity levels for data fields."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    RESTRICTED = "restricted"


class DataAsset(Base):
    """A logical data collection (table, document store, etc.)."""

    __tablename__ = "data_assets"

    name = Column(String(200), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    asset_type = Column(String(50), nullable=False)  # "employee_records", "customer_records", "financial_docs"
    owner_department = Column(String(100), nullable=True)
    # Physical table backing this asset (used by the authorized data connector).
    table_name = Column(String(100), nullable=True)

    # Relationships
    fields = relationship("DataField", back_populates="asset", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<DataAsset {self.name}>"


class DataField(Base):
    """Individual field within a data asset with sensitivity metadata."""

    __tablename__ = "data_fields"

    asset_id = Column(String(32), ForeignKey("data_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    field_name = Column(String(200), nullable=False)
    # Column actually holding the value in the backing table; defaults to
    # ``field_name`` when they are identical (see seed data).
    column_name = Column(String(200), nullable=True)
    field_type = Column(String(50), nullable=False, default="string")  # string, number, date, etc.
    sensitivity = Column(
        SAEnum(SensitivityLevel, name="sensitivity_level"),
        nullable=False,
        default=SensitivityLevel.MEDIUM,
    )
    pii_category = Column(String(100), nullable=True)  # e.g. "salary", "email", "ssn", "phone"
    description = Column(Text, nullable=True)

    # Relationships
    asset = relationship("DataAsset", back_populates="fields")
    classifications = relationship("DataClassification", back_populates="field", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("asset_id", "field_name", name="uq_asset_field"),
        Index("ix_field_sensitivity", "sensitivity"),
    )

    def __repr__(self) -> str:
        return f"<DataField {self.field_name} ({self.sensitivity})>"


class DataClassification(Base):
    """Record of a classification decision for a data field.

    Each time the classifier evaluates a field, a classification record
    is stored so that drift and re-classifications can be tracked.
    """

    __tablename__ = "data_classifications"

    field_id = Column(String(32), ForeignKey("data_fields.id", ondelete="CASCADE"), nullable=False, index=True)
    classified_by = Column(String(100), nullable=False)  # "schema_annotation", "presidio", "manual"
    sensitivity = Column(
        SAEnum(SensitivityLevel, name="sensitivity_level", create_type=False),
        nullable=False,
    )
    confidence = Column(String(20), nullable=True)  # "high", "medium", "low"
    entity_type = Column(String(100), nullable=True)  # Presidio entity type if applicable
    notes = Column(Text, nullable=True)

    # Relationships
    field = relationship("DataField", back_populates="classifications")

    def __repr__(self) -> str:
        return f"<DataClassification field={self.field_id} by={self.classified_by}>"
