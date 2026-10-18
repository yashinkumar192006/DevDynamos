"""Data-asset and field repositories."""

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import DataAsset, DataField, DataClassification, SensitivityLevel
from .base import BaseRepository


class DataAssetRepository(BaseRepository[DataAsset]):
    model = DataAsset

    async def get_by_name(self, name: str) -> DataAsset | None:
        stmt = select(DataAsset).where(DataAsset.name == name)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_with_fields(self, asset_id: str) -> DataAsset | None:
        stmt = (
            select(DataAsset)
            .where(DataAsset.id == asset_id)
            .options(selectinload(DataAsset.fields))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_name_with_fields(self, name: str) -> DataAsset | None:
        stmt = (
            select(DataAsset)
            .where(DataAsset.name == name)
            .options(selectinload(DataAsset.fields))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_assets_by_department(self, department: str) -> Sequence[DataAsset]:
        stmt = select(DataAsset).where(DataAsset.owner_department == department)
        result = await self.session.execute(stmt)
        return result.scalars().all()


class DataFieldRepository(BaseRepository[DataField]):
    model = DataField

    async def get_fields_for_asset(self, asset_id: str) -> Sequence[DataField]:
        stmt = select(DataField).where(DataField.asset_id == asset_id)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_permitted_fields(
        self,
        asset_name: str,
        allowed_field_names: Sequence[str] | None = None,
        max_sensitivity: SensitivityLevel | None = None,
    ) -> Sequence[DataField]:
        """Return fields constrained by name whitelist and/or sensitivity cap.

        This ensures the database layer never returns more fields than the
        caller is permitted to see.
        """
        stmt = (
            select(DataField)
            .join(DataAsset, DataField.asset_id == DataAsset.id)
            .where(DataAsset.name == asset_name)
        )

        if allowed_field_names is not None:
            stmt = stmt.where(DataField.field_name.in_(allowed_field_names))

        if max_sensitivity is not None:
            sensitivity_order = {
                SensitivityLevel.LOW: 1,
                SensitivityLevel.MEDIUM: 2,
                SensitivityLevel.HIGH: 3,
                SensitivityLevel.RESTRICTED: 4,
            }
            max_level = sensitivity_order[max_sensitivity]
            allowed_levels = [
                lvl for lvl, order in sensitivity_order.items() if order <= max_level
            ]
            stmt = stmt.where(DataField.sensitivity.in_(allowed_levels))

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_fields_by_sensitivity(self, sensitivity: SensitivityLevel) -> Sequence[DataField]:
        stmt = select(DataField).where(DataField.sensitivity == sensitivity)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_fields_by_pii_category(self, pii_category: str) -> Sequence[DataField]:
        stmt = select(DataField).where(DataField.pii_category == pii_category)
        result = await self.session.execute(stmt)
        return result.scalars().all()
