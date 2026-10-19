"""Database-aware classification service.

Thin adapter between the data catalog (``data_assets`` / ``data_fields``
/ ``business_documents``) and the pure :mod:`app.services.classifier`
engine. It loads *metadata only* — never row values — and delegates the
classification itself so the engine stays independently testable.

Read-only: classification does not modify the catalog or write
classification rows at request time. ``DataClassification`` records are
created by the seed / migration path; drift tracking can be layered on
later without changing callers.
"""

from typing import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import BusinessDocument, DataField, SensitivityLevel
from app.repositories import BusinessDocumentRepository, DataAssetRepository
from app.schemas.classifier import ClassifiedField, ClassificationResult
from app.services.classifier import (
    FieldMetadata,
    SensitiveDataClassifier,
    resolve_sensitivity,
)


class ClassificationService:
    """Classify catalog fields, business documents, and free text."""

    def __init__(
        self,
        session: AsyncSession,
        classifier: SensitiveDataClassifier | None = None,
    ):
        self.session = session
        self.classifier = classifier or SensitiveDataClassifier()
        self.assets = DataAssetRepository(session)
        self.documents = BusinessDocumentRepository(session)

    # ── Structured records ──────────────────────────────────────────

    async def classify_asset_fields(
        self,
        asset_name: str,
        field_names: Sequence[str] | None = None,
    ) -> ClassificationResult:
        """Classify an asset's fields (all fields when none are named).

        Unknown fields are still returned — classified with the
        conservative default — because a missing annotation must never be
        treated as "not sensitive".
        """
        asset = await self.assets.get_by_name_with_fields(asset_name)
        if asset is None:
            metadata = [
                FieldMetadata(name=name, asset_name=asset_name)
                for name in (field_names or [])
            ]
            result = self.classifier.classify_structured_record(asset_name, metadata)
            result.notes.append(
                f"asset '{asset_name}' not found in the data catalog; "
                "fields classified with deterministic rules and conservative defaults"
            )
            return result

        known = {field.field_name: field for field in asset.fields}
        selected = (
            [known[name] for name in field_names if name in known]
            if field_names is not None
            else list(asset.fields)
        )
        metadata = [self._metadata_from_field(asset, field) for field in selected]

        missing_names = [
            name for name in (field_names or []) if name not in known
        ] if field_names is not None else []
        metadata.extend(
            FieldMetadata(name=name, asset_name=asset.name)
            for name in missing_names
        )

        result = self.classifier.classify_structured_record(asset_name, metadata)
        if missing_names:
            result.notes.append(
                "not present in the asset schema: " + ", ".join(sorted(missing_names))
            )
        return result

    async def classify_field(
        self, asset_name: str, field_name: str
    ) -> ClassifiedField:
        """Classify a single field of a named asset."""
        result = await self.classify_asset_fields(asset_name, [field_name])
        if result.fields:
            return result.fields[0]
        # No catalog and no rule information → conservative fallback.
        field = self.classifier.classify_field(
            FieldMetadata(name=field_name, asset_name=asset_name)
        )
        return field

    # ── Documents ───────────────────────────────────────────────────

    async def classify_document(self, document_number: str) -> ClassificationResult:
        """Classify a business document by its stored classification label.

        The optional content summary is additionally scanned for embedded
        PII. A missing document falls back to the conservative default
        instead of assuming it is safe.
        """
        document: BusinessDocument | None = (
            await self.documents.get_by_document_number(document_number)
        )
        if document is None:
            result = self.classifier.classify_document(document_number, None)
            result.notes.append(
                f"document '{document_number}' not found; conservative "
                "classification applied"
            )
            return result
        return self.classifier.classify_document(
            document.document_number,
            document.classification,
            summary_text=document.content_summary,
        )

    # ── Free text ───────────────────────────────────────────────────

    def classify_text(
        self, text: str, *, source_ref: str = "text"
    ) -> ClassificationResult:
        """Classify free text (delegates to the pure engine)."""
        return self.classifier.classify_text(text, source_ref=source_ref)

    # ── Status ──────────────────────────────────────────────────────

    def status(self) -> dict:
        """Classifier configuration / NLP availability (for system status)."""
        return self.classifier.status()

    # ── Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _metadata_from_field(asset, field: DataField) -> FieldMetadata:
        sensitivity = field.sensitivity
        if not isinstance(sensitivity, SensitivityLevel):
            sensitivity = resolve_sensitivity(sensitivity)
        return FieldMetadata(
            name=field.field_name,
            column_name=field.column_name or field.field_name,
            sensitivity=sensitivity,
            pii_category=field.pii_category,
            description=field.description,
            field_type=field.field_type,
            asset_name=asset.name,
            asset_type=asset.asset_type,
            table_name=asset.table_name,
        )
