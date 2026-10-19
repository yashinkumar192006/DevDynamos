"""add actor kind to audit events (agent / service actors)

Revision ID: e91f2a7c4b3d
Revises: c4a8f2e91b07
Create Date: 2026-10-19 12:00:00.000000

The audit trail now records agent (service-account) activity alongside
human-user activity, so every gateway decision is explainable end to end.

* ``actor_kind`` distinguishes the actor id space: ``"user"``
  (``users.id``) or ``"service"`` (``service_accounts.id``). Existing rows
  are backfilled as ``"user"``.
* The original ``actor_id → users.id`` foreign key is dropped: one column
  cannot reference two id spaces, and audit rows are retention records
  that must survive account deletion (no cascade, no null-out).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e91f2a7c4b3d'
down_revision: Union[str, None] = 'c4a8f2e91b07'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'audit_events',
        sa.Column('actor_kind', sa.String(length=20), nullable=True),
    )
    op.execute("UPDATE audit_events SET actor_kind = 'user' WHERE actor_kind IS NULL")
    op.drop_constraint(
        'audit_events_actor_id_fkey', 'audit_events', type_='foreignkey'
    )


def downgrade() -> None:
    # Service-account actors cannot satisfy the users(id) foreign key that
    # downgrade restores; drop those rows rather than corrupt the trail.
    op.execute("DELETE FROM audit_events WHERE actor_kind = 'service'")
    op.create_foreign_key(
        'audit_events_actor_id_fkey',
        'audit_events',
        'users',
        ['actor_id'],
        ['id'],
        ondelete='SET NULL',
    )
    op.drop_column('audit_events', 'actor_kind')
