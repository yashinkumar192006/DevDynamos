"""link customers to user accounts

Revision ID: c4a8f2e91b07
Revises: 7b1e4c9d2a55
Create Date: 2026-10-19 09:00:00.000000

Adds ``customers.user_id`` so an external customer contact can authenticate
and read their own records (self-service) through the same ownership
mechanism employees already use. ``None`` means no login is linked.

The ownership semantics are documented in ``docs/llm-integration.md``
(secure-request pipeline) and ``docs/authentication.md`` (customer role).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4a8f2e91b07'
down_revision: Union[str, None] = '7b1e4c9d2a55'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'customers',
        sa.Column('user_id', sa.String(length=32), nullable=True),
    )
    op.create_foreign_key(
        'fk_customers_user_id_users',
        'customers',
        'users',
        ['user_id'],
        ['id'],
        ondelete='SET NULL',
    )
    op.create_index(
        'ix_customers_user_id',
        'customers',
        ['user_id'],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index('ix_customers_user_id', table_name='customers')
    op.drop_constraint('fk_customers_user_id_users', 'customers', type_='foreignkey')
    op.drop_column('customers', 'user_id')
