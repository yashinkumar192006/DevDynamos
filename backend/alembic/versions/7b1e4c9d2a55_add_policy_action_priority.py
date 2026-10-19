"""add policy action and priority

Revision ID: 7b1e4c9d2a55
Revises: 606f597667cb
Create Date: 2026-10-18 15:40:00.000000

Adds the disclosure-action and conflict-priority fields to
``privacy_policies`` so policy norms can express their decision
(ALLOW/MASK/…/BLOCK) and precedence explicitly, as described in
``docs/privacy-policies.md`` §3.1 / §4.2.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7b1e4c9d2a55'
down_revision: Union[str, None] = '606f597667cb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'privacy_policies',
        sa.Column('action', sa.String(length=20), nullable=True),
    )
    op.add_column(
        'privacy_policies',
        sa.Column(
            'priority',
            sa.Integer(),
            nullable=False,
            server_default='0',
        ),
    )


def downgrade() -> None:
    op.drop_column('privacy_policies', 'priority')
    op.drop_column('privacy_policies', 'action')
