##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2026, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
##########################################################################

"""Add passthrough_oauth_identity to server and sharedserver tables.

Revision ID: a8f3b1c2d4e5
Revises: f28be870d5ec
Create Date: 2026-02-27 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a8f3b1c2d4e5'
down_revision = 'add_tools_ai_perm'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table(
            "server", table_kwargs={'sqlite_autoincrement': True}) as batch_op:
        batch_op.add_column(
            sa.Column('passthrough_oauth_identity',
                      sa.Boolean(), nullable=False, server_default='0'))

    with op.batch_alter_table("sharedserver") as batch_op:
        batch_op.add_column(
            sa.Column('passthrough_oauth_identity',
                      sa.Boolean(), nullable=False, server_default='0'))


def downgrade():
    # pgAdmin only upgrades, downgrade not implemented.
    pass
