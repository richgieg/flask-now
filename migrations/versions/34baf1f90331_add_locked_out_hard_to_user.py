"""Add locked_out_hard to User

Revision ID: 34baf1f90331
Revises: fb6a6554b21
Create Date: 2015-10-29 17:29:57.101292

"""

# revision identifiers, used by Alembic.
revision = '34baf1f90331'
down_revision = 'fb6a6554b21'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('locked_out_hard', sa.Boolean(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'locked_out_hard')
    ### end Alembic commands ###
