"""inventory intelligence: tags, profiles, HTTP metadata, saved searches, API tokens

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-09 13:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('saved_searches',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('query', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('kind', sa.String(length=10), nullable=False),
    sa.Column('alert', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.String(length=150), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('last_run_at', sa.DateTime(), nullable=True),
    sa.Column('last_count', sa.Integer(), nullable=False),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('initialized', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('api_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('prefix', sa.String(length=12), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('last_used_at', sa.DateTime(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.Column('revoked', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('api_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_api_tokens_token_hash'), ['token_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_api_tokens_user_id'), ['user_id'], unique=False)

    op.create_table('device_profiles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('owner', sa.String(length=150), nullable=True),
    sa.Column('location', sa.String(length=200), nullable=True),
    sa.Column('criticality', sa.String(length=10), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('exposure_factors', sa.JSON(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_id')
    )
    op.create_table('device_tags',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('tag', sa.String(length=60), nullable=False),
    sa.Column('source', sa.String(length=10), nullable=False),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_id', 'tag', name='uq_device_tag')
    )
    with op.batch_alter_table('device_tags', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_tags_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_tags_tag'), ['tag'], unique=False)

    op.create_table('saved_search_hits',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('search_id', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('first_matched_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['search_id'], ['saved_searches.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('search_id', 'device_id', name='uq_search_hit')
    )
    with op.batch_alter_table('saved_search_hits', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_saved_search_hits_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_saved_search_hits_search_id'), ['search_id'], unique=False)

    op.create_table('port_http',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_port_id', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('scheme', sa.String(length=8), nullable=True),
    sa.Column('status', sa.Integer(), nullable=True),
    sa.Column('title', sa.String(length=500), nullable=True),
    sa.Column('server', sa.String(length=255), nullable=True),
    sa.Column('content_type', sa.String(length=255), nullable=True),
    sa.Column('location', sa.Text(), nullable=True),
    sa.Column('login', sa.Boolean(), nullable=False),
    sa.Column('default_page', sa.Boolean(), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['device_port_id'], ['device_ports.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_port_id')
    )
    with op.batch_alter_table('port_http', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_port_http_device_id'), ['device_id'], unique=False)

    with op.batch_alter_table('device_ports', schema=None) as batch_op:
        batch_op.add_column(sa.Column('cpe', sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column('tunnel', sa.String(length=10), nullable=True))

    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('device_type', sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column('exposure_score', sa.Integer(), server_default='0', nullable=False))
        batch_op.add_column(sa.Column('classified_at', sa.DateTime(), nullable=True))
        batch_op.create_index(batch_op.f('ix_devices_device_type'), ['device_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_devices_exposure_score'), ['exposure_score'], unique=False)

    with op.batch_alter_table('networks', schema=None) as batch_op:
        batch_op.add_column(sa.Column('zone', sa.String(length=20), nullable=True))



def downgrade() -> None:
    with op.batch_alter_table('networks', schema=None) as batch_op:
        batch_op.drop_column('zone')

    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_devices_exposure_score'))
        batch_op.drop_index(batch_op.f('ix_devices_device_type'))
        batch_op.drop_column('classified_at')
        batch_op.drop_column('exposure_score')
        batch_op.drop_column('device_type')

    with op.batch_alter_table('device_ports', schema=None) as batch_op:
        batch_op.drop_column('tunnel')
        batch_op.drop_column('cpe')

    with op.batch_alter_table('port_http', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_port_http_device_id'))

    op.drop_table('port_http')
    with op.batch_alter_table('saved_search_hits', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_saved_search_hits_search_id'))
        batch_op.drop_index(batch_op.f('ix_saved_search_hits_device_id'))

    op.drop_table('saved_search_hits')
    with op.batch_alter_table('device_tags', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_tags_tag'))
        batch_op.drop_index(batch_op.f('ix_device_tags_device_id'))

    op.drop_table('device_tags')
    op.drop_table('device_profiles')
    with op.batch_alter_table('api_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_api_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_api_tokens_token_hash'))

    op.drop_table('api_tokens')
    op.drop_table('saved_searches')
