"""v3 durable authentication, sessions, events and approval grants

Revision ID: 9b71c8d2f301
Revises: 8763c54bbdfd
"""
from alembic import op
import sqlalchemy as sa


revision = '9b71c8d2f301'
down_revision = '8763c54bbdfd'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'auth_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.Column('user_agent', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_auth_sessions_user_id', 'auth_sessions', ['user_id'])
    op.create_index('ix_auth_sessions_token_hash', 'auth_sessions', ['token_hash'], unique=True)
    op.create_index('ix_auth_sessions_expires_at', 'auth_sessions', ['expires_at'])

    op.create_table(
        'api_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('jti', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('scopes_json', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_api_tokens_jti', 'api_tokens', ['jti'], unique=True)
    op.create_index('ix_api_tokens_user_id', 'api_tokens', ['user_id'])
    op.create_index('ix_api_tokens_token_hash', 'api_tokens', ['token_hash'], unique=True)
    op.create_index('ix_api_tokens_expires_at', 'api_tokens', ['expires_at'])

    op.create_table(
        'scan_sessions_v3',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('mode', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('target_json', sa.Text(), nullable=False),
        sa.Column('policy_json', sa.Text(), nullable=False),
        sa.Column('plan_json', sa.Text(), nullable=False),
        sa.Column('result_json', sa.Text(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scan_sessions_v3_user_id', 'scan_sessions_v3', ['user_id'])
    op.create_index('ix_scan_sessions_v3_status', 'scan_sessions_v3', ['status'])

    op.create_table(
        'session_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('event_type', sa.String(length=60), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['scan_sessions_v3.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_session_events_session_id', 'session_events', ['session_id'])
    op.create_index('ix_session_events_user_id', 'session_events', ['user_id'])
    op.create_index('ix_session_events_event_type', 'session_events', ['event_type'])
    op.create_index('ix_session_events_created_at', 'session_events', ['created_at'])

    op.create_table(
        'approval_grants',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('jti', sa.String(length=36), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('target', sa.String(length=255), nullable=False),
        sa.Column('poc_filename', sa.String(length=255), nullable=False),
        sa.Column('risk_ceiling', sa.String(length=32), nullable=False),
        sa.Column('allowed_domains_json', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_approval_grants_jti', 'approval_grants', ['jti'], unique=True)
    op.create_index('ix_approval_grants_token_hash', 'approval_grants', ['token_hash'], unique=True)
    op.create_index('ix_approval_grants_session_id', 'approval_grants', ['session_id'])
    op.create_index('ix_approval_grants_user_id', 'approval_grants', ['user_id'])
    op.create_index('ix_approval_grants_expires_at', 'approval_grants', ['expires_at'])


def downgrade():
    op.drop_table('approval_grants')
    op.drop_table('session_events')
    op.drop_table('scan_sessions_v3')
    op.drop_table('api_tokens')
    op.drop_table('auth_sessions')
