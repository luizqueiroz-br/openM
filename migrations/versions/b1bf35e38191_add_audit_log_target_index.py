"""add audit log target index (issue #129)

Revision ID: b1bf35e38191
Revises: aa41d2af2b67
Create Date: 2026-06-30 16:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b1bf35e38191'
down_revision = 'aa41d2af2b67'
branch_labels = None
depends_on = None


def upgrade():
    # Índice composto em (target_type, target_id, created_at) para
    # acelerar a query do endpoint /api/sightings (issue #129):
    #
    #   SELECT ... FROM audit_log
    #   WHERE target_type = 'entity' AND target_id = :entity_id
    #   ORDER BY created_at DESC LIMIT 50
    #
    # Sem o índice composto, a engine cai em varredura por created_at
    # (que já tem índice simples) + filtro em memória. Em volumes
    # grandes de auditoria esse padrão fica caro. O índice composto
    # cobre o prefixo de igualdade e usa created_at como tie-breaker
    # para evitar sort explícito.
    op.create_index(
        'ix_audit_log_target',
        'audit_log',
        ['target_type', 'target_id', 'created_at'],
        unique=False,
    )


def downgrade():
    op.drop_index('ix_audit_log_target', table_name='audit_log')
