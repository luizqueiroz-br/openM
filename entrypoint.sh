#!/bin/sh
set -e

# NOTE: schema managed by Flask-Migrate (Alembic). See README for migration
# workflow. Old ``scripts/migrate_*.sql`` are deprecated and will be removed
# in the next release (issue #36).

# Aplica migrations (idempotente — nunca cria tabelas, só ALTER).
# Toleramos falha: em ambientes onde o banco ainda não está totalmente
# pronto (ex.: primeira subida do Postgres), o gunicorn vai falhar nos
# requests e o orquestrador reinicia o container.
flask db upgrade || echo "Migrations failed — DB may not be ready yet"

exec "$@"
