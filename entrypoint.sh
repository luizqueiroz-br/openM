#!/bin/sh
set -e

# Roda migrations SQL idempotentes antes de criar tabelas.
# Necessário porque o projeto não usa Alembic/Flask-Migrate.
if [ -f /app/scripts/migrate_investigations_v2.sql ] && [ -n "$DATABASE_URL" ]; then
    echo "Rodando migrate_investigations_v2.sql..."
    # Converte postgresql:// para formato psql aceito; psql aceita URL direta também
    psql "$DATABASE_URL" -v ON_ERROR_STOP=0 -f /app/scripts/migrate_investigations_v2.sql || \
        echo "  (migration pulada — provavelmente sem psql no container ou DB indisponível)"
fi

# Migration: Investigation versioning (issue #37)
if [ -f /app/scripts/migrate_investigations_versioning.sql ] && [ -n "$DATABASE_URL" ]; then
    echo "Rodando migrate_investigations_versioning.sql..."
    psql "$DATABASE_URL" -v ON_ERROR_STOP=0 -f /app/scripts/migrate_investigations_versioning.sql || \
        echo "  (migration pulada — provavelmente sem psql no container ou DB indisponível)"
fi

# Cria as tabelas do PostgreSQL antes de iniciar o Flask.
python -c "
from openm.app import create_app
from openm.extensions import db
app = create_app()
with app.app_context():
    db.create_all()
    print('PostgreSQL tables created successfully.')
"

exec "$@"
