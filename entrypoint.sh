#!/bin/sh
set -e

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
