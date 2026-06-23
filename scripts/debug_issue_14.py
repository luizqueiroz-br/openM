"""
Debug visual temporário para a issue #14.

Sobe um Flask com SQLite + Neo4j mockado, abre Playwright, reproduz o
fluxo da issue (cria investigação → reload → clica), e captura network +
console + screenshots.

Uso:
    source venv/bin/activate
    python scripts/debug_issue_14.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Reset DB sempre
DB_PATH = "/tmp/openm-debug.db"
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)


class _FakeGraphManager:
    """Stub do Neo4j. Cria 3 entidades pra investigação ter conteúdo."""
    def __init__(self):
        self.entities = {
            "root1": {"id": "root1", "label": "example.com", "type": "Domain", "value": "example.com"},
            "ip1": {"id": "ip1", "label": "1.2.3.4", "type": "IPAddress", "value": "1.2.3.4"},
            "ip2": {"id": "ip2", "label": "5.6.7.8", "type": "IPAddress", "value": "5.6.7.8"},
        }

    def get_subgraph(self, entity_id, depth=2):
        # Subgraph centrado em root1 com 2 IPs vizinhos
        return {
            "elements": [
                {"data": {"id": "root1", "label": "example.com", "type": "Domain"}},
                {"data": {"id": "ip1", "label": "1.2.3.4", "type": "IPAddress"}},
                {"data": {"id": "ip2", "label": "5.6.7.8", "type": "IPAddress"}},
                {"data": {"id": "e1", "source": "root1", "target": "ip1", "label": "resolves_to"}},
                {"data": {"id": "e2", "source": "root1", "target": "ip2", "label": "resolves_to"}},
            ]
        }

    def get_entity(self, *args, **kwargs):
        return None

    def create_relationship(self, *args, **kwargs):
        return {}

    def delete_relationship(self, *args, **kwargs):
        return None

    def merge_entity(self, *args, **kwargs):
        return None

    def update_entity_properties(self, *args, **kwargs):
        return None

    def delete_entity(self, *args, **kwargs):
        return None


# Monkeypatch Neo4j ANTES de criar o app
import openm.utils.neo4j_client as _n4
import openm.api.graph as _graph
import openm.api.entities as _entities
import openm.api.transforms as _transforms

_fake = lambda *a, **k: _FakeGraphManager()
_n4.get_graph_manager = _fake
_graph.get_graph_manager = _fake
_entities.get_graph_manager = _fake
_transforms.get_graph_manager = _fake


from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User


class DebugConfig(Config):
    TESTING = False
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True
    JWT_COOKIE_SECURE = False


app = create_app(DebugConfig)


@app.cli.command("seed-debug")
def seed_debug():
    """Cria user de debug."""
    with app.app_context():
        db.create_all()
        existing = User.query.filter_by(email="debug@x.com").first()
        if existing:
            print("user já existe")
            return
        u = User(
            email="debug@x.com",
            password_hash=hash_password("debug-pass-123"),
            role="analyst",
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        print("✓ user debug@x.com criado")


def seed():
    with app.app_context():
        db.create_all()
        existing = User.query.filter_by(email="debug@x.com").first()
        if not existing:
            u = User(
                email="debug@x.com",
                password_hash=hash_password("debug-pass-123"),
                role="analyst",
                is_active=True,
            )
            db.session.add(u)
            db.session.commit()
            print("[seed] user criado")


if __name__ == "__main__":
    seed()
    print(f"[debug-server] subindo Flask em http://localhost:5057")
    print(f"[debug-server] DB: {DB_PATH}")
    print(f"[debug-server] login: debug@x.com / debug-pass-123")
    app.run(host="127.0.0.1", port=5057, debug=False, use_reloader=False)