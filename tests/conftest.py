import os
import tempfile

import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User


class _FakeGraphManager:
    """Stub do Neo4j manager — evita precisar de Neo4j real nos testes."""

    def get_subgraph(self, *args, **kwargs):
        return {"elements": []}

    def get_entity(self, entity_id, *args, **kwargs):
        # IDs começando com "ok" simulam entidades existentes — útil para
        # testes de RBAC que precisam passar da checagem de existência.
        if isinstance(entity_id, str) and entity_id.startswith("ok"):
            return {"id": entity_id, "type": "Domain", "value": "x.com"}
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


@pytest.fixture(autouse=True)
def _mock_neo4j(monkeypatch):
    """Mocka get_graph_manager em todos os blueprints que usam Neo4j.

    Necessário porque os endpoints chamam Neo4j e os testes rodam sem o
    serviço real. O pattern é o mesmo usado em test_api_protected.py.
    """
    def fake(*args, **kwargs):
        return _FakeGraphManager()

    for mod_name in [
        "openm.utils.neo4j_client",
        "openm.api.graph",
        "openm.api.entities",
        "openm.api.transforms",
    ]:
        monkeypatch.setattr(f"{mod_name}.get_graph_manager", fake)


class TestConfig(Config):
    """Configuração para testes: SQLite em arquivo temporário."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "TEST_DATABASE_URL",
        f"sqlite:///{tempfile.gettempdir()}/openm_test.db",
    )
    NEO4J_URI = "bolt://localhost:7687"  # não usado nos testes unitários da API
    RATELIMIT_STORAGE_URI = "memory://"
    # Habilita registro pra fixtures que precisem.
    ALLOW_REGISTRATION = True


@pytest.fixture
def app():
    """Cria aplicação Flask configurada para testes."""
    app = create_app(TestConfig)
    app.config["TESTING"] = True

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Cliente de teste Flask (sem autenticação)."""
    return app.test_client()


@pytest.fixture
def auth_client(app):
    """
    Cliente autenticado para testes que precisam de sessão.

    Cria um usuário direto via ORM (bypassa o endpoint de registro),
    faz login via /api/auth/login e injeta o access token no header
    Authorization de todas as requests.
    """
    return _make_auth_client(app, email="tester@example.com", role="analyst")


@pytest.fixture
def admin_client(app):
    """Cliente autenticado com role='admin'."""
    return _make_auth_client(app, email="admin@example.com", role="admin")


@pytest.fixture
def viewer_client(app):
    """Cliente autenticado com role='viewer'."""
    return _make_auth_client(app, email="viewer@example.com", role="viewer")


def _make_auth_client(app, *, email: str, role: str):
    password = "test-password-123"

    with app.app_context():
        user = User(
            email=email,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    client = app.test_client()
    resp = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"login falhou no fixture: {resp.get_json()}"
    token = resp.get_json()["access_token"]
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client
