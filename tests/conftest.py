import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User


class TestConfig(Config):
    """Configuração para testes: SQLite em memória."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
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
    email = "tester@example.com"
    password = "test-password-123"

    with app.app_context():
        user = User(
            email=email,
            password_hash=hash_password(password),
            role="analyst",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    client = app.test_client()
    resp = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"login falhou no fixture auth_client: {resp.get_json()}"
    token = resp.get_json()["access_token"]
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client
