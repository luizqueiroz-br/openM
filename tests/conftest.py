import pytest

from openm.app import create_app
from openm.config import Config
from openm.extensions import db


class TestConfig(Config):
    """Configuração para testes: SQLite em memória."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"  # não usado nos testes unitários da API
    RATELIMIT_STORAGE_URI = "memory://"


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
    """Cliente de teste Flask."""
    return app.test_client()
