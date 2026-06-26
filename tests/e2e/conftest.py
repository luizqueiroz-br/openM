"""
Fixtures para testes E2E (issue #18).

IMPORTANTE: testes E2E precisam de:
- Postgres real rodando (`make db-up` ou container)
- Neo4j real rodando (mesmo docker-compose)
- DB ``openm_e2e`` criado (separado do ``openm`` de produção)

Setup local:
    make db-up
    docker compose exec postgres createdb -U openm openm_e2e

    DATABASE_URL=postgresql://openm:openm123@localhost:5432/openm_e2e \\
    NEO4J_URI=bolt://localhost:7687 \\
    NEO4J_USER=neo4j \\
    NEO4J_PASSWORD=openm123 \\
    pytest -m e2e tests/e2e/

Ou simplesmente:
    make test-e2e
"""

import os

import pytest
from sqlalchemy import text

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User
from openm.utils.neo4j_client import get_graph_manager, reset_graph_manager


class TestE2EConfig(Config):
    """Config para testes E2E: Postgres real + Neo4j real."""

    TESTING = True
    # Lê env vars (default aponta para `localhost` porque E2E roda em máquina dev)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql://openm:openm123@localhost:5432/openm_e2e",
    )
    NEO4J_URI = os.environ.get("TEST_NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.environ.get("TEST_NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.environ.get("TEST_NEO4J_PASSWORD", "openm123")
    RATELIMIT_STORAGE_URI = "memory://"
    # Rate limit desabilitado em E2E — o storage memory persiste entre
    # testes da mesma sessão, então rodar 10+ logins dispara 429.
    # E2E testa integração, não rate limiting.
    RATELIMIT_ENABLED: bool = False
    ALLOW_REGISTRATION = True


@pytest.fixture(scope="session", autouse=True)
def _override_config_for_e2e():
    """Override singleton Config para apontar para Neo4j/PG reais.

    O helper ``get_graph_manager`` lê ``Config.NEO4J_URI`` diretamente
    (não do ``current_app.config``), então precisamos patchar a classe
    Config para que o singleton pegue os valores do E2E.

    Marcado ``autouse=True`` no escopo ``tests/e2e/`` (este conftest é
    carregado só pelos testes E2E), então não afeta testes unitários.
    """
    # Backup
    orig_uri = Config.NEO4J_URI
    orig_user = Config.NEO4J_USER
    orig_pwd = Config.NEO4J_PASSWORD

    # Override para E2E
    Config.NEO4J_URI = TestE2EConfig.NEO4J_URI
    Config.NEO4J_USER = TestE2EConfig.NEO4J_USER
    Config.NEO4J_PASSWORD = TestE2EConfig.NEO4J_PASSWORD

    # Reset singleton para que a próxima chamada pegue os novos valores
    reset_graph_manager()

    yield

    # Restore (best-effort)
    Config.NEO4J_URI = orig_uri
    Config.NEO4J_USER = orig_user
    Config.NEO4J_PASSWORD = orig_pwd
    reset_graph_manager()


def _truncate_all_tables(app):
    """Limpa todas as tabelas PG (mantém schema). Mais rápido que drop_all.

    Usa ``TRUNCATE ... RESTART IDENTITY CASCADE`` — Postgres-specific.
    OK porque E2E roda contra Postgres real, nunca SQLite.
    """
    with app.app_context():
        tables = list(db.metadata.tables.keys())
        if not tables:
            return
        table_list = ", ".join(f'"{t}"' for t in tables)
        db.session.execute(
            text(f"TRUNCATE TABLE {table_list} RESTART IDENTITY CASCADE")
        )
        db.session.commit()


def _clear_neo4j():
    """Limpa todos os nós e relações do Neo4j (idempotente)."""
    gm = get_graph_manager()
    gm.clear()


@pytest.fixture(scope="session")
def e2e_app():
    """Cria Flask app para E2E: Postgres real + Neo4j real.

    Session-scoped: cria schema 1x e reaproveita entre testes.
    Cleanup final garante estado limpo após a sessão.
    """
    # Reset singleton Neo4j (caso algum teste unitário anterior tenha criado
    # um manager apontando para outro URI antes do E2E).
    reset_graph_manager()

    app = create_app(TestE2EConfig)
    app.config["TESTING"] = True

    with app.app_context():
        # Cria schema PG (idempotente — não dropa antes pra não conflitar
        # com sessões paralelas que possam existir).
        db.create_all()
        # Constraints Neo4j (idempotente — CREATE CONSTRAINT IF NOT EXISTS).
        gm = get_graph_manager()
        try:
            gm.ensure_constraints()
        except Exception as exc:
            pytest.skip(f"Neo4j indisponível: {exc}")

    yield app

    # Cleanup fim de sessão: garante estado limpo para a próxima execução.
    with app.app_context():
        try:
            _truncate_all_tables(app)
        except Exception:
            pass  # Best-effort — se o DB já foi derrubado, ok.
        try:
            _clear_neo4j()
        except Exception:
            pass
    reset_graph_manager()


@pytest.fixture(autouse=True)
def e2e_clean_state(request, e2e_app):
    """Limpa estado antes de cada teste E2E (function-scoped).

    Defesa em profundidade — o conftest root filtra por marker `e2e`
    no bypass do mock Neo4j, e aqui garantimos que cada teste E2E
    começa com PG + Neo4j vazios.
    """
    marker = request.node.get_closest_marker("e2e")
    if marker is None:
        # Não é teste E2E — não faz nada (defesa em profundidade).
        yield
        return

    # Limpa Postgres + Neo4j antes do teste
    _truncate_all_tables(e2e_app)
    _clear_neo4j()
    yield
    # Não precisa cleanup depois (próximo teste limpa antes; fim de sessão
    # já faz cleanup via e2e_app teardown).


@pytest.fixture
def e2e_client(e2e_app):
    """Flask test client sem auth."""
    return e2e_app.test_client()


@pytest.fixture
def e2e_auth_client(e2e_app):
    """Cliente autenticado como analyst."""
    return _make_auth_client_for_e2e(
        e2e_app, email="e2e-analyst@example.com", role="analyst",
    )


@pytest.fixture
def e2e_admin_client(e2e_app):
    """Cliente autenticado como admin."""
    return _make_auth_client_for_e2e(
        e2e_app, email="e2e-admin@example.com", role="admin",
    )


def _make_auth_client_for_e2e(app, *, email: str, role: str):
    """Cria user direto via ORM + login via API (mesmo padrão do conftest root)."""
    password = "e2e-test-password"

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
    assert resp.status_code == 200, f"E2E login falhou: {resp.get_json()}"
    token = resp.get_json()["access_token"]
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client
