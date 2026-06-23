"""
Testes de isolamento multi-usuário para investigations (issue #2).

Cenários:
- User A cria investigação → visível só pra A
- User B lista → não vê investigação de A
- User B busca por id da investigação de A → 404
- User com role diferente vê só as próprias
- Investigations legadas (user_id=null) ficam visíveis pra qualquer user?
  Decisão: visíveis pra TODOS (pra não quebrar dados antigos)
"""

from __future__ import annotations

import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User


class MultiUserTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


@pytest.fixture
def mu_app():
    app = create_app(MultiUserTestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def mu_client(mu_app):
    return mu_app.test_client()


def _create_user(app, email, password="pass-12345678"):
    """Cria user direto via ORM."""
    with app.app_context():
        u = User(
            email=email,
            password_hash=hash_password(password),
            role="analyst",
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        return u.id


def _login(client, email, password="pass-12345678"):
    resp = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200
    return resp.get_json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _create_inv(client, token, title="Test"):
    resp = client.post(
        "/api/investigations",
        json={"title": title, "root_entity_id": "example.com"},
        headers=_bearer(token),
    )
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["investigation"]


# ============ Isolamento básico ============

class TestInvestigationIsolation:
    def test_user_a_creates_investigation_owned_by_a(self, mu_app, mu_client):
        _create_user(mu_app, "alice@x.com")
        token_a = _login(mu_client, "alice@x.com")

        inv = _create_inv(mu_client, token_a, "Alice's investigation")

        assert inv["user_id"] is not None
        assert inv["title"] == "Alice's investigation"

    def test_user_b_does_not_see_user_a_investigations_in_list(self, mu_app, mu_client):
        _create_user(mu_app, "alice@x.com")
        _create_user(mu_app, "bob@x.com")
        token_a = _login(mu_client, "alice@x.com")
        token_b = _login(mu_client, "bob@x.com")

        # Alice cria 2
        _create_inv(mu_client, token_a, "A1")
        _create_inv(mu_client, token_a, "A2")
        # Bob cria 1
        _create_inv(mu_client, token_b, "B1")

        # Alice lista → 2 (só dela)
        resp_a = mu_client.get("/api/investigations", headers=_bearer(token_a))
        assert resp_a.status_code == 200
        titles_a = {i["title"] for i in resp_a.get_json()["investigations"]}
        assert titles_a == {"A1", "A2"}

        # Bob lista → 1 (só dele)
        resp_b = mu_client.get("/api/investigations", headers=_bearer(token_b))
        titles_b = {i["title"] for i in resp_b.get_json()["investigations"]}
        assert titles_b == {"B1"}

    def test_user_b_cannot_get_user_a_investigation_by_id(self, mu_app, mu_client):
        _create_user(mu_app, "alice@x.com")
        _create_user(mu_app, "bob@x.com")
        token_a = _login(mu_client, "alice@x.com")
        token_b = _login(mu_client, "bob@x.com")

        inv_a = _create_inv(mu_client, token_a, "Alice secret")

        # Bob tenta acessar investigação da Alice → 404 (anti-enumeração)
        resp = mu_client.get(
            f"/api/investigations/{inv_a['id']}",
            headers=_bearer(token_b),
        )
        assert resp.status_code == 404
        assert "not found" in resp.get_json()["error"].lower()

    def test_user_a_can_still_get_own_investigation(self, mu_app, mu_client):
        _create_user(mu_app, "alice@x.com")
        token_a = _login(mu_client, "alice@x.com")

        inv = _create_inv(mu_client, token_a, "Mine")

        resp = mu_client.get(
            f"/api/investigations/{inv['id']}",
            headers=_bearer(token_a),
        )
        assert resp.status_code == 200
        assert resp.get_json()["investigation"]["title"] == "Mine"


# ============ Edge cases ============

class TestInvestigationEdgeCases:
    def test_legacy_investigation_without_owner_visible_to_anyone(self, mu_app, mu_client):
        """
        Investigations antigas (user_id=null) ficam visíveis pra qualquer
        user logado. Decisão: pra não quebrar dados existentes.

        Alternative seria migrar ou esconder — mas essa é a escolha menos
        invasiva e mais explícita.
        """
        # Cria user legacy direto via ORM sem user_id
        from openm.models.investigation import Investigation as InvModel
        with mu_app.app_context():
            inv = InvModel(
                title="Legacy sem dono",
                description="Criada antes da issue #2",
                root_entity_id=None,
                user_id=None,
            )
            db.session.add(inv)
            db.session.commit()
            legacy_id = inv.id

        _create_user(mu_app, "alice@x.com")
        token = _login(mu_client, "alice@x.com")

        # Alice vê a legacy
        resp = mu_client.get(
            f"/api/investigations/{legacy_id}",
            headers=_bearer(token),
        )
        assert resp.status_code == 200

    def test_admin_role_can_create_investigation(self, mu_app, mu_client):
        """Role diferente (admin) também consegue criar."""
        with mu_app.app_context():
            u = User(
                email="admin@x.com",
                password_hash=hash_password("admin-pass-123"),
                role="admin",
                is_active=True,
            )
            db.session.add(u)
            db.session.commit()
        token = _login(mu_client, "admin@x.com", password="admin-pass-123")

        inv = _create_inv(mu_client, token, "Admin inv")
        assert inv["user_id"] is not None

    def test_unauthenticated_cannot_list_investigations(self, mu_client):
        resp = mu_client.get("/api/investigations")
        assert resp.status_code == 401

    def test_unauthenticated_cannot_create_investigation(self, mu_client):
        resp = mu_client.post("/api/investigations", json={"title": "hack"})
        assert resp.status_code == 401
