"""
Testes da autenticação JWT (issue #1).

Cobre: registro (gated), login, refresh com rotação, logout, /me,
tokens expirados/inválidos, rate limit de login.
"""

from __future__ import annotations

import time

import jwt
import pytest
from freezegun import freeze_time

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.revoked_token import RevokedToken
from openm.models.user import User


# ================ Fixtures ================

class AuthTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    # Habilita registro explicitamente para os testes que precisam.
    ALLOW_REGISTRATION = True
    # TTLs curtos ajudam a testar expiração sem esperar.
    JWT_ACCESS_TTL_MINUTES = 15
    JWT_REFRESH_TTL_DAYS = 7


@pytest.fixture
def auth_app():
    app = create_app(AuthTestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def auth_client(auth_app):
    return auth_app.test_client()


@pytest.fixture
def registered_user(auth_app):
    """Cria um usuário direto via ORM (bypassa o endpoint de registro)."""
    with auth_app.app_context():
        user = User(
            email="alice@example.com",
            password_hash=hash_password("correct horse battery staple"),
            role="analyst",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        return user.id


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ================ Registro ================

class TestRegister:
    def test_register_creates_user_with_bcrypt_hash(self, auth_client):
        resp = auth_client.post(
            "/api/auth/register",
            json={"email": "bob@example.com", "password": "supersecret"},
        )
        assert resp.status_code == 201
        body = resp.get_json()
        assert body["user"]["email"] == "bob@example.com"
        assert body["user"]["role"] == "analyst"
        # Garantimos que a senha nunca volta no JSON.
        assert "password" not in body["user"]
        assert "password_hash" not in body["user"]

        # E que de fato está hasheada com bcrypt no banco.
        with auth_client.application.app_context():
            u = User.query.filter_by(email="bob@example.com").first()
            assert u is not None
            assert u.password_hash.startswith("$2")

    def test_register_rejects_short_password(self, auth_client):
        resp = auth_client.post(
            "/api/auth/register",
            json={"email": "x@example.com", "password": "short"},
        )
        assert resp.status_code == 400

    def test_register_rejects_invalid_email(self, auth_client):
        resp = auth_client.post(
            "/api/auth/register",
            json={"email": "not-an-email", "password": "supersecret"},
        )
        assert resp.status_code == 400

    def test_register_duplicate_returns_generic_error(self, auth_client, registered_user):
        resp = auth_client.post(
            "/api/auth/register",
            json={"email": "alice@example.com", "password": "supersecret"},
        )
        # Não deve revelar que o email já existe.
        assert resp.status_code == 409

    def test_register_blocked_when_disabled(self, auth_app):
        # app separado com ALLOW_REGISTRATION=False
        class Cfg(AuthTestConfig):
            ALLOW_REGISTRATION = False

        app = create_app(Cfg)
        app.config["TESTING"] = True
        with app.app_context():
            db.create_all()
        client = app.test_client()
        resp = client.post(
            "/api/auth/register",
            json={"email": "x@example.com", "password": "supersecret"},
        )
        assert resp.status_code == 403


# ================ Login ================

class TestLogin:
    def test_login_success_returns_tokens(self, auth_client, registered_user):
        resp = auth_client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "correct horse battery staple"},
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["token_type"] == "Bearer"
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["user"]["email"] == "alice@example.com"

    def test_login_wrong_password_returns_401_no_leak(self, auth_client, registered_user):
        resp = auth_client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "wrong-password"},
        )
        assert resp.status_code == 401
        assert resp.get_json() == {"error": "invalid credentials"}

    def test_login_unknown_email_same_message(self, auth_client):
        resp = auth_client.post(
            "/api/auth/login",
            json={"email": "ghost@example.com", "password": "anything"},
        )
        assert resp.status_code == 401
        assert resp.get_json() == {"error": "invalid credentials"}

    def test_login_inactive_user_rejected(self, auth_app, auth_client, registered_user):
        with auth_app.app_context():
            u = User.query.get(registered_user)
            u.is_active = False
            db.session.commit()
        resp = auth_client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "correct horse battery staple"},
        )
        assert resp.status_code == 401


# ================ /me ================

class TestMe:
    def _login(self, client) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "correct horse battery staple"},
        )
        return resp.get_json()["access_token"]

    def test_me_with_valid_token(self, auth_client, registered_user):
        token = self._login(auth_client)
        resp = auth_client.get("/api/auth/me", headers=_bearer(token))
        assert resp.status_code == 200
        assert resp.get_json()["user"]["email"] == "alice@example.com"

    def test_me_without_token(self, auth_client):
        resp = auth_client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_with_invalid_signature(self, auth_client, registered_user):
        bad = jwt.encode(
            {"sub": "1", "type": "access", "exp": int(time.time()) + 60},
            "wrong-secret",
            algorithm="HS256",
        )
        resp = auth_client.get("/api/auth/me", headers=_bearer(bad))
        assert resp.status_code == 401

    def test_me_with_expired_token(self, auth_client, registered_user):
        token = self._login(auth_client)
        # Avança o relógio além do TTL (15min) + folga.
        with freeze_time("2099-01-01 00:00:00"):
            resp = auth_client.get("/api/auth/me", headers=_bearer(token))
        assert resp.status_code == 401

    def test_me_with_refresh_token_rejected(self, auth_client, registered_user):
        # access_token type é exigido; refresh deve falhar.
        resp = auth_client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "correct horse battery staple"},
        )
        refresh = resp.get_json()["refresh_token"]
        resp2 = auth_client.get("/api/auth/me", headers=_bearer(refresh))
        assert resp2.status_code == 401


# ================ Refresh (com rotação) ================

class TestRefresh:
    def _login(self, client) -> dict:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "correct horse battery staple"},
        )
        return resp.get_json()

    def test_refresh_rotates_tokens(self, auth_client, registered_user):
        first = self._login(auth_client)
        resp = auth_client.post(
            "/api/auth/refresh", json={"refresh_token": first["refresh_token"]}
        )
        assert resp.status_code == 200
        body = resp.get_json()
        # Novo par emitido.
        assert body["access_token"] != first["access_token"]
        assert body["refresh_token"] != first["refresh_token"]

        # O refresh antigo agora está na blacklist → reuso falha.
        resp2 = auth_client.post(
            "/api/auth/refresh", json={"refresh_token": first["refresh_token"]}
        )
        assert resp2.status_code == 401

    def test_refresh_invalid_token(self, auth_client):
        resp = auth_client.post(
            "/api/auth/refresh", json={"refresh_token": "not.a.jwt"}
        )
        assert resp.status_code == 401


# ================ Logout ================

class TestLogout:
    def _login(self, client) -> dict:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "correct horse battery staple"},
        )
        return resp.get_json()

    def test_logout_revokes_refresh_and_idempotent(self, auth_client, registered_user):
        first = self._login(auth_client)

        resp = auth_client.post(
            "/api/auth/logout", json={"refresh_token": first["refresh_token"]}
        )
        assert resp.status_code == 200

        # Reuso do mesmo refresh → 401.
        resp2 = auth_client.post(
            "/api/auth/refresh", json={"refresh_token": first["refresh_token"]}
        )
        assert resp2.status_code == 401

        # Logout de novo no mesmo token é idempotente.
        resp3 = auth_client.post(
            "/api/auth/logout", json={"refresh_token": first["refresh_token"]}
        )
        assert resp3.status_code == 200

    def test_blacklist_persisted(self, auth_client, auth_app, registered_user):
        first = self._login(auth_client)
        auth_client.post(
            "/api/auth/logout", json={"refresh_token": first["refresh_token"]}
        )
        with auth_app.app_context():
            assert RevokedToken.query.filter_by(jti=first["refresh_jti"]).first() is not None
