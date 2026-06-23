"""
Testes de proteção de páginas HTML (issue #13).

Cobre o decorator ``login_required_page``:
- GET / sem cookie/Bearer → 302 → /login
- GET / com cookie válido → 200
- GET / com cookie expirado/inválido → 302 → /login
- GET / com refresh token no cookie → 302 → /login (tipo errado)
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
from openm.models.user import User


class ProtectionTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


@pytest.fixture
def prot_app():
    app = create_app(ProtectionTestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def prot_client(prot_app):
    return prot_app.test_client()


@pytest.fixture
def prot_user(prot_app):
    with prot_app.app_context():
        user = User(
            email="prot@example.com",
            password_hash=hash_password("good-password-123"),
            role="analyst",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        return user.id


def _login_and_get_cookies(client, email="prot@example.com", password="good-password-123"):
    """Helper: faz login e retorna dict com cookies access/refresh."""
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    cookies = {"access": None, "refresh": None}
    for sc in resp.headers.getlist("Set-Cookie"):
        if sc.startswith("openm_access="):
            cookies["access"] = sc.split(";")[0]
        elif sc.startswith("openm_refresh="):
            cookies["refresh"] = sc.split(";")[0]
    return cookies


class TestIndexProtection:
    def test_index_without_auth_redirects_to_login(self, prot_client):
        resp = prot_client.get("/")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/login")

    def test_index_with_valid_access_cookie_renders(self, prot_client, prot_user):
        cookies = _login_and_get_cookies(prot_client)
        resp = prot_client.get("/", headers={"Cookie": cookies["access"]})
        assert resp.status_code == 200
        assert b"app-shell" in resp.data

    def test_index_with_expired_token_redirects(self, prot_client, prot_user):
        cookies = _login_and_get_cookies(prot_client)
        # Avança o relógio além do TTL (15min) + folga.
        with freeze_time("2099-01-01 00:00:00"):
            resp = prot_client.get("/", headers={"Cookie": cookies["access"]})
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/login")

    def test_index_with_invalid_signature_redirects(self, prot_client, prot_user):
        # Token com assinatura errada.
        bad = jwt.encode(
            {
                "sub": "1",
                "type": "access",
                "iss": "openm",
                "aud": "openm-api",
                "exp": int(time.time()) + 60,
            },
            "wrong-secret",
            algorithm="HS256",
        )
        resp = prot_client.get("/", headers={"Cookie": f"openm_access={bad}"})
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/login")

    def test_index_with_refresh_token_in_cookie_redirects(self, prot_app, prot_user):
        # Refresh token no lugar errado (cookie openm_access) → redirect.
        # Captura o refresh token via um client temporário pra não persistir
        # o openm_access no client principal.
        temp_client = prot_app.test_client()
        login_resp = temp_client.post(
            "/api/auth/login",
            json={"email": "prot@example.com", "password": "good-password-123"},
        )
        refresh_value = None
        for sc in login_resp.headers.getlist("Set-Cookie"):
            if sc.startswith("openm_refresh="):
                refresh_value = sc.split(";")[0].split("=", 1)[1]
                break
        assert refresh_value is not None

        # Usa um NOVO client (sem cookies) pra evitar persistência.
        fresh_client = prot_app.test_client()
        resp = fresh_client.get(
            "/",
            headers={"Cookie": f"openm_access={refresh_value}"},
        )
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/login")

    def test_index_with_no_cookie_at_all_redirects(self, prot_client):
        resp = prot_client.get("/")
        assert resp.status_code == 302

    def test_index_with_bearer_header_renders(self, prot_client, prot_user):
        cookies = _login_and_get_cookies(prot_client)
        # Extrai o token do "openm_access=<jwt>".
        token = cookies["access"].split("=", 1)[1]
        resp = prot_client.get("/", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200


class TestInactiveUserRedirects:
    def test_inactive_user_redirects_to_login(self, prot_app, prot_client, prot_user):
        # Faz login ANTES de desativar (senão login falha).
        cookies = _login_and_get_cookies(prot_client)
        assert cookies["access"] is not None

        # Agora desativa o user.
        with prot_app.app_context():
            u = User.query.get(prot_user)
            u.is_active = False
            db.session.commit()

        # Cookie ainda válido (assinatura ok), mas user está inativo.
        # /api/auth/me deve rejeitar com 401.
        me_resp = prot_client.get("/api/auth/me", headers={"Cookie": cookies["access"]})
        assert me_resp.status_code == 401

        # / (página HTML) deve redirecionar pra /login.
        index_resp = prot_client.get("/", headers={"Cookie": cookies["access"]})
        assert index_resp.status_code == 302
        assert index_resp.headers["Location"].endswith("/login")
