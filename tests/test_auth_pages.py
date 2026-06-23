"""
Testes das páginas HTML de autenticação (issue #13).

Cobre:
- GET /login renderiza
- GET /register renderiza quando ALLOW_REGISTRATION=true; redireciona/403 quando false
- GET /logout limpa cookies e redireciona
- Cookies httpOnly são setados em /api/auth/login e usados em requests subsequentes
"""

from __future__ import annotations

import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User


# ================ Fixtures ================

class PagesTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


@pytest.fixture
def pages_app():
    app = create_app(PagesTestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def pages_client(pages_app):
    return pages_app.test_client()


@pytest.fixture
def pages_user(pages_app):
    """Cria um usuário para os testes que precisam de login."""
    with pages_app.app_context():
        user = User(
            email="pageuser@example.com",
            password_hash=hash_password("page-password-123"),
            role="analyst",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
    return "pageuser@example.com"


# ================ /login ================

class TestLoginPage:
    def test_login_page_renders(self, pages_client):
        resp = pages_client.get("/login")
        assert resp.status_code == 200
        assert b"<form" in resp.data
        assert b'id="email"' in resp.data
        assert b'id="password"' in resp.data
        assert b"OpenM" in resp.data

    def test_login_page_is_public(self, pages_client):
        # Sem cookie, sem header — deve abrir normal.
        resp = pages_client.get("/login")
        assert resp.status_code == 200

    def test_login_page_hides_register_link_when_disabled(self, pages_app):
        class Cfg(PagesTestConfig):
            ALLOW_REGISTRATION = False

        app = create_app(Cfg)
        app.config["TESTING"] = True
        client = app.test_client()
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Registre-se" not in resp.data


# ================ /register ================

class TestRegisterPage:
    def test_register_page_renders_when_allowed(self, pages_client):
        resp = pages_client.get("/register")
        assert resp.status_code == 200
        assert b"id=\"password2\"" in resp.data
        assert b"Criar nova conta" in resp.data

    def test_register_page_blocked_when_disabled(self, pages_app):
        class Cfg(PagesTestConfig):
            ALLOW_REGISTRATION = False

        app = create_app(Cfg)
        app.config["TESTING"] = True
        client = app.test_client()
        resp = client.get("/register")
        # 403 + renderiza login.html
        assert resp.status_code == 403
        assert b"<form" in resp.data


# ================ /logout ================

class TestLogoutPage:
    def test_logout_redirects_to_login(self, pages_client):
        resp = pages_client.get("/logout")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/login")

    def test_logout_clears_cookies(self, pages_client, pages_user):
        # Faz login pra criar cookies httpOnly.
        login_resp = pages_client.post(
            "/api/auth/login",
            json={"email": pages_user, "password": "page-password-123"},
        )
        assert login_resp.status_code == 200
        cookies = {c.split("=")[0] for c in login_resp.headers.getlist("Set-Cookie")}
        assert "openm_access" in cookies
        assert "openm_refresh" in cookies

        # Logout deve limpar ambos.
        logout_resp = pages_client.get("/logout")
        assert logout_resp.status_code == 302
        # Set-Cookie com valor vazio (=;) é o sinal de delete.
        del_cookies = {c.split("=")[0] for c in logout_resp.headers.getlist("Set-Cookie")}
        assert "openm_access" in del_cookies
        assert "openm_refresh" in del_cookies


# ================ Cookies httpOnly ================

class TestHttpOnlyCookies:
    def test_login_sets_httponly_cookies(self, pages_client, pages_user):
        resp = pages_client.post(
            "/api/auth/login",
            json={"email": pages_user, "password": "page-password-123"},
        )
        assert resp.status_code == 200
        cookie_attrs = "; ".join(resp.headers.getlist("Set-Cookie"))
        assert "HttpOnly" in cookie_attrs
        assert "openm_access" in cookie_attrs
        assert "openm_refresh" in cookie_attrs

    def test_me_works_via_cookie_only(self, pages_client, pages_user):
        # Login via API.
        login_resp = pages_client.post(
            "/api/auth/login",
            json={"email": pages_user, "password": "page-password-123"},
        )
        # Captura o cookie openm_access e usa-o numa request sem Authorization.
        access_cookie = None
        for sc in login_resp.headers.getlist("Set-Cookie"):
            if sc.startswith("openm_access="):
                access_cookie = sc.split(";")[0]
                break
        assert access_cookie is not None

        resp = pages_client.get("/api/auth/me", headers={"Cookie": access_cookie})
        assert resp.status_code == 200
        assert resp.get_json()["user"]["email"] == pages_user

    def test_index_works_via_cookie_only(self, pages_client, pages_user):
        # Login + captura cookie + GET / só com cookie.
        login_resp = pages_client.post(
            "/api/auth/login",
            json={"email": pages_user, "password": "page-password-123"},
        )
        access_cookie = None
        refresh_cookie = None
        for sc in login_resp.headers.getlist("Set-Cookie"):
            if sc.startswith("openm_access="):
                access_cookie = sc.split(";")[0]
            elif sc.startswith("openm_refresh="):
                refresh_cookie = sc.split(";")[0]
        cookie_hdr = "; ".join(c for c in (access_cookie, refresh_cookie) if c)

        resp = pages_client.get("/", headers={"Cookie": cookie_hdr})
        assert resp.status_code == 200
        assert b"app-shell" in resp.data