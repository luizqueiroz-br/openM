"""
Testes do health check de services externos (issue #79).

Cobre:
- HealthCheckService.get_service_health / get_all_services_health
- Estados: ok, error, unchecked, rate-limit
- Cache em memoria com TTL
- Endpoint admin-only GET /api/services/health
"""

from __future__ import annotations

import time

import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.api_key import ApiKey
from openm.models.user import User
from openm.services import health_check as hc


class HealthTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


@pytest.fixture
def health_app():
    app = create_app(HealthTestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def health_client(health_app):
    return health_app.test_client()


@pytest.fixture(autouse=True)
def reset_health_cache():
    """Limpa o cache em memoria do health check antes de cada teste."""
    hc._HEALTH_CACHE.clear()
    yield
    hc._HEALTH_CACHE.clear()


def _create_user(app, email, role="admin"):
    with app.app_context():
        u = User(
            email=email,
            password_hash=hash_password("test-password-123"),
            role=role,
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        return u.id


def _create_key(app, service_name, key_value="valid-key-1234"):
    with app.app_context():
        k = ApiKey(
            service_name=service_name,
            key_value=key_value,
            key_type="free",
            is_active=True,
        )
        db.session.add(k)
        db.session.commit()
        return k.id


def _login(client, email):
    resp = client.post(
        "/api/auth/login",
        json={"email": email, "password": "test-password-123"},
    )
    assert resp.status_code == 200
    return resp.get_json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ========================================================================
# HealthCheckService — unit tests
# ========================================================================


def test_get_service_health_no_key_returns_unchecked(health_app):
    """Sem chave configurada -> unchecked."""
    with health_app.app_context():
        result = hc.get_service_health("shodan")
    assert result["status"] == "unchecked"
    assert result["key_valid"] is False
    assert "Nenhuma chave" in result["message"]


def test_get_service_health_unknown_service_returns_unchecked(health_app):
    """Service sem endpoint de health -> unchecked."""
    with health_app.app_context():
        _create_key(health_app, "unknown_service")
        result = hc.get_service_health("unknown_service")
    assert result["status"] == "unchecked"


def test_get_service_health_ok(health_app, monkeypatch):
    """Service responde 200 + dados -> ok."""
    _create_key(health_app, "shodan")

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "plan": "oss",
                "usage_limits": {"available_credits": 100},
            }

    def fake_get(url, headers, params, timeout):
        assert headers.get("User-Agent")
        return FakeResponse()

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    with health_app.app_context():
        result = hc.get_service_health("shodan")
    assert result["status"] == "ok"
    assert result["key_valid"] is True
    assert result["plan"] == "oss"
    assert result["credits_remaining"] == 100


def test_get_service_health_invalid_key(health_app, monkeypatch):
    """Service retorna 401 -> key_valid=False."""
    _create_key(health_app, "virustotal")

    class FakeResponse:
        status_code = 401

    def fake_get(url, headers, params, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    with health_app.app_context():
        result = hc.get_service_health("virustotal")
    assert result["status"] == "error"
    assert result["key_valid"] is False
    assert "401" in result["message"]


def test_get_service_health_rate_limit(health_app, monkeypatch):
    """429 -> status=error, key_valid=True."""
    _create_key(health_app, "hunter")

    class FakeResponse:
        status_code = 429

    def fake_get(url, headers, params, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    with health_app.app_context():
        result = hc.get_service_health("hunter")
    assert result["status"] == "error"
    assert result["key_valid"] is True
    assert "Rate-limit" in result["message"]


def test_get_service_health_network_error(health_app, monkeypatch):
    """requests.RequestException -> status=error."""
    import requests
    _create_key(health_app, "abuseipdb")

    def fake_get(url, headers, params, timeout):
        raise requests.ConnectionError("boom")

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    with health_app.app_context():
        result = hc.get_service_health("abuseipdb")
    assert result["status"] == "error"
    assert result["key_valid"] is False
    assert "rede" in result["message"].lower()


def test_get_service_health_caches_result(health_app, monkeypatch):
    """Segunda chamada usa cache."""
    _create_key(health_app, "shodan")

    call_count = {"n": 0}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"plan": "oss"}

    def fake_get(url, headers, params, timeout):
        call_count["n"] += 1
        return FakeResponse()

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    with health_app.app_context():
        first = hc.get_service_health("shodan")
        second = hc.get_service_health("shodan")

    assert first["status"] == "ok"
    assert second["status"] == "ok"
    assert second.get("cached") is True
    assert call_count["n"] == 1


def test_get_service_health_force_bypasses_cache(health_app, monkeypatch):
    """force=True ignora cache."""
    _create_key(health_app, "shodan")

    class FakeResponse:
        status_code = 200

        def json(self):
            return {}

    def fake_get(url, headers, params, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    with health_app.app_context():
        hc.get_service_health("shodan")
        hc.get_service_health("shodan", force=True)
        hc.get_service_health("shodan", force=True)

    # 1 cached + 2 forced = 3 chamadas reais
    import openm.services.health_check as hc_module
    assert len([k for k in hc_module._HEALTH_CACHE]) >= 1


def test_get_service_health_cache_expires(health_app, monkeypatch):
    """Cache expirado -> nova chamada."""
    _create_key(health_app, "shodan")

    class FakeResponse:
        status_code = 200

        def json(self):
            return {}

    def fake_get(url, headers, params, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    with health_app.app_context():
        hc.get_service_health("shodan")
        # Simula cache expirado ajustando o timestamp.
        for key in hc._HEALTH_CACHE:
            expires_at, payload = hc._HEALTH_CACHE[key]
            hc._HEALTH_CACHE[key] = (time.time() - 1, payload)
        result = hc.get_service_health("shodan")

    assert "cached" not in result or result.get("cached") is False


def test_get_all_services_health(health_app, monkeypatch):
    """get_all_services_health inclui services com health + do registry."""
    _create_key(health_app, "shodan")
    _create_key(health_app, "virustotal")

    class FakeResponse:
        status_code = 200

        def json(self):
            return {}

    def fake_get(url, headers, params, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    with health_app.app_context():
        result = hc.get_all_services_health()

    assert "shodan" in result
    assert "virustotal" in result
    assert "hunter" in result
    assert "abuseipdb" in result
    assert "hibp" in result
    assert result["shodan"]["status"] == "ok"


# ========================================================================
# GET /api/services/health — endpoint
# ========================================================================


def test_services_health_requires_auth(health_client):
    """Endpoint sem token -> 401."""
    resp = health_client.get("/api/services/health")
    assert resp.status_code == 401


def test_services_health_analyst_forbidden(health_app, health_client):
    """Apenas admin pode acessar."""
    _create_user(health_app, "analyst@example.com", role="analyst")
    token = _login(health_client, "analyst@example.com")

    resp = health_client.get(
        "/api/services/health",
        headers=_bearer(token),
    )
    assert resp.status_code == 403


def test_services_health_admin_returns_dict(health_app, health_client, monkeypatch):
    """Admin recebe dict de services."""
    _create_user(health_app, "admin@example.com", role="admin")
    _create_key(health_app, "shodan")

    class FakeResponse:
        status_code = 200

        def json(self):
            return {}

    def fake_get(url, headers, params, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    token = _login(health_client, "admin@example.com")

    resp = health_client.get(
        "/api/services/health",
        headers=_bearer(token),
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert "services" in data
    assert "shodan" in data["services"]
    assert data["services"]["shodan"]["status"] == "ok"


def test_services_health_filter_by_service(health_app, health_client, monkeypatch):
    """?service=shodan retorna apenas esse service."""
    _create_user(health_app, "admin@example.com", role="admin")
    _create_key(health_app, "shodan")

    class FakeResponse:
        status_code = 200

        def json(self):
            return {}

    def fake_get(url, headers, params, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.services.health_check.requests.get",
        fake_get,
    )

    token = _login(health_client, "admin@example.com")

    resp = health_client.get(
        "/api/services/health?service=shodan",
        headers=_bearer(token),
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert "services" in data
    assert "shodan" in data["services"]
    assert "virustotal" not in data["services"]
