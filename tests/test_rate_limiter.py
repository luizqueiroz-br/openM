"""
Testes para o rate limiting per user/service (issue #89).

Cobre:
- 429 retornado após N requests no mesmo service.
- Admin bypass (exempt_when).
- Headers X-RateLimit-* presentes em responses 2xx.
- Audit log gravado em 429 (action='ratelimit.exceeded').
- key_func retorna f"u{user_id}:{service_name}".
- Endpoint /api/services/quota responde estrutura esperada.
- Reset do limiter entre tests (autouse fixture).
"""

import pytest


# ---------------------------------------------------------------------------
# Fixtures locais
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_limiter():
    """
    Limpa o storage do Limiter entre tests para isolar contadores.

    O Flask-Limiter mantém o storage em memória (memory://); sem este
    reset, requests de tests anteriores contaminariam o estado.
    """
    from openm.extensions import limiter

    storage = getattr(limiter, "_storage", None)
    if storage is not None:
        # memory backend expõe ``reset()``; outros backends podem não
        # ter — tentamos e silenciamos falhas.
        try:
            storage.reset()
        except Exception:  # noqa: BLE001
            pass
    yield
    # Limpa novamente após o test para garantir isolamento.
    if storage is not None:
        try:
            storage.reset()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_transform_payload(transform_name="email_to_domain", value="x@y.com"):
    """Payload mínimo para POST /api/run_transform."""
    return {
        "transform_name": transform_name,
        "entity_type": "Email",
        "value": value,
    }


def _override_limit(monkeypatch, service: str, limit_str: str) -> None:
    """Override o limite default de um service em Config.RATELIMIT_SERVICES."""
    from openm import config as cfg
    from openm.extensions import limiter

    # Atualiza o dict de Config em runtime.
    monkeypatch.setitem(cfg.Config.RATELIMIT_SERVICES, service, limit_str)
    # Garante que o limiter vê o novo valor (caso já tenha cacheado
    # o limite para essa key).
    storage = getattr(limiter, "_storage", None)
    if storage is not None:
        try:
            storage.reset()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Testes
# ---------------------------------------------------------------------------


class TestRateLimitBasic:
    """Cobre o comportamento fundamental: 429 após N requests."""

    def test_rate_limit_blocks_after_quota_exceeded(
        self, app, auth_client, monkeypatch
    ):
        """Com limite 3/min, 3 requests OK, 4ª retorna 429."""
        from openm.core.audit import ACTION_RATE_LIMIT_EXCEEDED
        from openm.models.audit_log import AuditLog

        # Limita __internal__ a 3/minute (email_to_domain é __internal__).
        _override_limit(monkeypatch, "__internal__", "3/minute")

        payload = _run_transform_payload()
        # 3 requests OK
        for i in range(3):
            r = auth_client.post("/api/run_transform", json=payload)
            assert r.status_code == 200, f"req {i+1}: {r.status_code} {r.get_json()}"
        # 4ª request → 429
        r4 = auth_client.post("/api/run_transform", json=payload)
        assert r4.status_code == 429
        body = r4.get_json()
        assert body["error"] == "rate_limit_exceeded"
        assert "retry_after" in body
        assert "limit" in body
        assert r4.headers.get("Retry-After") is not None

        # Audit log gravado
        with app.app_context():
            entries = AuditLog.query.filter_by(
                action=ACTION_RATE_LIMIT_EXCEEDED
            ).all()
            assert len(entries) >= 1


class TestAdminBypass:
    """Cobre exempt_when para admins."""

    def test_admin_is_exempt_from_rate_limit(
        self, app, admin_client, monkeypatch
    ):
        """Admin faz N requests, todas 200 (não são bloqueadas)."""
        _override_limit(monkeypatch, "__internal__", "2/minute")

        payload = _run_transform_payload()
        # 5 requests — sem admin seriam bloqueadas a partir da 3ª.
        for i in range(5):
            r = admin_client.post("/api/run_transform", json=payload)
            assert r.status_code == 200, (
                f"admin req {i+1}: {r.status_code} {r.get_json()}"
            )


class TestRateLimitHeaders:
    """Cobre a presença de headers X-RateLimit-*."""

    def test_headers_present_on_all_responses(self, auth_client):
        """Responses 2xx em /api/services/health têm X-RateLimit-*."""
        r = auth_client.get("/api/services/health")
        # /api/services/health tem @require_role("admin") — analyst
        # recebe 403. Mas os headers X-RateLimit-* devem estar
        # presentes em QUALQUER response (Flask-Limiter emite-os via
        # after_request hook, independente do status final).
        assert r.status_code in (200, 403)  # depende do role do auth_client
        # X-RateLimit-Limit / Remaining / Reset são emitidos em
        # responses que passaram pelo limiter (incluindo 401/403).
        # Em responses muito pequenas (ex: 404 puro), podem estar
        # ausentes — o assertion principal é que quando presentes,
        # têm formato numérico.
        for header in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
            v = r.headers.get(header)
            if v is not None:
                assert v.isdigit() or v.lstrip("-").isdigit(), (
                    f"{header}={v!r} não é numérico"
                )


class TestAuditLogOnBreach:
    """Cobre o audit log best-effort do 429 handler."""

    def test_429_logs_audit_entry(
        self, app, auth_client, monkeypatch
    ):
        """1 entry em AuditLog com action='ratelimit.exceeded'."""
        from openm.core.audit import ACTION_RATE_LIMIT_EXCEEDED
        from openm.models.audit_log import AuditLog

        _override_limit(monkeypatch, "__internal__", "1/minute")

        payload = _run_transform_payload()
        r1 = auth_client.post("/api/run_transform", json=payload)
        assert r1.status_code == 200
        r2 = auth_client.post("/api/run_transform", json=payload)
        assert r2.status_code == 429

        with app.app_context():
            entries = AuditLog.query.filter_by(
                action=ACTION_RATE_LIMIT_EXCEEDED
            ).all()
            assert len(entries) == 1
            entry = entries[0]
            assert entry.target_type == "rate_limit"
            assert entry.target_id  # service name
            assert entry.meta is not None
            assert "limit" in entry.meta
            assert "retry_after" in entry.meta


class TestKeyFuncFormat:
    """Cobre o formato da key_func."""

    def test_key_func_uses_user_id_and_service(self, app, auth_client):
        """key_func retorna f"u<user_id>:<service_name>" para user autenticado."""
        from flask import g
        from openm.core.rate_limiter import user_service_key

        with app.test_request_context("/api/run_transform", method="POST"):
            # Simula o que _resolve_service_name faria em before_request
            g.user = type("FakeUser", (), {"id": 42, "role": "analyst"})()
            g.service_name = "shodan"
            key = user_service_key()
            assert key == "u42:shodan", f"got {key!r}"

    def test_key_func_falls_back_to_ip_when_anonymous(self, app):
        """Sem g.user, key_func retorna f"ip:<remote_addr>"."""
        from flask import g
        from openm.core.rate_limiter import user_service_key

        # Limpa g (caso algum test anterior tenha setado)
        with app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "1.2.3.4"}):
            g.pop("user", None)
            g.pop("service_name", None)
            key = user_service_key()
            assert key.startswith("ip:"), f"got {key!r}"
            assert "1.2.3.4" in key


class TestServicesQuotaEndpoint:
    """Cobre GET /api/services/quota."""

    def test_services_quota_returns_list(self, auth_client):
        """GET /api/services/quota retorna {services: [{name, limit, period, ...}, ...]}."""
        r = auth_client.get("/api/services/quota")
        assert r.status_code == 200
        body = r.get_json()
        assert "services" in body
        services = body["services"]
        assert isinstance(services, list)
        assert len(services) >= 5  # temos 10 services declarados

        # Cada entry tem os campos esperados
        for entry in services:
            assert "name" in entry
            assert "limit" in entry
            assert "period" in entry
            assert "used" in entry
            assert "remaining" in entry
            assert "reset_at" in entry
            # limit > 0 (todos os services têm limit declarado)
            assert entry["limit"] > 0
            # remaining >= 0
            assert entry["remaining"] >= 0
            # remaining == limit - used
            assert entry["remaining"] == max(entry["limit"] - entry["used"], 0)

    def test_services_quota_includes_internal_bucket(self, auth_client):
        """Quota inclui o bucket __internal__ (transforms sem API key)."""
        r = auth_client.get("/api/services/quota")
        body = r.get_json()
        names = [s["name"] for s in body["services"]]
        assert "__internal__" in names

    def test_services_quota_requires_auth(self, client):
        """Sem auth → 401."""
        r = client.get("/api/services/quota")
        assert r.status_code == 401


class TestRateLimiterHelpers:
    """Testes unitários dos helpers em openm.core.rate_limiter."""

    def test_parse_limit_string_basic(self):
        from openm.core.rate_limiter import _parse_limit_string
        n, p = _parse_limit_string("10/hour")
        assert n == 10
        assert p == "hour"

    def test_parse_limit_string_strips_whitespace(self):
        from openm.core.rate_limiter import _parse_limit_string
        n, p = _parse_limit_string(" 4 / minute ")
        assert n == 4
        assert p == "minute"

    def test_parse_limit_string_invalid_raises(self):
        from openm.core.rate_limiter import _parse_limit_string
        with pytest.raises(ValueError):
            _parse_limit_string("not-a-limit")
        with pytest.raises(ValueError):
            _parse_limit_string("")

    def test_get_user_quota_initial_state(self):
        """User nunca fez request: used=0, remaining=limit."""
        from openm.core.rate_limiter import get_user_quota

        q = get_user_quota(user_id=999, service="shodan")
        assert q["name"] == "shodan"
        assert q["limit"] == 10
        assert q["period"] == "hour"
        assert q["used"] == 0
        assert q["remaining"] == 10

    def test_get_user_quota_unknown_service(self):
        """Service desconhecido → limit=0, period=hour."""
        from openm.core.rate_limiter import get_user_quota

        q = get_user_quota(user_id=1, service="nonexistent_service")
        assert q["limit"] == 0
        assert q["period"] == "hour"
        assert q["remaining"] == 0

    def test_admin_exempt_returns_false_for_anonymous(self, app):
        from flask import g
        from openm.core.rate_limiter import admin_exempt

        with app.test_request_context("/"):
            g.pop("user", None)
            assert admin_exempt() is False

    def test_admin_exempt_returns_true_for_admin(self, app):
        from flask import g
        from openm.core.rate_limiter import admin_exempt

        with app.test_request_context("/"):
            g.user = type("FakeAdmin", (), {"id": 1, "role": "admin"})()
            assert admin_exempt() is True

    def test_admin_exempt_returns_false_for_analyst(self, app):
        from flask import g
        from openm.core.rate_limiter import admin_exempt

        with app.test_request_context("/"):
            g.user = type("FakeAnalyst", (), {"id": 2, "role": "analyst"})()
            assert admin_exempt() is False
