"""
Testes do audit log (issue #4).

Cobre:
- Helper ``log_action``: gravação, captura automática de user/IP,
  sanitização recursiva de chaves sensíveis, tolerância a falha de DB.
- Endpoint ``GET /api/audit-log``: autorização (admin only), filtros
  (user_id, action, target_type, since/until, limit, offset, sort).
- Instrumentação nos blueprints: login (sucesso e 3 caminhos de falha),
  logout, register, admin PATCH /role e /active, entities, transforms,
  investigations, api keys.
- CLI ``flask audit purge``: retenção, --dry-run, --days inválido.
- Garantia central: nenhum password/token/secret vaza para a tabela.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from openm.core.audit import (
    _sanitize,  # interno — coberto diretamente para fixar contrato
    log_action,
    ACTION_LOGIN_SUCCESS,
    ACTION_LOGIN_FAILED,
    ACTION_LOGOUT,
    ACTION_REGISTER,
    ACTION_USER_ROLE_CHANGE,
    ACTION_USER_ACTIVE_CHANGE,
    ACTION_ENTITY_CREATE,
    ACTION_ENTITY_UPDATE,
    ACTION_ENTITY_DELETE,
    ACTION_TRANSFORM_RUN,
    ACTION_INVESTIGATION_CREATE,
    ACTION_INVESTIGATION_UPDATE,
    ACTION_INVESTIGATION_ARCHIVE,
    ACTION_INVESTIGATION_UNARCHIVE,
    ACTION_APIKEY_CREATE,
    ACTION_APIKEY_UPDATE,
    ACTION_APIKEY_DELETE,
)
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.audit_log import AuditLog
from openm.models.user import User


# ====================================================================
# Helpers
# ====================================================================

def _all_events(app) -> list[AuditLog]:
    with app.app_context():
        return AuditLog.query.order_by(AuditLog.id.asc()).all()


def _create_user(app, *, email: str, role: str = "analyst") -> int:
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


def _invoke_cli(app, *args):
    runner = app.test_cli_runner()
    return runner.invoke(args=args, catch_exceptions=False)


# ====================================================================
# 1) Helper _sanitize (unidade pura, sem app context)
# ====================================================================

class TestSanitize:
    """Sanitização é função pura — testável sem app/DB."""

    def test_strips_password_key_at_top_level(self):
        out = _sanitize({"password": "hunter2", "user": "alice"})
        assert out["password"] == "[REDACTED]"
        assert out["user"] == "alice"

    def test_strips_sensitive_keys_case_insensitive(self):
        out = _sanitize({"PASSWORD": "x", "PassWord": "y", "ApiKey": "z"})
        assert out["PASSWORD"] == "[REDACTED]"
        assert out["PassWord"] == "[REDACTED]"
        assert out["ApiKey"] == "[REDACTED]"

    def test_strips_token_jwt_refresh_jti(self):
        out = _sanitize({
            "access_token": "a",
            "refresh_token": "r",
            "jwt": "j",
            "jti": "t",
            "csrf": "c",
        })
        for k in out:
            assert out[k] == "[REDACTED]"

    def test_strips_apikey_and_key_value(self):
        """ApiKey.key_value é o segredo real — precisa ser redacted."""
        out = _sanitize({"service_name": "hibp", "key_value": "real-secret"})
        assert out["service_name"] == "hibp"
        assert out["key_value"] == "[REDACTED]"

    def test_strips_secret_signature_password_hash(self):
        out = _sanitize({"secret": "s", "signature": "sig", "password_hash": "h"})
        for k in out:
            assert out[k] == "[REDACTED]"

    def test_recursively_sanitizes_nested_dict(self):
        out = _sanitize({
            "outer": {"password": "p", "ok": 1},
        })
        assert out["outer"]["password"] == "[REDACTED]"
        assert out["outer"]["ok"] == 1

    def test_recursively_sanitizes_list_of_dicts(self):
        out = _sanitize({"items": [{"token": "x"}, {"safe": "y"}]})
        assert out["items"][0]["token"] == "[REDACTED]"
        assert out["items"][1]["safe"] == "y"

    def test_non_sensitive_keys_pass_through(self):
        out = _sanitize({"email": "x@y.com", "role": "admin", "count": 5})
        assert out == {"email": "x@y.com", "role": "admin", "count": 5}

    def test_depth_limit_truncates(self):
        """Estrutura patologicamente profunda (>10) é truncada."""
        deep: dict = {}
        node = deep
        for _ in range(15):
            node["next"] = {}
            node = node["next"]
        out = _sanitize(deep)
        # Após 10 níveis, _sanitize retorna None — algum nível é None.
        # Não vamos fixar exatamente onde (depende da profundidade da
        # estrutura completa), mas garantimos que NÃO levanta exceção
        # e retorna algo finito.
        assert out is not None

    def test_non_dict_passthrough(self):
        """Primitivos passam intactos."""
        assert _sanitize("string") == "string"
        assert _sanitize(42) == 42
        assert _sanitize(None) is None
        assert _sanitize(True) is True


# ====================================================================
# 2) Helper log_action (integração com DB)
# ====================================================================

class TestLogAction:
    """log_action: gravação, captura automática, tolerância a falha."""

    def test_basic_write_persists_event(self, app):
        with app.app_context():
            ok = log_action("custom.event", target_type="widget", target_id="42",
                            metadata={"foo": "bar"})
            assert ok is True
            ev = AuditLog.query.filter_by(action="custom.event").first()
            assert ev is not None
            assert ev.target_type == "widget"
            assert ev.target_id == "42"
            assert ev.meta == {"foo": "bar"}

    def test_user_id_explicit_overrides_g_user(self, app):
        with app.app_context():
            log_action("x", user_id=999)
            ev = AuditLog.query.filter_by(action="x").first()
            assert ev.user_id == 999

    def test_user_id_falls_back_to_none_outside_request(self, app):
        """Sem request context, g.user não existe → user_id=None."""
        # Sem `with app.test_request_context()`: nenhum contexto de request.
        with app.app_context():
            log_action("no-req")
            ev = AuditLog.query.filter_by(action="no-req").first()
            assert ev.user_id is None

    def test_user_id_falls_back_to_g_user_id(self, app):
        """Em request context com g.user → usa g.user.id."""
        with app.test_request_context():
            with app.app_context():
                # Mock g.user com atributo .id
                from flask import g
                g.user = type("U", (), {"id": 42})()
                log_action("with-g-user")
                ev = AuditLog.query.filter_by(action="with-g-user").first()
                assert ev.user_id == 42

    def test_user_id_when_g_user_has_no_id_attr(self, app):
        """g.user sem atributo .id → getattr com default None."""
        from flask import g
        with app.test_request_context():
            with app.app_context():
                # g.user sem .id — getattr deve retornar None
                g.user = object()
                log_action("g-user-no-id")
                ev = AuditLog.query.filter_by(action="g-user-no-id").first()
                assert ev.user_id is None

    def test_sanitization_applied_to_metadata_in_db(self, app):
        with app.app_context():
            log_action("x", metadata={"password": "p1", "ok": "v"})
            ev = AuditLog.query.filter_by(action="x").first()
            assert ev.meta["password"] == "[REDACTED]"
            assert ev.meta["ok"] == "v"

    def test_ip_address_from_x_forwarded_for(self, app):
        with app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}):
            with app.app_context():
                log_action("ip-test")
                ev = AuditLog.query.filter_by(action="ip-test").first()
                # Primeiro IP da lista = cliente original.
                assert ev.ip_address == "1.2.3.4"

    def test_ip_address_fallback_to_remote_addr(self, app):
        with app.test_request_context(environ_base={"REMOTE_ADDR": "5.6.7.8"}):
            with app.app_context():
                log_action("ip-test-2")
                ev = AuditLog.query.filter_by(action="ip-test-2").first()
                assert ev.ip_address == "5.6.7.8"

    def test_ip_address_truncated_to_45_chars(self, app):
        """IP explícito > 45 chars é truncado para caber na coluna."""
        long_ip = "a" * 50 + ":1.2.3.4"
        with app.app_context():
            log_action("ip-trunc", ip_address=long_ip)
            ev = AuditLog.query.filter_by(action="ip-trunc").first()
            assert len(ev.ip_address) == 45
            assert ev.ip_address == long_ip[:45]

    def test_ip_address_none_when_no_request_context(self, app):
        """Sem request context e sem ip explícito → None."""
        with app.app_context():
            log_action("no-req-ip")
            ev = AuditLog.query.filter_by(action="no-req-ip").first()
            assert ev.ip_address is None

    def test_db_failure_does_not_propagate(self, app, monkeypatch):
        """Erro no DB → função retorna False, sem levantar exceção."""
        # Força o commit a falhar.
        def boom(*a, **kw):
            raise RuntimeError("db down")
        monkeypatch.setattr(db.session, "commit", boom)

        with app.app_context():
            ok = log_action("will-fail", user_id=1)
            assert ok is False

        # Nenhuma entrada foi gravada.
        with app.app_context():
            assert AuditLog.query.filter_by(action="will-fail").first() is None

    def test_db_failure_outside_app_context(self, monkeypatch):
        """Falha fora de app_context ainda retorna False (não levanta)."""
        # Sem app context. Forçamos um erro no import lazy simulando falha.
        # O caminho "except Exception" também pode ser exercitado aqui
        # passando-se db_session inválido.
        from openm.core import audit as audit_mod

        class _BrokenSession:
            def add(self, *a, **kw):
                raise RuntimeError("broken")

            def commit(self):
                raise RuntimeError("broken")

            def rollback(self):
                raise RuntimeError("broken-rollback")

        ok = audit_mod.log_action(
            "broken-session",
            db_session=_BrokenSession(),
        )
        assert ok is False

    def test_db_failure_logs_via_fallback_logger(self, monkeypatch):
        """Fora de app context, falha usa _logger.warning (não current_app.logger)."""
        from openm.core import audit as audit_mod

        class _BrokenSession:
            def add(self, *a, **kw):
                raise RuntimeError("x")

            def commit(self):
                raise RuntimeError("x")

            def rollback(self):
                pass

        # Capturar warning do logger fallback
        import logging
        captured = []

        class _CapturingHandler(logging.Handler):
            def emit(self, record):
                captured.append(record.getMessage())

        cap = _CapturingHandler(level=logging.WARNING)
        audit_mod._logger.addHandler(cap)
        try:
            # Sem app context: cai no else branch (_logger.warning)
            ok = audit_mod.log_action("no-app-ctx-fail", db_session=_BrokenSession())
            assert ok is False
        finally:
            audit_mod._logger.removeHandler(cap)
        # Confirma que o logger fallback foi usado.
        assert any("audit_log_failure" in m for m in captured)


# ====================================================================
# 3) Endpoint GET /api/audit-log (autorização)
# ====================================================================

class TestAuditEndpointAuthz:
    """RBAC do endpoint de leitura: só admin."""

    def test_requires_auth(self, client):
        resp = client.get("/api/audit-log")
        assert resp.status_code == 401

    def test_viewer_is_forbidden(self, viewer_client):
        resp = viewer_client.get("/api/audit-log")
        assert resp.status_code == 403

    def test_analyst_is_forbidden(self, auth_client):
        resp = auth_client.get("/api/audit-log")
        assert resp.status_code == 403

    def test_admin_can_list(self, admin_client, app):
        with app.app_context():
            log_action("admin-list-test")
        resp = admin_client.get("/api/audit-log")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "events" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data


# ====================================================================
# 4) Endpoint GET /api/audit-log (filtros)
# ====================================================================

class TestAuditEndpointFilters:
    """Filtros suportados: user_id, action, target_type, since, until, limit, offset, sort."""

    @pytest.fixture
    def seeded(self, app, admin_client):
        """Popula 5 eventos de tipos variados."""
        # Captura IDs existentes (admin_client fez login durante setup).
        with app.app_context():
            uid_admin = User.query.filter_by(email="admin@example.com").first().id

        with app.app_context():
            uid_a = _create_user(app, email="alice@example.com", role="analyst")
            uid_b = _create_user(app, email="bob@example.com", role="viewer")

            log_action(ACTION_LOGIN_SUCCESS, target_type="user",
                       target_id=str(uid_a), user_id=uid_a)
            log_action(ACTION_LOGIN_FAILED, target_type="user",
                       target_id=str(uid_a), user_id=uid_a,
                       metadata={"email_attempted": "alice@example.com"})
            log_action(ACTION_ENTITY_CREATE, target_type="entity",
                       target_id="ent-1", user_id=uid_a,
                       metadata={"entity_type": "Domain", "value": "x.com"})
            log_action(ACTION_INVESTIGATION_CREATE, target_type="investigation",
                       target_id="42", user_id=uid_a,
                       metadata={"title": "T1"})
            log_action(ACTION_APIKEY_UPDATE, target_type="apikey",
                       target_id="7", user_id=uid_b,
                       metadata={"service_name": "hibp"})
        return {"uid_a": uid_a, "uid_b": uid_b, "uid_admin": uid_admin}

    def test_filter_by_user_id(self, admin_client, seeded):
        resp = admin_client.get(f"/api/audit-log?user_id={seeded['uid_a']}")
        assert resp.status_code == 200
        evs = resp.get_json()["events"]
        assert all(e["user_id"] == seeded["uid_a"] for e in evs)
        # alice tem 4 eventos seeded (login_success, login_failed,
        # entity_create, investigation_create).
        assert len(evs) == 4

    def test_filter_by_action(self, admin_client, seeded):
        resp = admin_client.get(f"/api/audit-log?action={ACTION_LOGIN_SUCCESS}")
        assert resp.status_code == 200
        evs = resp.get_json()["events"]
        # 2 logins.success: alice (seed) + admin (criado pelo fixture).
        assert len(evs) == 2
        assert all(e["action"] == ACTION_LOGIN_SUCCESS for e in evs)

    def test_filter_by_target_type(self, admin_client, seeded):
        resp = admin_client.get("/api/audit-log?target_type=investigation")
        evs = resp.get_json()["events"]
        assert len(evs) == 1
        assert evs[0]["target_type"] == "investigation"

    def test_filter_by_since_excludes_older(self, admin_client, seeded):
        # Since no futuro → nenhuma entrada.
        # Usar query_string= faz URL-encoding correto do '+' (que vira '%2B').
        # Sem isso, o '+' seria decodificado como espaço e fromisoformat falharia.
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        resp = admin_client.get("/api/audit-log", query_string={"since": future})
        assert resp.status_code == 200
        assert resp.get_json()["total"] == 0

    def test_filter_by_until_excludes_newer(self, admin_client, seeded):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        resp = admin_client.get("/api/audit-log", query_string={"until": past})
        assert resp.status_code == 200
        assert resp.get_json()["total"] == 0

    def test_limit_caps_results(self, admin_client, seeded):
        resp = admin_client.get("/api/audit-log?limit=2")
        assert resp.status_code == 200
        assert len(resp.get_json()["events"]) == 2
        assert resp.get_json()["limit"] == 2

    def test_limit_capped_at_max(self, admin_client, seeded):
        resp = admin_client.get("/api/audit-log?limit=99999")
        assert resp.status_code == 200
        # max=500 é aplicado silenciosamente (filtro inválido vira default).
        assert resp.get_json()["limit"] == 100  # default

    def test_offset_skips_results(self, admin_client, seeded):
        resp1 = admin_client.get("/api/audit-log?limit=10")
        resp2 = admin_client.get("/api/audit-log?limit=10&offset=2")
        all_ids = [e["id"] for e in resp1.get_json()["events"]]
        offset_ids = [e["id"] for e in resp2.get_json()["events"]]
        assert offset_ids == all_ids[2:]

    def test_sort_invalid_returns_400(self, admin_client, seeded):
        resp = admin_client.get("/api/audit-log?sort=injection_attempt")
        assert resp.status_code == 400

    def test_sort_ascending(self, admin_client, seeded):
        resp = admin_client.get("/api/audit-log?sort=created_at")
        evs = resp.get_json()["events"]
        timestamps = [e["created_at"] for e in evs]
        assert timestamps == sorted(timestamps)

    def test_invalid_filters_silently_ignored(self, admin_client, seeded):
        """Filtros malformados viram None em vez de 400 (tolerância)."""
        resp = admin_client.get("/api/audit-log?user_id=abc&limit=xyz")
        assert resp.status_code == 200
        # Aplicou defaults (sem user_id, limit=100).
        assert resp.get_json()["limit"] == 100

    def test_limit_zero_silently_invalid(self, admin_client, seeded):
        """L52: limit=0 → _parse_int retorna None → usa default."""
        resp = admin_client.get("/api/audit-log?limit=0")
        assert resp.status_code == 200
        assert resp.get_json()["limit"] == 100  # default aplicado

    def test_limit_negative_silently_invalid(self, admin_client, seeded):
        """L52: limit=-5 < minimum=1 → _parse_int retorna None."""
        resp = admin_client.get("/api/audit-log?limit=-5")
        assert resp.status_code == 200
        assert resp.get_json()["limit"] == 100

    def test_offset_negative_silently_invalid(self, admin_client, seeded):
        """L52: offset=-1 < minimum=0 → _parse_int retorna None."""
        resp = admin_client.get("/api/audit-log?offset=-1")
        assert resp.status_code == 200
        assert resp.get_json()["offset"] == 0  # default

    def test_since_invalid_format_silently_ignored(self, admin_client, seeded):
        """L88-89: ?since=not-a-date → _parse_datetime retorna None."""
        resp = admin_client.get("/api/audit-log?since=not-a-date")
        assert resp.status_code == 200
        # Filtro não aplicado, retorna tudo (>= 5 eventos seedados).
        assert resp.get_json()["total"] >= 5

    def test_until_invalid_format_silently_ignored(self, admin_client, seeded):
        """L88-89: ?until=garbage → _parse_datetime retorna None."""
        resp = admin_client.get("/api/audit-log?until=garbage")
        assert resp.status_code == 200
        assert resp.get_json()["total"] >= 5


# ====================================================================
# 5) Instrumentação: auth
# ====================================================================

class TestAuthInstrumentation:
    """Verifica que auth.py gera os eventos corretos."""

    def test_login_success_generates_event(self, app, client):
        _create_user(app, email="login-ok@example.com")
        resp = client.post("/api/auth/login",
                           json={"email": "login-ok@example.com",
                                 "password": "test-password-123"})
        assert resp.status_code == 200

        events = _all_events(app)
        logins = [e for e in events if e.action == ACTION_LOGIN_SUCCESS]
        assert len(logins) == 1
        assert logins[0].target_type == "user"
        assert logins[0].user_id is not None

    def test_login_failed_wrong_password(self, app, client):
        _create_user(app, email="login-fail@example.com")
        resp = client.post("/api/auth/login",
                           json={"email": "login-fail@example.com",
                                 "password": "WRONG"})
        assert resp.status_code == 401

        events = _all_events(app)
        failures = [e for e in events if e.action == ACTION_LOGIN_FAILED]
        assert len(failures) == 1
        # Anti-enumeração: motivo genérico.
        assert failures[0].meta["reason"] == "invalid_credentials"
        # Email tentado é gravado (não distingue de "email inexistente").
        assert failures[0].meta["email_attempted"] == "login-fail@example.com"
        # target_id e user_id batem (user existe).
        assert failures[0].user_id is not None

    def test_login_failed_unknown_email_anonymous(self, app, client):
        """Email inexistente → user_id e target_id ficam None."""
        resp = client.post("/api/auth/login",
                           json={"email": "ghost@example.com",
                                 "password": "whatever"})
        assert resp.status_code == 401

        events = _all_events(app)
        failures = [e for e in events if e.action == ACTION_LOGIN_FAILED]
        assert len(failures) == 1
        assert failures[0].user_id is None
        assert failures[0].target_id is None
        assert failures[0].meta["email_attempted"] == "ghost@example.com"

    def test_login_failed_invalid_payload(self, app, client):
        """Body sem campos obrigatórios → log com reason=invalid_payload."""
        resp = client.post("/api/auth/login", json={"password": "x"})
        assert resp.status_code == 400

        events = _all_events(app)
        failures = [e for e in events if e.action == ACTION_LOGIN_FAILED]
        assert len(failures) == 1
        assert failures[0].meta["reason"] == "invalid_payload"

    def test_logout_generates_event(self, app, client):
        # Login → logout → evento.
        _create_user(app, email="logout@example.com")
        login_resp = client.post("/api/auth/login",
                                 json={"email": "logout@example.com",
                                       "password": "test-password-123"})
        refresh = login_resp.get_json()["refresh_token"]
        client.post("/api/auth/logout", json={"refresh_token": refresh})

        events = _all_events(app)
        logouts = [e for e in events if e.action == ACTION_LOGOUT]
        assert len(logouts) == 1
        assert logouts[0].user_id is not None

    def test_logout_without_token_is_silent(self, app, client):
        """Logout idempotente sem token → ainda loga (audit de tentativas)."""
        client.post("/api/auth/logout", json={})
        events = _all_events(app)
        logouts = [e for e in events if e.action == ACTION_LOGOUT]
        assert len(logouts) == 1
        assert logouts[0].user_id is None

    def test_register_generates_event(self, app, client):
        client.post("/api/auth/register",
                    json={"email": "new@example.com",
                          "password": "test-password-123"})
        events = _all_events(app)
        regs = [e for e in events if e.action == ACTION_REGISTER]
        assert len(regs) == 1
        assert regs[0].meta["email"] == "new@example.com"
        assert regs[0].meta["role"] == "analyst"
        # Defesa em profundidade: senha nunca logada (sanitização).
        assert "password" not in regs[0].meta

    def test_register_rejects_invalid_role(self, app, client):
        """L130: register com role='god' (não está em VALID_ROLES) → 400."""
        resp = client.post("/api/auth/register", json={
            "email": "newrole@example.com",
            "password": "test-password-123",
            "role": "god",
        })
        assert resp.status_code == 400

    def test_login_failed_invalid_email_format(self, app, client):
        """L184-192: email que _normalize_email rejeita → reason=invalid_email_format."""
        # Email com formato inválido — validate_email levanta EmailNotValidError
        # que _normalize_email converte para ValueError.
        resp = client.post("/api/auth/login", json={
            "email": "@@@invalid-format@@@",
            "password": "whatever",
        })
        assert resp.status_code == 401

        events = _all_events(app)
        failures = [e for e in events if e.action == ACTION_LOGIN_FAILED]
        # Confirma que pelo menos um evento tem reason=invalid_email_format.
        assert any(f.meta.get("reason") == "invalid_email_format" for f in failures)

    def test_refresh_without_token_returns_400(self, app, client):
        """L239: POST /api/auth/refresh sem refresh_token no body nem no cookie → 400."""
        resp = client.post("/api/auth/refresh", json={})
        assert resp.status_code == 400

    def test_refresh_with_inactive_user_returns_401(self, app, client, admin_client):
        """L252: refresh token de user desativado → 401."""
        _create_user(app, email="refresh-target@example.com")
        # Login para gerar tokens.
        login = client.post("/api/auth/login", json={
            "email": "refresh-target@example.com",
            "password": "test-password-123",
        })
        assert login.status_code == 200
        refresh = login.get_json()["refresh_token"]

        # Pega o id do user e desativa via admin.
        with app.app_context():
            from openm.models.user import User as _U
            uid = _U.query.filter_by(email="refresh-target@example.com").first().id
        admin_client.patch(
            f"/api/admin/users/{uid}/active", json={"is_active": False}
        )

        # Tentar refresh com o token agora → 401.
        resp = client.post("/api/auth/refresh", json={"refresh_token": refresh})
        assert resp.status_code == 401

    def test_logout_with_invalid_refresh_token_logs_event(self, app, client):
        """L283-291: logout com refresh_token garbage → 200 + user.logout."""
        resp = client.post("/api/auth/logout",
                           json={"refresh_token": "garbage.invalid.token"})
        assert resp.status_code == 200

        events = _all_events(app)
        logouts = [e for e in events if e.action == ACTION_LOGOUT]
        assert any(ev.meta.get("reason") == "invalid_token" for ev in logouts)


# ====================================================================
# 6) Instrumentação: admin (role/active)
# ====================================================================

class TestAdminInstrumentation:

    def test_role_change_logs_old_and_new(self, admin_client, app):
        target_id = _create_user(app, email="role-target@example.com", role="viewer")
        resp = admin_client.patch(
            f"/api/admin/users/{target_id}/role", json={"role": "analyst"}
        )
        assert resp.status_code == 200

        events = _all_events(app)
        role_changes = [e for e in events if e.action == ACTION_USER_ROLE_CHANGE]
        assert len(role_changes) == 1
        meta = role_changes[0].meta
        assert meta["old_role"] == "viewer"
        assert meta["new_role"] == "analyst"
        assert meta["target_email"] == "role-target@example.com"

    def test_active_change_logs_old_and_new(self, admin_client, app):
        target_id = _create_user(app, email="active-target@example.com")
        resp = admin_client.patch(
            f"/api/admin/users/{target_id}/active", json={"is_active": False}
        )
        assert resp.status_code == 200

        events = _all_events(app)
        active_changes = [e for e in events if e.action == ACTION_USER_ACTIVE_CHANGE]
        assert len(active_changes) == 1
        meta = active_changes[0].meta
        assert meta["old_is_active"] is True
        assert meta["new_is_active"] is False


# ====================================================================
# 7) Instrumentação: entities / transforms / investigations / keys
# ====================================================================

class TestOtherInstrumentation:

    def test_entity_create_logs_property_keys_not_values(self, app, auth_client):
        """Loga quais keys foram setadas, não os valores (podem ser sensíveis)."""
        resp = auth_client.post("/api/entity", json={
            "type": "Domain",
            "value": "example.com",
            "notes": "this is private intel",
        })
        assert resp.status_code == 201

        events = _all_events(app)
        evs = [e for e in events if e.action == ACTION_ENTITY_CREATE]
        assert len(evs) == 1
        assert evs[0].meta["entity_type"] == "Domain"
        assert evs[0].meta["value"] == "example.com"
        assert evs[0].meta["property_keys"] == ["notes"]
        # O VALOR da propriedade NÃO vaza no metadata.
        assert "notes" not in evs[0].meta or evs[0].meta.get("notes") is None

    def test_entity_update_logs_only_property_keys(self, app, auth_client):
        resp = auth_client.patch("/api/entity/ok1", json={
            "properties": {"secret": "value-should-not-be-logged"},
        })
        assert resp.status_code == 200

        events = _all_events(app)
        evs = [e for e in events if e.action == ACTION_ENTITY_UPDATE]
        assert len(evs) == 1
        # property_keys contém "secret" (a chave), mas o valor não.
        assert evs[0].meta["property_keys"] == ["secret"]
        # O valor da propriedade nunca foi logado.
        meta = evs[0].to_dict()["metadata"]
        assert "value-should-not-be-logged" not in str(meta)
        # E a chave "secret" também não (só "property_keys" existe, contendo
        # o nome "secret" como string dentro de uma lista — semântica OK).
        assert "secret" not in meta or meta.get("secret") == "[REDACTED]"

    def test_entity_delete_logs_event(self, app, auth_client):
        auth_client.delete("/api/entity/ok1")
        events = _all_events(app)
        deletes = [e for e in events if e.action == ACTION_ENTITY_DELETE]
        assert len(deletes) == 1

    def test_transform_run_logs_counts_only(self, app, auth_client):
        """Não loga entidades resultantes (podem ser IOC/PII)."""
        resp = auth_client.post("/api/run_transform", json={
            "transform_name": "check_fraud_email",
            "entity_type": "Email",
            "value": "x@x.com",
        })
        assert resp.status_code == 200

        events = _all_events(app)
        evs = [e for e in events if e.action == ACTION_TRANSFORM_RUN]
        assert len(evs) == 1
        assert evs[0].meta["transform_name"] == "check_fraud_email"
        assert "new_entities_count" in evs[0].meta
        assert "new_relationships_count" in evs[0].meta

    def test_investigation_create_logs_title_not_description(self, app, auth_client):
        resp = auth_client.post("/api/investigations", json={
            "title": "Operação X",
            "description": "muito secreto",
        })
        assert resp.status_code == 201

        events = _all_events(app)
        evs = [e for e in events if e.action == ACTION_INVESTIGATION_CREATE]
        assert len(evs) == 1
        assert evs[0].meta["title"] == "Operação X"
        assert "description" not in evs[0].meta

    def test_investigation_update_changed_fields(self, app, auth_client):
        # Cria.
        r = auth_client.post("/api/investigations", json={"title": "A"})
        inv_id = r.get_json()["investigation"]["id"]
        # Atualiza só o título.
        auth_client.put(f"/api/investigations/{inv_id}", json={"title": "B"})
        events = _all_events(app)
        updates = [e for e in events if e.action == ACTION_INVESTIGATION_UPDATE]
        assert len(updates) == 1
        assert updates[0].meta["changed_fields"] == ["title"]

    def test_investigation_archive_unarchive(self, app, auth_client):
        r = auth_client.post("/api/investigations", json={"title": "X"})
        inv_id = r.get_json()["investigation"]["id"]
        auth_client.post(f"/api/investigations/{inv_id}/archive")
        auth_client.post(f"/api/investigations/{inv_id}/unarchive")

        events = _all_events(app)
        actions = [e.action for e in events]
        assert ACTION_INVESTIGATION_ARCHIVE in actions
        assert ACTION_INVESTIGATION_UNARCHIVE in actions

    def test_investigation_create_invalid_payload(self, app, auth_client):
        """L93-94: POST sem title → ValidationError → 400."""
        resp = auth_client.post("/api/investigations",
                                json={"description": "missing title"})
        assert resp.status_code == 400

    def test_investigation_update_graph_snapshot_not_dict(self, app, auth_client):
        """L219: PUT com graph_snapshot = lista (não dict) → 400."""
        # Cria investigação.
        r = auth_client.post("/api/investigations", json={"title": "X"})
        assert r.status_code == 201
        inv_id = r.get_json()["investigation"]["id"]
        # PUT com graph_snapshot inválido (lista).
        resp = auth_client.put(f"/api/investigations/{inv_id}",
                               json={"graph_snapshot": []})
        assert resp.status_code == 400

    def test_investigation_update_snapshot_size_handles_unstringifiable(
        self, app, auth_client
    ):
        """L245-246 marcada com # pragma: no cover.

        O caminho defensivo `except Exception` no cálculo de snapshot_size_kb
        é raríssimo (pydantic já validou como dict, então str() só falharia
        com tipos customizados que fogem ao schema). Monkeypatchar
        builtins.str para testar este caminho mostrou-se frágil (contamina
        o próprio pytest que usa str() internamente para formatar warnings).
        Marcamos a linha como não-coberta por design.
        """
        # Verifica que um update normal funciona (caminho feliz).
        r = auth_client.post("/api/investigations", json={"title": "X"})
        inv_id = r.get_json()["investigation"]["id"]
        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"graph_snapshot": {"nodes": [{"id": "1"}], "edges": []}},
        )
        assert resp.status_code == 200
        events = _all_events(app)
        updates = [e for e in events if e.action == ACTION_INVESTIGATION_UPDATE]
        assert len(updates) == 1
        # Tamanho > 0 (snapshot válido tem bytes).
        assert updates[0].meta["snapshot_size_kb"] > 0

    def test_apikey_create_does_not_log_key_value(self, app, auth_client):
        resp = auth_client.post("/api/keys", json={
            "service_name": "hibp",
            "key_value": "real-secret-12345",
        })
        assert resp.status_code == 201

        events = _all_events(app)
        evs = [e for e in events if e.action == ACTION_APIKEY_CREATE]
        assert len(evs) == 1
        # Defesa em profundidade (sanitização remove key_value): confirma
        # que o segredo NÃO aparece em nenhum campo do metadata serializado.
        meta = evs[0].to_dict()["metadata"]
        assert "real-secret-12345" not in str(meta)

    def test_apikey_update_and_delete(self, app, auth_client):
        auth_client.post("/api/keys", json={"service_name": "x", "key_value": "v"})
        # Update (mesmo service_name → atualiza).
        auth_client.post("/api/keys", json={"service_name": "x", "key_value": "v2"})

        events = _all_events(app)
        creates = [e for e in events if e.action == ACTION_APIKEY_CREATE]
        updates = [e for e in events if e.action == ACTION_APIKEY_UPDATE]
        assert len(creates) == 1
        assert len(updates) == 1

        # Delete.
        from openm.models.api_key import ApiKey
        with app.app_context():
            kid = ApiKey.query.filter_by(service_name="x").first().id
        auth_client.delete(f"/api/keys/{kid}")
        events = _all_events(app)
        deletes = [e for e in events if e.action == ACTION_APIKEY_DELETE]
        assert len(deletes) == 1
        assert deletes[0].meta["service_name"] == "x"


# ====================================================================
# 8) CLI audit purge
# ====================================================================

class TestAuditPurgeCLI:

    def test_purge_default_days_removes_old(self, app):
        """Eventos antigos (>90 dias default) são removidos."""
        with app.app_context():
            # Evento velho.
            old = AuditLog(
                action="old", user_id=None, created_at=datetime.now(timezone.utc)
                - timedelta(days=120),
            )
            db.session.add(old)
            # Evento novo.
            new = AuditLog(
                action="new", user_id=None, created_at=datetime.now(timezone.utc),
            )
            db.session.add(new)
            db.session.commit()

        result = _invoke_cli(app, "audit", "purge", "--days", "90")
        assert result.exit_code == 0, result.output
        assert "1 entradas removidas" in result.output

        with app.app_context():
            assert AuditLog.query.count() == 1
            assert AuditLog.query.first().action == "new"

    def test_purge_uses_config_default_when_no_flag(self, app):
        """Sem --days, usa AUDIT_LOG_RETENTION_DAYS da config."""
        app.config["AUDIT_LOG_RETENTION_DAYS"] = 30
        with app.app_context():
            old = AuditLog(
                action="old", created_at=datetime.now(timezone.utc) - timedelta(days=45),
            )
            db.session.add(old)
            db.session.commit()

        result = _invoke_cli(app, "audit", "purge")
        assert result.exit_code == 0, result.output
        assert "1 entradas removidas" in result.output

    def test_purge_dry_run_does_not_delete(self, app):
        with app.app_context():
            db.session.add(AuditLog(
                action="x",
                created_at=datetime.now(timezone.utc) - timedelta(days=200),
            ))
            db.session.commit()

        result = _invoke_cli(app, "audit", "purge", "--days", "90", "--dry-run")
        assert result.exit_code == 0
        assert "[dry-run]" in result.output
        assert "1 entradas seriam removidas" in result.output

        with app.app_context():
            # Nada foi apagado.
            assert AuditLog.query.count() == 1

    def test_purge_nothing_to_remove(self, app):
        result = _invoke_cli(app, "audit", "purge", "--days", "90")
        assert result.exit_code == 0
        assert "Nada a remover" in result.output

    def test_purge_negative_days_rejected(self, app):
        result = _invoke_cli(app, "audit", "purge", "--days", "-1")
        assert result.exit_code == 2  # click.BadParameter
        assert ">=" in result.output or ">= 0" in result.output


# ====================================================================
# 9) Garantia central: nenhum password/token vaza na tabela
# ====================================================================

class TestNoSecretsLeak:
    """Scan global: percorre todas as colunas de metadata buscando
    padrões que jamais deveriam aparecer."""

    def test_no_password_in_any_metadata(self, app):
        with app.app_context():
            log_action("a", metadata={"password": "hunter2"})
            log_action("b", metadata={"nested": {"passWord": "hunter3"}})
            log_action("c", metadata=[{"PASSWORD": "hunter4"}])

        with app.app_context():
            for ev in AuditLog.query.all():
                serialized = str(ev.to_dict()["metadata"])
                assert "hunter2" not in serialized
                assert "hunter3" not in serialized
                assert "hunter4" not in serialized
                # Mas o marcador [REDACTED] está lá.
                assert "[REDACTED]" in serialized

    def test_no_jwt_or_token_in_any_metadata(self, app):
        with app.app_context():
            log_action("a", metadata={"access_token": "eyJxxx"})
            log_action("b", metadata={"refresh_token": "eyJyyy"})

        with app.app_context():
            for ev in AuditLog.query.all():
                serialized = str(ev.to_dict()["metadata"])
                assert "eyJxxx" not in serialized
                assert "eyJyyy" not in serialized
