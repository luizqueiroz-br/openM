"""
Testes de unidade para VirusTotalService (issue #6).

Cobre todos os métodos e caminhos de erro:
- get_key: banco, env, None
- query_domain / query_ip: 200 (sucesso), 404 (sem dados), 401 (chave
  inválida), 429 com retry que eventualmente funciona, 429 que esgota,
  exceção de rede.
- investigate_entity: domain com malicious>0, domain limpo, IP flagged,
  404, stats vazios, tipo não suportado.
- _request_with_retry: verifica que time.sleep é chamado com 60/120/240s
  conforme retries (com sleep configurável para evitar waits reais).
"""

from unittest.mock import MagicMock, patch

import requests

from openm.services.virustotal_service import VirusTotalService


# ====================================================================
# get_key
# ====================================================================

class TestGetKey:
    """Cobertura para VirusTotalService.get_key."""

    def test_returns_key_from_db(self, app):
        from openm.extensions import db
        from openm.models.api_key import ApiKey

        with app.app_context():
            db.session.add(
                ApiKey(
                    service_name="virustotal",
                    key_value="db-secret-key",
                    key_type="free",
                    is_active=True,
                )
            )
            db.session.commit()

            result = VirusTotalService.get_key()

        assert result == "db-secret-key"

    def test_returns_key_from_db_and_increments_usage(self, app):
        from openm.extensions import db
        from openm.models.api_key import ApiKey

        with app.app_context():
            key = ApiKey(
                service_name="virustotal",
                key_value="db-secret-key",
                key_type="free",
                is_active=True,
                usage_count=0,
            )
            db.session.add(key)
            db.session.commit()

            result = VirusTotalService.get_key()
            assert result == "db-secret-key"
            assert key.usage_count == 1

    def test_returns_key_from_env_when_no_db_key(self, app):
        with app.app_context():
            with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "env-secret"}):
                result = VirusTotalService.get_key()
        assert result == "env-secret"

    def test_returns_none_when_no_key_anywhere(self, app):
        with app.app_context():
            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "openm.services.virustotal_service.ApiKey.query"
                ) as mock_q:
                    mock_q.filter_by.return_value.order_by.return_value. \
                        first.return_value = None
                    result = VirusTotalService.get_key()
        assert result is None


# ====================================================================
# query_domain
# ====================================================================

MOCK_DOMAIN_ATTRS = {
    "last_analysis_stats": {
        "harmless": 83,
        "malicious": 4,
        "suspicious": 1,
        "timeout": 0,
        "undetected": 9,
    },
    "reputation": -41,
    "last_analysis_results": {
        "Kaspersky": {
            "category": "malicious",
            "engine_name": "Kaspersky",
            "result": "malware site",
        },
        "Google": {
            "category": "harmless",
            "engine_name": "Google",
            "result": "clean",
        },
        "PhishTank": {
            "category": "suspicious",
            "engine_name": "PhishTank",
            "result": "phishing",
        },
    },
}


def _ok_response(payload=None):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "data": {
            "id": "x",
            "type": "domain",
            "attributes": payload or MOCK_DOMAIN_ATTRS,
        }
    }
    return resp


def _resp_with_status(status_code):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"error": "mock"}
    return resp


class TestQueryDomain:
    """Cobertura para VirusTotalService.query_domain."""

    def test_success_returns_attributes(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_ok_response(),
                ):
                    result = VirusTotalService.query_domain("example.com")

        assert result is not None
        assert result["reputation"] == -41
        assert result["last_analysis_stats"]["malicious"] == 4
        assert result["last_analysis_results"]["Kaspersky"]["category"] == "malicious"

    def test_no_key_returns_none(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value=None):
                result = VirusTotalService.query_domain("example.com")
        assert result is None

    def test_404_returns_none(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_resp_with_status(404),
                ):
                    result = VirusTotalService.query_domain("notfound.example")
        assert result is None

    def test_401_returns_none(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="bad"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_resp_with_status(401),
                ):
                    result = VirusTotalService.query_domain("example.com")
        assert result is None

    def test_403_returns_none(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="bad"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_resp_with_status(403),
                ):
                    result = VirusTotalService.query_domain("example.com")
        assert result is None

    def test_500_returns_none(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_resp_with_status(500),
                ):
                    result = VirusTotalService.query_domain("example.com")
        assert result is None

    def test_request_exception_returns_none(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    side_effect=requests.exceptions.ConnectionError("net"),
                ):
                    result = VirusTotalService.query_domain("example.com")
        assert result is None

    def test_invalid_json_returns_none(self, app):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = ValueError("bad json")
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=resp,
                ):
                    result = VirusTotalService.query_domain("example.com")
        assert result is None

    def test_missing_attributes_returns_none(self, app):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": {}}  # sem attributes
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=resp,
                ):
                    result = VirusTotalService.query_domain("example.com")
        assert result is None

    def test_429_eventually_succeeds(self, app):
        """429 nas 2 primeiras tentativas, 200 na 3a."""
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    side_effect=[
                        _resp_with_status(429),
                        _resp_with_status(429),
                        _ok_response(),
                    ],
                ):
                    result = VirusTotalService.query_domain(
                        "example.com", sleep_seconds=0,
                    )
        assert result is not None
        assert result["reputation"] == -41

    def test_429_exhausts_retries(self, app):
        """429 em todas as tentativas → None."""
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_resp_with_status(429),
                ):
                    result = VirusTotalService.query_domain(
                        "example.com", sleep_seconds=0,
                    )
        assert result is None

    def test_uses_x_apikey_header(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="my-key"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_ok_response(),
                ) as mock_get:
                    VirusTotalService.query_domain(
                        "example.com", sleep_seconds=0,
                    )
        args, kwargs = mock_get.call_args
        assert kwargs["headers"]["x-apikey"] == "my-key"
        assert "domains/example.com" in args[0]


# ====================================================================
# query_ip (estrutura análoga)
# ====================================================================

MOCK_IP_ATTRS = {
    "last_analysis_stats": {
        "harmless": 70, "malicious": 2, "suspicious": 0,
        "timeout": 0, "undetected": 15,
    },
    "reputation": -22,
    "last_analysis_results": {
        "Kaspersky": {"category": "malicious", "engine_name": "Kaspersky",
                      "result": "C2 server"},
    },
}


def _ok_ip_response(payload=None):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "data": {
            "id": "1.1.1.1",
            "type": "ip_address",
            "attributes": payload or MOCK_IP_ATTRS,
        }
    }
    return resp


class TestQueryIp:
    """Cobertura para VirusTotalService.query_ip."""

    def test_success_returns_attributes(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_ok_ip_response(),
                ):
                    result = VirusTotalService.query_ip("1.1.1.1")

        assert result is not None
        assert result["reputation"] == -22
        assert result["last_analysis_stats"]["malicious"] == 2

    def test_404_returns_none(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_resp_with_status(404),
                ):
                    result = VirusTotalService.query_ip("9.9.9.9")
        assert result is None

    def test_429_eventually_succeeds(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    side_effect=[
                        _resp_with_status(429),
                        _ok_ip_response(),
                    ],
                ):
                    result = VirusTotalService.query_ip(
                        "1.1.1.1", sleep_seconds=0,
                    )
        assert result is not None
        assert result["reputation"] == -22

    def test_429_exhausts_retries(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_resp_with_status(429),
                ):
                    result = VirusTotalService.query_ip(
                        "1.1.1.1", sleep_seconds=0,
                    )
        assert result is None

    def test_uses_ip_endpoint(self, app):
        with app.app_context():
            with patch.object(VirusTotalService, "get_key", return_value="k"):
                with patch(
                    "openm.services.virustotal_service.requests.get",
                    return_value=_ok_ip_response(),
                ) as mock_get:
                    VirusTotalService.query_ip("1.2.3.4", sleep_seconds=0)
        args, _ = mock_get.call_args
        assert "ip_addresses/1.2.3.4" in args[0]


# ====================================================================
# investigate_entity
# ====================================================================

class TestInvestigateEntity:
    """Cobertura para VirusTotalService.investigate_entity."""

    def test_domain_with_malicious(self, app):
        with app.app_context():
            with patch.object(
                VirusTotalService, "query_domain",
                return_value=MOCK_DOMAIN_ATTRS,
            ):
                result = VirusTotalService.investigate_entity(
                    "Domain", "example.com"
                )

        assert result["available"] is True
        assert result["value"] == "example.com"
        assert result["type"] == "Domain"
        assert result["reputation"] == -41
        assert result["last_analysis_stats"]["malicious"] == 4
        # Apenas engines com categoria malicious ou suspicious
        engines = {f["engine"] for f in result["flagged_by"]}
        assert "Kaspersky" in engines
        assert "PhishTank" in engines
        assert "Google" not in engines  # harmless — não flagga
        assert all(
            f["category"] in ("malicious", "suspicious")
            for f in result["flagged_by"]
        )

    def test_ip_with_flagged(self, app):
        with app.app_context():
            with patch.object(
                VirusTotalService, "query_ip", return_value=MOCK_IP_ATTRS,
            ):
                result = VirusTotalService.investigate_entity(
                    "IPAddress", "1.1.1.1"
                )

        assert result["available"] is True
        assert result["type"] == "IPAddress"
        assert result["last_analysis_stats"]["malicious"] == 2
        assert any(
            f["engine"] == "Kaspersky" and f["category"] == "malicious"
            for f in result["flagged_by"]
        )

    def test_clean_entity(self, app):
        clean_attrs = {
            "last_analysis_stats": {
                "harmless": 90, "malicious": 0, "suspicious": 0,
                "timeout": 0, "undetected": 5,
            },
            "reputation": 0,
            "last_analysis_results": {
                "Google": {"category": "harmless", "engine_name": "Google",
                           "result": "clean"},
            },
        }
        with app.app_context():
            with patch.object(
                VirusTotalService, "query_domain", return_value=clean_attrs,
            ):
                result = VirusTotalService.investigate_entity(
                    "Domain", "clean.com"
                )

        assert result["available"] is True
        assert result["last_analysis_stats"]["malicious"] == 0
        assert result["flagged_by"] == []

    def test_no_data_404(self, app):
        with app.app_context():
            with patch.object(
                VirusTotalService, "query_domain", return_value=None,
            ):
                result = VirusTotalService.investigate_entity(
                    "Domain", "missing.com"
                )

        assert result["available"] is False
        assert result["last_analysis_stats"] is None
        assert result["flagged_by"] == []
        assert result["reputation"] is None

    def test_empty_stats(self, app):
        attrs_no_stats = {
            "last_analysis_results": {},
        }
        with app.app_context():
            with patch.object(
                VirusTotalService, "query_domain", return_value=attrs_no_stats,
            ):
                result = VirusTotalService.investigate_entity(
                    "Domain", "weird.com"
                )

        assert result["available"] is True
        assert result["last_analysis_stats"] is None
        assert result["flagged_by"] == []

    def test_unsupported_type(self, app):
        result = VirusTotalService.investigate_entity("Email", "x@y.com")

        assert result["available"] is False
        assert result["type"] == "Email"
        assert result["last_analysis_stats"] is None

    def test_checked_at_is_iso8601(self, app):
        result = VirusTotalService.investigate_entity("Domain", "x.com")
        # ISO 8601: contém 'T' e termina com 'Z' ou tem offset numérico
        assert "T" in result["checked_at"]

    def test_stats_partial_missing(self, app):
        """Stats com apenas malicious presente — outros campos default 0."""
        attrs = {
            "last_analysis_stats": {"malicious": 3},
            "reputation": -10,
        }
        with app.app_context():
            with patch.object(
                VirusTotalService, "query_domain", return_value=attrs,
            ):
                result = VirusTotalService.investigate_entity(
                    "Domain", "x.com"
                )
        assert result["last_analysis_stats"]["malicious"] == 3
        assert result["last_analysis_stats"]["harmless"] == 0
        assert result["last_analysis_stats"]["suspicious"] == 0

    def test_flagged_results_handle_garbled(self, app):
        """Engines com info não-dict são puladas; result ausente → string vazia."""
        attrs = {
            "last_analysis_results": {
                "BrokenEngine": "not-a-dict",
                "Good": {"category": "malicious", "engine_name": "Good",
                         "result": "trojan"},
                "NoResult": {"category": "suspicious", "engine_name": "NoResult"},
            }
        }
        with app.app_context():
            with patch.object(
                VirusTotalService, "query_domain", return_value=attrs,
            ):
                result = VirusTotalService.investigate_entity(
                    "Domain", "x.com"
                )
        engines = {f["engine"]: f for f in result["flagged_by"]}
        assert "BrokenEngine" not in engines
        assert engines["Good"]["result"] == "trojan"
        assert engines["NoResult"]["result"] == ""


# ====================================================================
# Retry / Backoff
# ====================================================================

class TestRetryBackoff:
    """Validação do schedule de backoff."""

    def test_sleep_called_with_backoff_schedule(self, monkeypatch):
        """Em 429, time.sleep é chamado com 60s/120s/240s entre tentativas."""
        sleep_calls = []
        monkeypatch.setattr(
            "openm.services.virustotal_service.time.sleep",
            lambda s: sleep_calls.append(s),
        )

        with patch.object(VirusTotalService, "get_key", return_value="k"):
            with patch(
                "openm.services.virustotal_service.requests.get",
                return_value=_resp_with_status(429),
            ):
                VirusTotalService._request_with_retry(
                    "https://example.com", {"x-apikey": "k"}, timeout=1,
                )

        # 1a req não dorme; após 1o 429 → 60s; após 2o → 120s; após 3o → 240s;
        # após 4o (esgota) → sem sleep.
        assert sleep_calls == [60, 120, 240]

    def test_sleep_schedule_matches_spec(self):
        """Garante que BACKOFF_SCHEDULE é exatamente (60, 120, 240)."""
        assert VirusTotalService.BACKOFF_SCHEDULE == (60, 120, 240)

    def test_sleep_seconds_override(self, monkeypatch):
        """Parâmetro sleep_seconds sobrescreve backoff real."""
        sleep_calls = []
        monkeypatch.setattr(
            "openm.services.virustotal_service.time.sleep",
            lambda s: sleep_calls.append(s),
        )

        with patch.object(VirusTotalService, "get_key", return_value="k"):
            with patch(
                "openm.services.virustotal_service.requests.get",
                side_effect=[
                    _resp_with_status(429),
                    _resp_with_status(429),
                    _resp_with_status(429),
                    _ok_response(),
                ],
            ):
                result = VirusTotalService.query_domain(
                    "example.com", sleep_seconds=2,
                )

        assert result is not None
        assert sleep_calls == [2, 2, 2]

    def test_429_stops_after_max_retries(self, monkeypatch):
        """Após BACKOFF_SCHEDULE esgotar (3 tentativas), retorna None."""
        sleep_calls = []
        monkeypatch.setattr(
            "openm.services.virustotal_service.time.sleep",
            lambda s: sleep_calls.append(s),
        )

        call_count = {"n": 0}

        def always_429(*a, **kw):
            call_count["n"] += 1
            return _resp_with_status(429)

        with patch.object(VirusTotalService, "get_key", return_value="k"):
            with patch(
                "openm.services.virustotal_service.requests.get",
                side_effect=always_429,
            ):
                result = VirusTotalService.query_domain(
                    "example.com", sleep_seconds=0,
                )

        # 1 inicial + 3 retries = 4 chamadas no total
        assert call_count["n"] == 4
        assert result is None
        # 3 sleeps (um por retry) — não há sleep após o último
        assert len(sleep_calls) == 3

    def test_200_short_circuits_no_sleep(self, monkeypatch):
        """Em 200 imediato, não há time.sleep."""
        sleep_calls = []
        monkeypatch.setattr(
            "openm.services.virustotal_service.time.sleep",
            lambda s: sleep_calls.append(s),
        )

        with patch.object(VirusTotalService, "get_key", return_value="k"):
            with patch(
                "openm.services.virustotal_service.requests.get",
                return_value=_ok_response(),
            ):
                result = VirusTotalService.query_domain(
                    "example.com", sleep_seconds=0,
                )
        assert result is not None
        assert sleep_calls == []

    def test_404_no_sleep(self, monkeypatch):
        """Em 404, sem retry, sem sleep."""
        sleep_calls = []
        monkeypatch.setattr(
            "openm.services.virustotal_service.time.sleep",
            lambda s: sleep_calls.append(s),
        )

        with patch.object(VirusTotalService, "get_key", return_value="k"):
            with patch(
                "openm.services.virustotal_service.requests.get",
                return_value=_resp_with_status(404),
            ):
                result = VirusTotalService.query_domain(
                    "example.com", sleep_seconds=0,
                )
        assert result is None
        assert sleep_calls == []
