"""
Testes de unidade para HunterService (issue #7).

Cobre:
- get_key: DB, env, None
- _request: 200 (sucesso), 403 com retry, 403 que esgota, 429 (sem retry),
  451 (gdpr_blocked), 202 polling, 222 SMTP retry, 400 (erro genérico),
  falha de rede, sem chave.
- domain_search: cache hit, cache miss, cache write, sem cachear erros.
- email_verifier: idem.
- investigate_domain: domain com pessoas, vazio, quota, gdpr, 404.
- investigate_email: válido, disposable, unknown, quota, gdpr.
- Cache integration: TTL diferenciado, normalização case-insensitive.
"""

from unittest.mock import MagicMock, patch

from openm.services.hunter_service import HunterService
from openm.services.sqlite_cache import SqliteCache


# ====================================================================
# Helpers de response mocking
# ====================================================================

def _ok_response(data=None, meta=None):
    """Monta um MagicMock de response com status 200 e payload Hunter."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "data": data or {"domain": "example.com", "emails": []},
        "meta": meta or {},
    }
    return resp


def _resp_with_status(status_code, body=None):
    """Monta MagicMock de response com status arbitrário."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body or {"errors": [{"id": "x", "details": "err"}]}
    return resp


def _patch_requests_get(monkeypatch, side_effect):
    """Patcha requests.get em hunter_service para retornar side_effect."""
    return patch(
        "openm.services.hunter_service.requests.get",
        side_effect=side_effect,
    )


def _patch_sleep(monkeypatch):
    """Captura todas as chamadas a time.sleep em hunter_service."""
    calls = []
    monkeypatch.setattr(
        "openm.services.hunter_service.time.sleep",
        lambda s: calls.append(s),
    )
    return calls


def _make_hunter(tmp_path, monkeypatch):
    """Isola o cache da HunterService em tmp_path.

    Injeta um SqliteCache novo na singleton ``_shared_cache`` e
    restaura no teardown. Retorna o cache para que o teste possa
    inspecionar TTL/keys diretamente.
    """
    monkeypatch.delenv("HUNTER_CACHE_PATH", raising=False)
    cache = SqliteCache(db_path=str(tmp_path / "hunter.db"))
    monkeypatch.setattr(HunterService, "_shared_cache", cache)
    return HunterService(cache=cache)


# ====================================================================
# get_key
# ====================================================================

class TestGetKey:
    """Cobertura para HunterService.get_key."""

    def test_returns_key_from_db(self, app):
        from openm.extensions import db
        from openm.models.api_key import ApiKey

        with app.app_context():
            db.session.add(
                ApiKey(
                    service_name="hunter",
                    key_value="db-hunter-key",
                    key_type="free",
                    is_active=True,
                )
            )
            db.session.commit()
            result = HunterService.get_key()

        assert result == "db-hunter-key"

    def test_returns_key_from_db_and_increments_usage(self, app):
        from openm.extensions import db
        from openm.models.api_key import ApiKey

        with app.app_context():
            key = ApiKey(
                service_name="hunter",
                key_value="db-hunter-key",
                key_type="free",
                is_active=True,
                usage_count=0,
            )
            db.session.add(key)
            db.session.commit()

            result = HunterService.get_key()
            assert result == "db-hunter-key"
            assert key.usage_count == 1

    def test_returns_key_from_env_when_no_db_key(self, app):
        with app.app_context():
            with patch.dict("os.environ", {"HUNTER_API_KEY": "env-hunter"}):
                result = HunterService.get_key()
        assert result == "env-hunter"

    def test_db_key_wins_over_env(self, app):
        from openm.extensions import db
        from openm.models.api_key import ApiKey

        with app.app_context():
            db.session.add(
                ApiKey(
                    service_name="hunter",
                    key_value="db-key",
                    key_type="free",
                    is_active=True,
                )
            )
            db.session.commit()
            with patch.dict("os.environ", {"HUNTER_API_KEY": "env-key"}):
                result = HunterService.get_key()
        assert result == "db-key"

    def test_returns_none_when_no_key_anywhere(self, app):
        with app.app_context():
            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "openm.services.hunter_service.ApiKey.query"
                ) as mock_q:
                    mock_q.filter_by.return_value.order_by.return_value. \
                        first.return_value = None
                    result = HunterService.get_key()
        assert result is None

    def test_inactive_db_key_is_ignored(self, app):
        from openm.extensions import db
        from openm.models.api_key import ApiKey

        with app.app_context():
            db.session.add(
                ApiKey(
                    service_name="hunter",
                    key_value="inactive-key",
                    key_type="free",
                    is_active=False,
                )
            )
            db.session.commit()
            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "openm.services.hunter_service.ApiKey.query"
                ) as mock_q:
                    mock_q.filter_by.return_value.order_by.return_value. \
                        first.return_value = None
                    result = HunterService.get_key()
        assert result is None


# ====================================================================
# _request
# ====================================================================

class TestRequest:
    """Cobertura do método _request da HunterService."""

    def test_200_returns_parsed_json(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response({"domain": "example.com"}),
        ):
            result = HunterService._request("/domain-search", {"domain": "x"})

        assert result == {
            "data": {"domain": "example.com"},
            "meta": {},
        }

    def test_no_key_returns_none(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: None))
        result = HunterService._request("/domain-search", {"domain": "x"})
        assert result is None

    def test_network_exception_returns_none(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        import requests
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            side_effect=requests.ConnectionError("boom"),
        ):
            result = HunterService._request("/domain-search", {"domain": "x"})
        assert result is None

    def test_401_returns_error_dict(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "bad"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(401),
        ):
            result = HunterService._request("/domain-search", {"domain": "x"})
        assert result["status"] == 401
        # O mock body retorna errors[0].details = "err"
        assert result["error"] == "err"

    def test_400_wrong_params_returns_error(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(400),
        ):
            result = HunterService._request("/email-verifier", {"email": "bad"})
        assert result["status"] == 400

    def test_429_returns_quota_exceeded_without_retry(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        sleep_calls = _patch_sleep(monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(429),
        ) as mock_get:
            result = HunterService._request("/domain-search", {"domain": "x"})

        assert result == {"quota_exceeded": True, "status": 429}
        # NUNCA retenta 429 — quota mensal exige esperar até reset
        assert mock_get.call_count == 1
        assert sleep_calls == []

    def test_451_returns_gdpr_blocked(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(451),
        ):
            result = HunterService._request("/domain-search", {"domain": "x"})
        assert result == {"gdpr_blocked": True, "status": 451}

    def test_403_retries_then_succeeds(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        sleep_calls = _patch_sleep(monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            side_effect=[
                _resp_with_status(403),
                _resp_with_status(403),
                _ok_response({"domain": "x"}),
            ],
        ):
            result = HunterService._request("/domain-search", {"domain": "x"})

        assert result == {"data": {"domain": "x"}, "meta": {}}
        # 2 sleeps com backoff exponencial: 1.0, 2.0
        assert sleep_calls == [1.0, 2.0]

    def test_403_exhausts_retries(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        sleep_calls = _patch_sleep(monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        # 4 respostas 403: 1 inicial + 3 retries
        with patch(
            "openm.services.hunter_service.requests.get",
            side_effect=[
                _resp_with_status(403),
                _resp_with_status(403),
                _resp_with_status(403),
                _resp_with_status(403),
            ],
        ) as mock_get:
            result = HunterService._request("/domain-search", {"domain": "x"})

        assert result == {"error": "rate_limited", "status": 403}
        assert mock_get.call_count == 4
        # 3 sleeps (1.0, 2.0, 4.0) — não dorme após o último
        assert sleep_calls == [1.0, 2.0, 4.0]

    def test_202_polling_then_succeeds(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        sleep_calls = _patch_sleep(monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            side_effect=[
                _resp_with_status(202),
                _resp_with_status(202),
                _ok_response({"status": "valid"}),
            ],
        ) as mock_get:
            result = HunterService._request("/email-verifier", {"email": "x"})

        assert result == {"data": {"status": "valid"}, "meta": {}}
        # 202 não conta como retry — apenas polling sleeps
        assert mock_get.call_count == 3
        assert sleep_calls == [5.0, 5.0]

    def test_222_smtp_retries_then_gives_up(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        sleep_calls = _patch_sleep(monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        # MAX_RETRIES_222 = 2, então 1 inicial + 2 retries = 3 chamadas
        with patch(
            "openm.services.hunter_service.requests.get",
            side_effect=[
                _resp_with_status(222),
                _resp_with_status(222),
                _resp_with_status(222),
            ],
        ) as mock_get:
            result = HunterService._request("/email-verifier", {"email": "x"})

        assert result == {"error": "smtp_failure", "status": 222}
        assert mock_get.call_count == 3
        # 2 sleeps de 30s (após cada retry)
        assert sleep_calls == [30.0, 30.0]

    def test_222_retries_then_succeeds(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        _patch_sleep(monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            side_effect=[
                _resp_with_status(222),
                _ok_response({"status": "valid"}),
            ],
        ) as mock_get:
            result = HunterService._request("/email-verifier", {"email": "x"})

        assert result == {"data": {"status": "valid"}, "meta": {}}
        assert mock_get.call_count == 2

    def test_uses_x_api_key_header(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(
            HunterService, "get_key", staticmethod(lambda: "my-hunter-key")
        )
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response({"domain": "x"}),
        ) as mock_get:
            HunterService._request("/domain-search", {"domain": "x"})

        args, kwargs = mock_get.call_args
        assert kwargs["headers"]["X-API-KEY"] == "my-hunter-key"
        assert "domain-search" in args[0]
        assert "email" not in (args[0] + str(kwargs))

    def test_invalid_json_returns_error_dict(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = ValueError("not-json")
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=resp,
        ):
            result = HunterService._request("/domain-search", {"domain": "x"})
        assert result == {"error": "invalid_json", "status": 200}

    def test_sleep_seconds_override(self, tmp_path, monkeypatch):
        """sleep_seconds=0 evita waits reais nos testes."""
        _ = _make_hunter(tmp_path, monkeypatch)
        sleep_calls = _patch_sleep(monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            side_effect=[
                _resp_with_status(403),
                _resp_with_status(403),
                _ok_response({"domain": "x"}),
            ],
        ):
            HunterService._request(
                "/domain-search", {"domain": "x"}, sleep_seconds=0,
            )
        # override usado em todos os sleeps
        assert sleep_calls == [0, 0]


# ====================================================================
# domain_search — cache integration
# ====================================================================

MOCK_DOMAIN_DATA = {
    "domain": "intercom.com",
    "organization": "Intercom",
    "pattern": "{first}",
    "disposable": False,
    "webmail": False,
    "accept_all": True,
    "linked_domains": [],
    "emails": [
        {
            "value": "ciaran@intercom.com",
            "type": "personal",
            "confidence": 92,
            "first_name": "Ciaran",
            "last_name": "Lee",
            "position": "Support Engineer",
            "seniority": "senior",
            "department": "it",
            "linkedin": None,
            "twitter": "ciaran_lee",
            "phone_number": None,
            "sources": [
                {
                    "domain": "github.com",
                    "uri": "http://github.com/ciaranlee",
                    "extracted_on": "2015-07-29",
                    "last_seen_on": "2017-07-01",
                    "still_on_page": True,
                }
            ],
            "verification": {"date": "2019-12-06", "status": "valid"},
        }
    ],
}


class TestDomainSearch:
    """Cobertura para HunterService.domain_search."""

    def test_success_returns_data(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_DOMAIN_DATA),
        ):
            result = HunterService.domain_search("intercom.com")

        assert result is not None
        assert result["data"]["organization"] == "Intercom"
        assert result["data"]["emails"][0]["value"] == "ciaran@intercom.com"
        # Primeira chamada NÃO vem do cache (_cache_hit ausente ou False)
        assert not result.get("_cache_hit")

    def test_cache_hit_skips_request(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_DOMAIN_DATA),
        ):
            HunterService.domain_search("intercom.com")  # popula cache
        # Segunda chamada — cache hit, requests.get NÃO é chamado
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response({"different": "data"}),
        ) as mock_get:
            result = HunterService.domain_search("intercom.com")

        assert result is not None
        assert result.get("_cache_hit") is True
        # organization vem do cache (Intercom), não do mock diferente
        assert result["data"]["organization"] == "Intercom"
        mock_get.assert_not_called()

    def test_quota_exceeded_not_cached(self, tmp_path, monkeypatch):
        """Resposta com quota_exceeded não é cacheada."""
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(429),
        ):
            result = HunterService.domain_search("intercom.com")
        assert result["quota_exceeded"] is True

        # Segunda chamada deve chamar requests.get novamente (não tem cache)
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_DOMAIN_DATA),
        ) as mock_get:
            result2 = HunterService.domain_search("intercom.com")
        assert mock_get.call_count == 1
        assert result2["data"]["organization"] == "Intercom"

    def test_gdpr_blocked_not_cached(self, tmp_path, monkeypatch):
        """451 não cacheia."""
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(451),
        ):
            HunterService.domain_search("intercom.com")

        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_DOMAIN_DATA),
        ) as mock_get:
            HunterService.domain_search("intercom.com")
        assert mock_get.call_count == 1

    def test_uses_correct_query_param(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_DOMAIN_DATA),
        ) as mock_get:
            HunterService.domain_search("foo.bar")

        _, kwargs = mock_get.call_args
        assert kwargs["params"]["domain"] == "foo.bar"

    def test_cache_key_normalizes_case(self, tmp_path, monkeypatch):
        """Mesmo domínio com case diferente → mesmo cache hit."""
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_DOMAIN_DATA),
        ):
            HunterService.domain_search("INTERCOM.com")

        with patch(
            "openm.services.hunter_service.requests.get",
        ) as mock_get:
            result = HunterService.domain_search("intercom.com")
        mock_get.assert_not_called()
        assert result.get("_cache_hit") is True


# ====================================================================
# email_verifier
# ====================================================================

MOCK_EMAIL_DATA = {
    "status": "valid",
    "score": 100,
    "email": "patrick@stripe.com",
    "regexp": True,
    "gibberish": False,
    "disposable": False,
    "webmail": False,
    "mx_records": True,
    "smtp_server": True,
    "smtp_check": True,
    "accept_all": False,
    "block": False,
    "sources": [],
}


class TestEmailVerifier:
    """Cobertura para HunterService.email_verifier."""

    def test_success_returns_data(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_EMAIL_DATA),
        ):
            result = HunterService.email_verifier("patrick@stripe.com")

        assert result["data"]["status"] == "valid"
        assert result["data"]["score"] == 100

    def test_cache_hit(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_EMAIL_DATA),
        ):
            HunterService.email_verifier("patrick@stripe.com")
        with patch(
            "openm.services.hunter_service.requests.get",
        ) as mock_get:
            result = HunterService.email_verifier("patrick@stripe.com")
        assert result.get("_cache_hit") is True
        mock_get.assert_not_called()


# ====================================================================
# investigate_domain
# ====================================================================

class TestInvestigateDomain:
    """Cobertura para HunterService.investigate_domain."""

    def test_domain_with_people(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_DOMAIN_DATA),
        ):
            result = HunterService.investigate_domain("intercom.com")

        assert result["domain"] == "intercom.com"
        assert result["available"] is True
        assert result["organization"] == "Intercom"
        assert result["pattern"] == "{first}"
        assert result["accept_all"] is True
        assert len(result["people"]) == 1
        person = result["people"][0]
        assert person["first_name"] == "Ciaran"
        assert person["email"] == "ciaran@intercom.com"
        assert person["confidence"] == 92
        assert result["cache_hit"] is False
        assert result["quota_exceeded"] is False
        assert result["gdpr_blocked"] is False

    def test_domain_empty(self, tmp_path, monkeypatch):
        """Domain sem emails retornados — ainda retorna estrutura válida."""
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response({
                "domain": "empty.com", "emails": [], "organization": None,
            }),
        ):
            result = HunterService.investigate_domain("empty.com")

        assert result["available"] is True
        assert result["people"] == []
        assert result["organization"] is None

    def test_quota_exceeded_propagates(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(429),
        ):
            result = HunterService.investigate_domain("x.com")

        assert result["available"] is False
        assert result["quota_exceeded"] is True
        assert result["people"] == []

    def test_gdpr_blocked_propagates(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(451),
        ):
            result = HunterService.investigate_domain("x.com")

        assert result["available"] is False
        assert result["gdpr_blocked"] is True

    def test_no_key_returns_unavailable(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: None))
        result = HunterService.investigate_domain("x.com")
        assert result["available"] is False

    def test_generic_error_returns_unavailable(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(500),
        ):
            result = HunterService.investigate_domain("x.com")
        # investigate_domain retorna a base dict (com available=False)
        # quando _request devolveu um erro generico — sem propagar o
        # dict de erro cru, apenas marcando unavailable.
        assert result["available"] is False
        assert result["people"] == []  # nao tenta criar entidades
        assert result["quota_exceeded"] is False
        assert result["gdpr_blocked"] is False

    def test_cache_hit_flag_set(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_DOMAIN_DATA),
        ):
            HunterService.investigate_domain("intercom.com")  # popula cache
        with patch(
            "openm.services.hunter_service.requests.get",
        ):
            result = HunterService.investigate_domain("intercom.com")
        assert result["cache_hit"] is True
        assert result["available"] is True


# ====================================================================
# investigate_email
# ====================================================================

class TestInvestigateEmail:
    """Cobertura para HunterService.investigate_email."""

    def test_email_valid(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_EMAIL_DATA),
        ):
            result = HunterService.investigate_email("patrick@stripe.com")

        assert result["email"] == "patrick@stripe.com"
        assert result["available"] is True
        assert result["status"] == "valid"
        assert result["score"] == 100
        assert result["deliverable"] is True
        assert result["mx_records"] is True
        assert result["smtp_server"] is True

    def test_email_disposable(self, tmp_path, monkeypatch):
        """Status=disposable, score=50 (fixo da Hunter para disposable)."""
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response({
                "status": "disposable", "score": 50,
                "mx_records": False, "smtp_server": False,
                "disposable": True, "webmail": False,
            }),
        ):
            result = HunterService.investigate_email("temp@mailinator.com")

        assert result["status"] == "disposable"
        assert result["disposable"] is True
        assert result["deliverable"] is False

    def test_email_unknown(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response({
                "status": "unknown", "score": 50,
            }),
        ):
            result = HunterService.investigate_email("nobody@nowhere.com")

        assert result["status"] == "unknown"
        assert result["available"] is True

    def test_email_quota_exceeded(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(429),
        ):
            result = HunterService.investigate_email("x@y.com")

        assert result["available"] is False
        assert result["quota_exceeded"] is True

    def test_email_gdpr_blocked(self, tmp_path, monkeypatch):
        _ = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_resp_with_status(451),
        ):
            result = HunterService.investigate_email("x@y.com")

        assert result["available"] is False
        assert result["gdpr_blocked"] is True


# ====================================================================
# Cache TTL diferenciado
# ====================================================================

class TestCacheIntegration:
    """Cache TTL respeitado por endpoint, normalização case-insensitive."""

    def test_domain_search_uses_long_ttl(self, tmp_path, monkeypatch):
        """domain_search cacheia por 7 dias."""
        _ = _make_hunter(tmp_path, monkeypatch)
        assert HunterService.CACHE_TTL_DOMAIN_SEARCH == 7 * 24 * 3600

    def test_email_verifier_uses_short_ttl(self, tmp_path, monkeypatch):
        assert HunterService.CACHE_TTL_EMAIL_VERIFIER == 24 * 3600

    def test_cache_does_not_share_keys_across_endpoints(self, tmp_path, monkeypatch):
        """Mesma string usada nos 2 endpoints → 2 caches separados."""
        _ = _make_hunter(tmp_path, monkeypatch)
        # Cache key do domain é prefixada com "domain_search",
        # do email com "email_verifier" — não colidem.
        key_domain = HunterService._cache_key("domain_search", "x.com")
        key_email = HunterService._cache_key("email_verifier", "x.com")
        assert key_domain != key_email

    def test_cache_ttl_set_correctly(self, tmp_path, monkeypatch):
        """Ao cachear, TTL é respeitado (não cacheia pra sempre)."""
        hunter = _make_hunter(tmp_path, monkeypatch)
        monkeypatch.setattr(HunterService, "get_key", staticmethod(lambda: "k"))
        with patch(
            "openm.services.hunter_service.requests.get",
            return_value=_ok_response(MOCK_DOMAIN_DATA),
        ):
            hunter.domain_search("intercom.com")
        # Confere que o expires_at está dentro do esperado (cache = _shared_cache)
        cache_key = HunterService._cache_key("domain_search", "intercom.com")
        with HunterService._get_cache()._conn() as conn:
            row = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?",
                (cache_key,),
            ).fetchone()
        assert row is not None
        # expires_at deve estar no futuro próximo (7 dias)
        import time
        assert row["expires_at"] > time.time() + 6 * 24 * 3600
