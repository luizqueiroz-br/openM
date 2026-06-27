"""
Testes do helper centralizado de HTTP com timeout/retry (issue #77).

Cobre:
- Sucesso em primeira tentativa.
- Retry automatico em 5xx e 429.
- Retry em ConnectionError/Timeout.
- Respeito ao header Retry-After.
- Desistencia apos max_retries.
- Status nao retentavel (4xx != 429) retorna imediato.
- Incremento do contador de chamadas externas.
- POST funciona com json payload.
"""

import time

import requests

from openm.core import http_client
from openm.core.transform import (
    get_api_call_count,
    reset_api_call_counter,
)


# ========================================================================
# Helpers
# ========================================================================


class FakeResponse:
    """Mock minimalista de requests.Response."""

    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {}

    def json(self):
        if isinstance(self._json_data, Exception):
            raise self._json_data
        return self._json_data


# ========================================================================
# Retry-After parsing
# ========================================================================


def test_parse_retry_after_numeric():
    """Numero em segundos -> float."""
    assert http_client._parse_retry_after("5") == 5.0
    assert http_client._parse_retry_after("0") == 0.0
    # Acima do cap (60s) e limitado.
    assert http_client._parse_retry_after("120.5") == 60.0


def test_parse_retry_after_invalid_returns_none():
    """Valor invalido -> None (fallback para backoff schedule)."""
    assert http_client._parse_retry_after(None) is None
    assert http_client._parse_retry_after("") is None
    assert http_client._parse_retry_after("not-a-number") is None


def test_parse_retry_after_caps_at_max():
    """Valores enormes sao limitados ao cap."""
    assert http_client._parse_retry_after("999999") == http_client.MAX_BACKOFF_CAP_SECONDS


def test_parse_retry_after_negative_returns_none():
    """Valores negativos sao descartados."""
    assert http_client._parse_retry_after("-1") is None


# ========================================================================
# http_get
# ========================================================================


def test_http_get_success_first_try(monkeypatch):
    """Resposta 200 -> retorna Response, sem retry."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(200, {"ok": True})

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    reset_api_call_counter()
    resp = http_client.http_get("https://example.com", timeout=5.0)
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert len(calls) == 1
    assert get_api_call_count() == 1


def test_http_get_retry_on_5xx(monkeypatch):
    """5xx retentavel -> ate 3 tentativas ate sucesso."""
    responses = [
        FakeResponse(503),
        FakeResponse(502),
        FakeResponse(200, {"ok": True}),
    ]

    def fake_get(url, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_get(
        "https://example.com",
        timeout=5.0,
        backoff_schedule=(0.1, 0.2, 0.4),
    )
    assert resp.status_code == 200


def test_http_get_retry_on_429(monkeypatch):
    """429 -> retentavel."""
    responses = [
        FakeResponse(429),
        FakeResponse(429),
        FakeResponse(200, {"ok": True}),
    ]

    def fake_get(url, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_get("https://example.com")
    assert resp.status_code == 200


def test_http_get_retry_on_connection_error(monkeypatch):
    """ConnectionError -> retentavel ate sucesso."""
    responses = [
        requests.ConnectionError("boom"),
        FakeResponse(200, {"ok": True}),
    ]

    def fake_get(url, **kwargs):
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_get("https://example.com")
    assert resp.status_code == 200


def test_http_get_retry_on_timeout(monkeypatch):
    """Timeout -> retentavel."""
    responses = [
        requests.Timeout("slow"),
        FakeResponse(200, {"ok": True}),
    ]

    def fake_get(url, **kwargs):
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_get("https://example.com")
    assert resp.status_code == 200


def test_http_get_exhausts_retries(monkeypatch):
    """Apos max_retries, retorna a ultima response (mesmo retentavel)."""
    def fake_get(url, **kwargs):
        return FakeResponse(503)

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_get(
        "https://example.com",
        backoff_schedule=(0.1, 0.1, 0.1),
    )
    # 1 inicial + 3 retries = 4 tentativas. Retorna o ultimo 503.
    assert resp.status_code == 503


def test_http_get_returns_none_when_all_network_fails(monkeypatch):
    """ConnectionError persistente -> None."""
    def fake_get(url, **kwargs):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_get(
        "https://example.com",
        backoff_schedule=(0.1, 0.1, 0.1),
    )
    assert resp is None


def test_http_get_non_retriable_4xx_returns_immediately(monkeypatch):
    """400/401/403/404 -> retorno imediato, sem retry."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append(1)
        return FakeResponse(404)

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_get("https://example.com")
    assert resp.status_code == 404
    assert len(calls) == 1


def test_http_get_respects_retry_after_header(monkeypatch):
    """Retry-After header sobrescreve backoff schedule."""
    sleep_calls = []

    def fake_sleep(seconds):
        sleep_calls.append(seconds)

    responses = [
        FakeResponse(429, headers={"Retry-After": "7"}),
        FakeResponse(200, {"ok": True}),
    ]

    def fake_get(url, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", fake_sleep)

    resp = http_client.http_get(
        "https://example.com",
        backoff_schedule=(99, 99),  # alto para garantir override
    )
    assert resp.status_code == 200
    assert sleep_calls == [7.0]


def test_http_get_increments_api_call_counter(monkeypatch):
    """Cada tentativa (sucesso ou falha) incrementa o contador."""
    def fake_get(url, **kwargs):
        return FakeResponse(200)

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    reset_api_call_counter()
    http_client.http_get("https://example.com")
    assert get_api_call_count() == 1


def test_http_get_backoff_schedule_limits_retries(monkeypatch):
    """Tamanho da backoff_schedule limita retries (sem mais que len(schedule))."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append(1)
        return FakeResponse(503)

    monkeypatch.setattr(http_client.requests, "get", fake_get)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    http_client.http_get("https://example.com", backoff_schedule=(0.1,))
    # 1 inicial + 1 retry = 2 tentativas.
    assert len(calls) == 2


# ========================================================================
# http_post
# ========================================================================


def test_http_post_success(monkeypatch):
    """POST com sucesso em primeira tentativa."""
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        return FakeResponse(200, {"uuid": "abc"})

    monkeypatch.setattr(http_client.requests, "post", fake_post)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_post(
        "https://example.com/submit",
        json={"key": "value"},
    )
    assert resp.status_code == 200
    assert captured["url"] == "https://example.com/submit"
    assert captured["json"] == {"key": "value"}


def test_http_post_no_retry_by_default(monkeypatch):
    """POST default nao re-tenta 5xx (max_retries=1 = 2 tentativas total)."""
    calls = []

    def fake_post(url, **kwargs):
        calls.append(1)
        return FakeResponse(503)

    monkeypatch.setattr(http_client.requests, "post", fake_post)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_post("https://example.com")
    assert resp.status_code == 503
    assert len(calls) == 2  # 1 inicial + 1 retry padrao


def test_http_post_retry_when_configured(monkeypatch):
    """POST com max_retries customizado."""
    calls = []

    def fake_post(url, **kwargs):
        calls.append(1)
        if len(calls) < 3:
            return FakeResponse(502)
        return FakeResponse(200, {"ok": True})

    monkeypatch.setattr(http_client.requests, "post", fake_post)
    monkeypatch.setattr(http_client.time, "sleep", lambda *_: None)

    resp = http_client.http_post(
        "https://example.com",
        max_retries=3,
        backoff_schedule=(0.1, 0.2, 0.4),
    )
    assert resp.status_code == 200
    assert len(calls) == 3


# ========================================================================
# Smoke tests dos services refatorados
# ========================================================================


def test_abuseipdb_uses_http_client(monkeypatch):
    """Smoke: AbuseIPDB.query_ip delega ao http_client."""
    from openm.services.abuseipdb_service import AbuseIPDBService

    class FakeResp:
        status_code = 200

        def json(self):
            return {"data": {"attributes": {"abuseConfidenceScore": 50}}}

    captured = {}

    def fake_http_get(url, **kwargs):
        captured["url"] = url
        captured["headers"] = kwargs.get("headers")
        return FakeResp()

    monkeypatch.setattr(http_client, "http_get", fake_http_get)
    monkeypatch.setattr(AbuseIPDBService, "get_key", staticmethod(lambda: "test-key"))

    result = AbuseIPDBService.query_ip("8.8.8.8")
    assert result == {"abuseConfidenceScore": 50}
    assert captured["url"].endswith("/check")
    assert captured["headers"]["Key"] == "test-key"


def test_hibp_uses_http_client(monkeypatch):
    """Smoke: HIBP._request delega ao http_client."""
    from openm.services.hibp_service import HibpService

    class FakeResp:
        status_code = 200

        def json(self):
            return []

    monkeypatch.setattr(http_client, "http_get", lambda *a, **kw: FakeResp())
    monkeypatch.setattr(HibpService, "get_key", staticmethod(lambda: "test-key"))

    result = HibpService.query_email_breaches("test@example.com")
    assert result == []


def test_urlscan_submit_uses_http_client(monkeypatch):
    """Smoke: URLScan.submit_scan delega ao http_client."""
    from openm.services.urlscan_service import UrlscanService

    class FakeResp:
        status_code = 200

        def json(self):
            return {"uuid": "abc", "result": "https://urlscan.io/result/abc/"}

    monkeypatch.setattr(http_client, "http_post", lambda *a, **kw: FakeResp())
    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: "test-key"))

    result = UrlscanService.submit_scan("example.com", poll=False)
    assert result["available"] is False
    assert result["uuid"] == "abc"


def test_urlscan_poll_uses_http_client(monkeypatch):
    """Smoke: URLScan polling delega ao http_client."""
    from openm.services.urlscan_service import UrlscanService

    class SubmitResp:
        status_code = 200

        def json(self):
            return {"uuid": "abc", "result": "x"}

    class ResultResp:
        status_code = 200

        def json(self):
            return {
                "uuid": "abc",
                "page": {"domain": "example.com", "url": "https://example.com/", "status": "200"},
                "task": {"url": "https://example.com/"},
                "stats": [],
                "verdicts": {"overall": {"malicious": False, "score": 0}},
                "lists": {"ips": [], "domains": [], "urls": [], "countries": []},
                "meta": {"processors": {"wappa": {"data": []}}},
            }

    responses = [SubmitResp(), ResultResp()]

    def fake_http(method, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(http_client, "http_post", fake_http)
    monkeypatch.setattr(http_client, "http_get", fake_http)
    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: "test-key"))
    monkeypatch.setattr(time, "sleep", lambda *_: None)

    result = UrlscanService.submit_scan(
        "example.com",
        poll_interval=0.0,
        poll_max_wait=5.0,
    )
    assert result["available"] is True
    assert result["page_domain"] == "example.com"
