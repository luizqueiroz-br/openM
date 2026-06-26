"""
Testes de unidade para ShodanService (issue #48).

Cobre todos os métodos e caminhos de fallback:
- get_key: banco, env, None
- resolve_domain: API sucesso, sem key, API falha, domínio inválido
- query_host: sucesso, sem key, timeout, HTTP error
- investigate_host: dados reais, simulado, campos opcionais
"""

import requests
from unittest.mock import MagicMock, patch

from openm.services.shodan_service import ShodanService


# ====================================================================
# get_key
# ====================================================================

class TestGetKey:
    """Cobertura para ShodanService.get_key."""

    def test_returns_key_from_db(self, app):
        from openm.extensions import db
        from openm.models.api_key import ApiKey

        with app.app_context():
            db.session.add(
                ApiKey(
                    service_name="shodan",
                    key_value="db-secret-key",
                    key_type="paid",
                    is_active=True,
                )
            )
            db.session.commit()

            result = ShodanService.get_key()

        assert result == "db-secret-key"

    def test_returns_key_from_db_and_increments_usage(self, app):
        from openm.models.api_key import ApiKey

        with app.app_context():
            key = ApiKey(
                service_name="shodan",
                key_value="db-secret-key",
                key_type="paid",
                is_active=True,
                usage_count=0,
            )
            # Precisamos adicionar e commitar para o query funcionar
            from openm.extensions import db

            db.session.add(key)
            db.session.commit()

            result = ShodanService.get_key()
            assert result == "db-secret-key"
            assert key.usage_count == 1

    def test_returns_key_from_env_when_no_db_key(self, app):
        with app.app_context():
            with patch.dict("os.environ", {"SHODAN_API_KEY": "env-secret"}):
                result = ShodanService.get_key()
        assert result == "env-secret"

    def test_returns_none_when_no_key_anywhere(self, app):
        with app.app_context():
            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "openm.services.shodan_service.ApiKey.query"
                ) as mock_q:
                    mock_q.filter_by.return_value.order_by.return_value. \
                        first.return_value = None
                    result = ShodanService.get_key()
        assert result is None


# ====================================================================
# resolve_domain
# ====================================================================

class TestResolveDomain:
    """Cobertura para ShodanService.resolve_domain."""

    def test_with_api_key_success(self, app):
        with app.app_context():
            with patch.object(
                ShodanService, "get_key", return_value="fake-key"
            ):
                with patch(
                    "openm.services.shodan_service.requests.get"
                ) as mock_get:
                    mock_resp = MagicMock()
                    mock_resp.json.return_value = {
                        "example.com": "93.184.216.34"
                    }
                    mock_get.return_value = mock_resp

                    result = ShodanService.resolve_domain("example.com")

        assert result == "93.184.216.34"
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        assert "shodan.io/dns/resolve" in args[0]
        assert kwargs["params"]["hostnames"] == "example.com"
        assert kwargs["params"]["key"] == "fake-key"

    def test_without_api_key_fallback_to_socket(self, app):
        with app.app_context():
            with patch.object(ShodanService, "get_key", return_value=None):
                with patch(
                    "openm.services.shodan_service.socket.gethostbyname",
                    return_value="1.2.3.4",
                ):
                    result = ShodanService.resolve_domain("localhost")

        assert result == "1.2.3.4"

    def test_without_api_key_socket_fails_returns_none(self, app):
        with app.app_context():
            with patch.object(ShodanService, "get_key", return_value=None):
                with patch(
                    "openm.services.shodan_service.socket.gethostbyname",
                    side_effect=OSError("DNS error"),
                ):
                    result = ShodanService.resolve_domain("invalid.invalid")

        assert result is None

    def test_api_falls_back_to_socket(self, app):
        conn_err = requests.exceptions.ConnectionError("Connection timeout")
        with app.app_context():
            with patch.object(
                ShodanService, "get_key", return_value="fake-key"
            ):
                with patch(
                    "openm.services.shodan_service.requests.get",
                    side_effect=conn_err,
                ):
                    with patch(
                        "openm.services.shodan_service.socket.gethostbyname",
                        return_value="5.6.7.8",
                    ):
                        result = ShodanService.resolve_domain("example.com")

        assert result == "5.6.7.8"

    def test_api_fails_and_socket_also_fails(self, app):
        conn_err = requests.exceptions.ConnectionError("Connection timeout")
        dns_err = OSError("DNS error")
        with app.app_context():
            with patch.object(
                ShodanService, "get_key", return_value="fake-key"
            ):
                with patch(
                    "openm.services.shodan_service.requests.get",
                    side_effect=conn_err,
                ):
                    with patch(
                        "openm.services.shodan_service.socket.gethostbyname",
                        side_effect=dns_err,
                    ):
                        result = ShodanService.resolve_domain("example.com")

        assert result is None

    def test_json_missing_domain_key_returns_none(self, app):
        with app.app_context():
            with patch.object(
                ShodanService, "get_key", return_value="fake-key"
            ):
                with patch(
                    "openm.services.shodan_service.requests.get"
                ) as mock_get:
                    mock_resp = MagicMock()
                    # Resposta sem a chave do domínio
                    mock_resp.json.return_value = {}
                    mock_get.return_value = mock_resp

                    result = ShodanService.resolve_domain("example.com")

        assert result is None


# ====================================================================
# query_host
# ====================================================================

class TestQueryHost:
    """Cobertura para ShodanService.query_host."""

    def test_success_returns_raw_data(self, app):
        with app.app_context():
            with patch.object(
                ShodanService, "get_key", return_value="fake-key"
            ):
                with patch(
                    "openm.services.shodan_service.requests.get"
                ) as mock_get:
                    mock_resp = MagicMock()
                    mock_resp.json.return_value = {
                        "ip": "1.1.1.1",
                        "data": [{"port": 53}],
                    }
                    mock_get.return_value = mock_resp

                    result = ShodanService.query_host("1.1.1.1")

        assert result == {"ip": "1.1.1.1", "data": [{"port": 53}]}

    def test_no_key_returns_none(self, app):
        with app.app_context():
            with patch.object(ShodanService, "get_key", return_value=None):
                result = ShodanService.query_host("1.1.1.1")

        assert result is None

    def test_timeout_returns_none(self, app):
        with app.app_context():
            with patch.object(
                ShodanService, "get_key", return_value="fake-key"
            ):
                with patch(
                    "openm.services.shodan_service.requests.get",
                    side_effect=requests.exceptions.Timeout("timeout"),
                ):
                    result = ShodanService.query_host("1.1.1.1")

        assert result is None

    def test_http_error_returns_none(self, app):
        http_err = requests.exceptions.HTTPError("404 Not Found")
        with app.app_context():
            with patch.object(
                ShodanService, "get_key", return_value="fake-key"
            ):
                with patch(
                    "openm.services.shodan_service.requests.get"
                ) as mock_get:
                    mock_resp = MagicMock()
                    mock_resp.raise_for_status.side_effect = http_err
                    mock_get.return_value = mock_resp

                    result = ShodanService.query_host("1.1.1.1")

        assert result is None


# ====================================================================
# investigate_host
# ====================================================================

class TestInvestigateHost:
    """Cobertura para ShodanService.investigate_host."""

    def test_with_real_data_extracts_ports_and_services(self, app):
        raw_data = {
            "data": [
                {
                    "port": 80,
                    "transport": "tcp",
                    "product": "Apache",
                    "version": "2.4.41",
                    "data": "HTTP/1.1 200 OK\r\nServer: Apache",
                    "cpe": ["cpe:/a:apache:http_server:2.4.41"],
                },
                {
                    "port": 443,
                    "transport": "tcp",
                    "product": "Apache",
                    "version": "2.4.41",
                    "data": "HTTP/1.1 200 OK\r\nServer: Apache",
                    "cpe": ["cpe:/a:apache:http_server:2.4.41"],
                },
                # Porta duplicada para testar deduplicação
                {
                    "port": 80,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.18",
                    "data": "HTTP/1.1 200 OK",
                    "cpe": [],
                },
            ],
            "country_name": "United States",
            "city": "San Francisco",
            "region_code": "CA",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "org": "Cloudflare, Inc.",
            "isp": "Cloudflare",
            "hostnames": ["cf.example.com"],
            "domains": ["example.com"],
            "os": "Linux",
            "tags": ["cdn", "cloud"],
        }

        with app.app_context():
            with patch.object(
                ShodanService, "query_host", return_value=raw_data
            ):
                result = ShodanService.investigate_host("1.1.1.1")

        assert result["ip"] == "1.1.1.1"
        assert result["source"] == "shodan"
        # Deduplicação: portas 80 e 443 (apenas 2, não 3)
        assert result["ports"] == [80, 443]
        assert len(result["services"]) == 3
        # Primeiro serviço
        assert result["services"][0]["port"] == 80
        assert result["services"][0]["product"] == "Apache"
        expected_banner = "HTTP/1.1 200 OK\r\nServer: Apache"[:200]
        assert result["services"][0]["banner"] == expected_banner
        # Location
        assert result["location"]["country"] == "United States"
        assert result["location"]["city"] == "San Francisco"
        assert result["location"]["latitude"] == 37.7749
        # Metadados
        assert result["organization"] == "Cloudflare, Inc."
        assert result["hostnames"] == ["cf.example.com"]
        assert result["domains"] == ["example.com"]
        assert result["os"] == "Linux"
        assert result["tags"] == ["cdn", "cloud"]

    def test_with_real_data_missing_optional_fields(self, app):
        """Quando a API retorna dados sem campos opcionais."""
        raw_data = {
            "data": [{"port": 22}],
            # country_name, city, region_code, latitude, longitude ausentes
            # org, isp, hostnames, domains, os, tags ausentes
        }

        with app.app_context():
            with patch.object(
                ShodanService, "query_host", return_value=raw_data
            ):
                result = ShodanService.investigate_host("192.0.2.1")

        assert result["location"]["country"] == ""
        assert result["location"]["city"] == ""
        assert result["location"]["latitude"] is None
        assert result["organization"] == ""  # org ausente, isp ausente
        assert result["hostnames"] == []
        assert result["domains"] == []
        assert result["os"] == ""
        assert result["tags"] == []
        assert result["services"][0]["product"] == ""
        assert result["services"][0]["version"] == ""
        assert result["services"][0]["transport"] == "tcp"  # default
        assert result["services"][0]["cpe"] == []

    def test_with_empty_data_list(self, app):
        """Quando query_host retorna dados mas data é lista vazia."""
        raw_data = {"data": []}

        with app.app_context():
            with patch.object(
                ShodanService, "query_host", return_value=raw_data
            ):
                result = ShodanService.investigate_host("192.0.2.1")

        assert result["ports"] == []
        assert result["services"] == []
        assert result["source"] == "shodan"

    def test_fallback_simulated_when_query_fails(self, app):
        with app.app_context():
            with patch.object(ShodanService, "query_host", return_value=None):
                result = ShodanService.investigate_host("192.0.2.1")

        assert result["source"] == "shodan_simulated"
        assert result["ports"] == [80, 443]
        assert len(result["services"]) == 2
        assert result["services"][0]["port"] == 80
        assert result["services"][1]["port"] == 443
        assert result["location"]["country"] == "Unknown"
        assert result["organization"] == "Simulated ISP"

    def test_banner_truncation(self, app):
        """Banner maior que 200 chars deve ser truncado."""
        long_banner = "A" * 500
        raw_data = {
            "data": [
                {
                    "port": 80,
                    "data": long_banner,
                }
            ],
        }

        with app.app_context():
            with patch.object(
                ShodanService, "query_host", return_value=raw_data
            ):
                result = ShodanService.investigate_host("1.1.1.1")

        assert len(result["services"][0]["banner"]) == 200
        assert result["services"][0]["banner"] == long_banner[:200]

    def test_org_fallback_to_isp(self, app):
        """Quando org ausente mas isp presente."""
        raw_data = {
            "data": [],
            "isp": "AT&T",
            # org ausente
        }

        with app.app_context():
            with patch.object(
                ShodanService, "query_host", return_value=raw_data
            ):
                result = ShodanService.investigate_host("1.1.1.1")

        assert result["organization"] == "AT&T"

    def test_port_none_skipped_in_deduplication(self, app):
        """Portas None não devem quebrar sorted(set(...))."""
        raw_data = {
            "data": [
                {"port": None},
                {"port": 22},
                {"port": None},
            ],
        }

        with app.app_context():
            with patch.object(
                ShodanService, "query_host", return_value=raw_data
            ):
                result = ShodanService.investigate_host("1.1.1.1")

        assert result["ports"] == [22]
        assert len(result["services"]) == 3  # todos incluídos, None aceito
