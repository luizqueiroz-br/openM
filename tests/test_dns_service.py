"""Cobertura do DNS service (issue #60)."""
import socket
from unittest.mock import patch

from openm.services.dns_service import resolve_domain


class TestResolveDomain:
    """Cobertura de ``openm.services.dns_service.resolve_domain``."""

    def test_resolve_returns_ip_list(self):
        """Resolução bem-sucedida retorna lista de IPs."""
        with patch(
            "openm.services.dns_service.socket.gethostbyname_ex",
            return_value=("example.com", [], ["93.184.216.34"]),
        ):
            result = resolve_domain("example.com")
        assert result == ["93.184.216.34"]

    def test_resolve_gaierror_returns_empty(self):
        """Falha de DNS (gaierror) retorna lista vazia + loga warning."""
        with patch(
            "openm.services.dns_service.socket.gethostbyname_ex",
            side_effect=socket.gaierror("Name or service not known"),
        ):
            result = resolve_domain("invalid.invalid")
        assert result == []

    def test_resolve_sets_and_resets_timeout(self):
        """``setdefaulttimeout`` é aplicado ANTES da chamada e resetado
        para o default do sistema no ``finally`` (``None``).

        Validação indireta: se o reset funcionou, o timeout pós-chamada
        é igual ao timeout pré-chamada (que por default em testes é
        ``None`` — o sistema default).
        """
        original = socket.getdefaulttimeout()
        try:
            with patch(
                "openm.services.dns_service.socket.gethostbyname_ex",
                return_value=("x.com", [], ["1.2.3.4"]),
            ):
                resolve_domain("x.com", timeout=2.5)
            # finally: voltou para o default (None) — não 2.5
            assert socket.getdefaulttimeout() == original
        finally:
            socket.setdefaulttimeout(original)

    def test_resolve_multiple_ips(self):
        """Domínio com múltiplos IPs retorna todos na ordem."""
        with patch(
            "openm.services.dns_service.socket.gethostbyname_ex",
            return_value=(
                "google.com",
                [],
                ["142.250.78.206", "142.250.78.207"],
            ),
        ):
            result = resolve_domain("google.com")
        assert result == ["142.250.78.206", "142.250.78.207"]
