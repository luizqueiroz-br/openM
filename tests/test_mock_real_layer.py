"""
Testes do refactor de Mock vs Real (issue #85).

Cobre:
- GeoIPService: factory get_geoip_service() respeita OPENM_GEOIP_MODE.
- GeoIPService: tem source_label correto por backend.
- GeoIPService: MaxMind.delega para Simulated quando backend indisponivel.
- GeoIPService: resultado inclui flag ``simulated``.
- SimulatedGeoIPService: investigate_ip e lookup funcionam standalone.
- WhoisService: investigate_domain delega para Simulated quando vazio.
- WhoisService: SimulatedWhoisService.investigate_domain standalone.
- get_whois_service() respeita OPENM_WHOIS_MODE.
"""

import pytest  # noqa: F401  (kept for editor/test discovery parity)


def test_get_geoip_service_default_no_maxmind_returns_simulated(monkeypatch):
    """Sem backend MaxMind disponivel -> SimulatedGeoIPService."""
    import openm.services.geoip_service as gs

    monkeypatch.setattr(gs, "_HAS_MAXMIND", False)
    monkeypatch.delenv("OPENM_GEOIP_MODE", raising=False)

    service = gs.get_geoip_service()
    assert isinstance(service, gs.SimulatedGeoIPService)


def test_get_geoip_service_explicit_real(monkeypatch):
    """OPENM_GEOIP_MODE=real forca MaxMindGeoIPService mesmo sem backend."""
    import openm.services.geoip_service as gs

    monkeypatch.setenv("OPENM_GEOIP_MODE", "real")

    service = gs.get_geoip_service()
    assert isinstance(service, gs.MaxMindGeoIPService)


def test_get_geoip_service_explicit_simulated(monkeypatch):
    """OPENM_GEOIP_MODE=simulated forca SimulatedGeoIPService mesmo com backend."""
    import openm.services.geoip_service as gs

    monkeypatch.setattr(gs, "_HAS_MAXMIND", True)
    monkeypatch.setenv("OPENM_GEOIP_MODE", "simulated")

    service = gs.get_geoip_service()
    assert isinstance(service, gs.SimulatedGeoIPService)


def test_simulated_geoip_marks_simulated_true():
    """SimulatedGeoIPService.investigate_ip sempre retorna simulated=True."""
    import openm.services.geoip_service as gs

    result = gs.SimulatedGeoIPService.investigate_ip("8.8.8.8")
    assert result["simulated"] is True
    assert result["source"] == "geoip_simulated"


def test_simulated_geoip_private_ip_range():
    """Faixas RFC 1918 retornam localizacao simulada."""
    import openm.services.geoip_service as gs

    result = gs.SimulatedGeoIPService.investigate_ip("192.168.1.1")
    assert result["country"] == "US"
    assert result["organization"] == "Private Network"
    assert result["simulated"] is True


def test_simulated_geoip_unknown_ip_default():
    """IP fora das faixas conhecidas -> default US Unknown."""
    import openm.services.geoip_service as gs

    result = gs.SimulatedGeoIPService.investigate_ip("255.255.255.255")
    assert result["country"] == "US"
    assert result["simulated"] is True


def test_simulated_geoip_lookup_returns_dict():
    """SimulatedGeoIPService.lookup retorna dict sem chave simulated."""
    import openm.services.geoip_service as gs

    result = gs.SimulatedGeoIPService.lookup("8.8.8.8")
    assert result is not None
    assert "source" in result
    # lookup eh versao low-level: sem simulated para nao confundir
    # consumidores que esperam formato MaxMind-like.
    assert "simulated" not in result


def test_maxmind_geoip_lookup_no_backend_returns_none(monkeypatch):
    """MaxMindGeoIPService sem backend retorna None (lookup low-level)."""
    import openm.services.geoip_service as gs

    monkeypatch.setattr(gs, "_HAS_MAXMIND", False)
    gs.MaxMindGeoIPService._reader = None
    gs.MaxMindGeoIPService._reader_loaded = False

    result = gs.MaxMindGeoIPService.lookup("8.8.8.8")
    assert result is None


def test_maxmind_geoip_investigate_ip_delegates_to_simulated_when_no_backend(monkeypatch):
    """investigate_ip no MaxMind sem backend delega para Simulated."""
    import openm.services.geoip_service as gs

    monkeypatch.setattr(gs, "_HAS_MAXMIND", False)
    gs.MaxMindGeoIPService._reader = None
    gs.MaxMindGeoIPService._reader_loaded = False

    result = gs.MaxMindGeoIPService.investigate_ip("8.8.8.8")
    # Quando MaxMind nao tem backend, investiga via Simulated.
    assert result["simulated"] is True
    assert result["source"] == "geoip_simulated"


def test_geoip_service_alias_is_maxmind():
    """GeoIPService (legacy alias) aponta para MaxMindGeoIPService."""
    import openm.services.geoip_service as gs

    assert gs.GeoIPService is gs.MaxMindGeoIPService


# ========================================================================
# WHOIS — factory + SimulatedWhoisService
# ========================================================================


def test_get_whois_service_default_returns_real(monkeypatch):
    """Sem env var -> WhoisService real."""
    import openm.services.whois_service as ws

    monkeypatch.delenv("OPENM_WHOIS_MODE", raising=False)
    service = ws.get_whois_service()
    assert service is ws.WhoisService


def test_get_whois_service_explicit_simulated(monkeypatch):
    """OPENM_WHOIS_MODE=simulated -> instancia de SimulatedWhoisService."""
    import openm.services.whois_service as ws

    monkeypatch.setenv("OPENM_WHOIS_MODE", "simulated")
    service = ws.get_whois_service()
    assert isinstance(service, ws.SimulatedWhoisService)


def test_simulated_whois_service_basic_fields():
    """SimulatedWhoisService.investigate_domain retorna dados plausiveis."""
    import openm.services.whois_service as ws

    result = ws.SimulatedWhoisService.investigate_domain("example.com")
    assert result["domain"] == "example.com"
    assert result["registrar"] == "Example Registrar, Inc."
    assert result["simulated"] if "simulated" in result else True
    assert result["source"] == "whois_simulated"
    assert "example.com" in result["nameservers"][0] or "ns1.example.com" == result["nameservers"][0]


def test_whois_investigate_domain_marks_simulated_when_fallback(monkeypatch):
    """WhoisService.investigate_domain retorna simulated=True quando fallback."""
    import openm.services.whois_service as ws

    # Mock query para retornar dados vazios
    def fake_query(domain):
        return {
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "nameservers": [],
        }

    monkeypatch.setattr(ws.WhoisService, "query", staticmethod(fake_query))

    result = ws.WhoisService.investigate_domain("empty.example")
    assert result["simulated"] is True
    assert result["source"] == "whois_simulated"


def test_whois_investigate_domain_no_fallback_when_has_data(monkeypatch):
    """WhoisService.investigate_domain NAO usa simulated quando tem dados reais."""
    import openm.services.whois_service as ws

    def fake_query(domain):
        return {
            "domain": domain,
            "registrar": "Real Registrar, Inc.",
            "creation_date": "2020-01-01T00:00:00Z",
            "nameservers": ["ns1.real.com"],
            "source": "whois",
        }

    monkeypatch.setattr(ws.WhoisService, "query", staticmethod(fake_query))

    result = ws.WhoisService.investigate_domain("real.example")
    assert result["simulated"] is False
    assert result["registrar"] == "Real Registrar, Inc."
    assert result["source"] == "whois"
