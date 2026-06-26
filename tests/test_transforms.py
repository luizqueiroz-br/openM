import os
from unittest.mock import patch

from openm.core.entity import Domain, Email, IPAddress
from openm.transforms.fraud_email import CheckFraudEmailTransform
from openm.transforms.resolve_ip import ResolveIPTransform
from openm.transforms.shodan import ShodanTransform


def test_resolve_ip_transform():
    domain = Domain(value="localhost", properties={})
    transform = ResolveIPTransform()

    with patch("openm.transforms.resolve_ip.resolve_domain", return_value=["127.0.0.1"]):
        result = transform.run(domain)

    assert len(result.entities) == 1
    assert isinstance(result.entities[0], IPAddress)
    assert result.entities[0].value == "127.0.0.1"
    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "RESOLVES_TO"
    assert result.relationships[0]["from_id"] == domain.id


def test_resolve_ip_transform_skips_non_domain():
    email = Email(value="a@b.com")
    transform = ResolveIPTransform()
    result = transform.run(email)
    assert result.entities == []
    assert result.relationships == []


def test_fraud_email_transform_simulation():
    email = Email(value="test@example.com")
    transform = CheckFraudEmailTransform()

    with patch.object(
        transform.__class__.__bases__[0],
        "__init__",
        lambda self: None,
    ):
        pass

    with patch(
        "openm.transforms.fraud_email.ThreatIntelService.investigate_email",
        return_value={
            "email": "test@example.com",
            "sources": ["simulated"],
            "risk_score": 0,
            "indicators": [],
            "associated_ips": [
                {"ip": "198.51.100.7", "context": "simulated_suspicious_access"}
            ],
            "associated_devices": [
                {"device": "android-suspicious-1", "context": "simulated_device"}
            ],
        },
    ):
        result = transform.run(email)

    assert len(result.entities) == 2
    assert len(result.relationships) == 2
    assert any(r["type"] == "SUSPICIOUS_LOGIN" for r in result.relationships)
    assert any(r["type"] == "ASSOCIATED_WITH" for r in result.relationships)


# ====================================================================
# Shodan Transform
# ====================================================================

def test_shodan_transform_domain():
    """Domain → IP → portas/serviços via Shodan."""
    domain = Domain(value="example.com", properties={})
    transform = ShodanTransform()

    with patch("openm.transforms.shodan.ShodanService.resolve_domain", return_value="93.184.216.34"):
        with patch(
            "openm.transforms.shodan.ShodanService.investigate_host",
            return_value={
                "ip": "93.184.216.34",
                "source": "shodan",
                "ports": [80, 443],
                "services": [
                    {
                        "port": 80,
                        "transport": "tcp",
                        "product": "nginx",
                        "version": "1.18",
                        "banner": "HTTP/1.1 200",
                        "cpe": [],
                    },
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "nginx",
                        "version": "1.18",
                        "banner": "HTTP/1.1 200",
                        "cpe": [],
                    },
                ],
                "location": {"country": "US", "city": "Los Angeles"},
                "organization": "Example Inc",
                "os": "Linux",
                "tags": ["web"],
            },
        ):
            result = transform.run(domain)

    # Deve ter: 1 IP + 2 Device (portas) + 1 Device (metadata) = 4 entidades
    assert len(result.entities) == 4
    # 1 RESOLVES_TO + 2 EXPOSES + 1 RUNS = 4 relacionamentos
    assert len(result.relationships) == 4
    assert any(r["type"] == "RESOLVES_TO" for r in result.relationships)
    assert sum(1 for r in result.relationships if r["type"] == "EXPOSES") == 2
    assert any(r["type"] == "RUNS" for r in result.relationships)


def test_shodan_transform_ip():
    """IPAddress → portas/serviços (sem resolver domínio)."""
    ip = IPAddress(value="1.1.1.1")
    transform = ShodanTransform()

    with patch(
        "openm.transforms.shodan.ShodanService.investigate_host",
        return_value={
            "ip": "1.1.1.1",
            "source": "shodan",
            "ports": [53],
            "services": [
                {"port": 53, "transport": "udp", "product": "dnsmasq", "version": "", "banner": "", "cpe": []},
            ],
            "location": {"country": "US", "city": ""},
            "organization": "Cloudflare",
            "os": "",
            "tags": [],
        },
    ):
        result = transform.run(ip)

    # 1 Device (porta 53) + 1 Device (metadata)
    assert len(result.entities) == 2
    assert len(result.relationships) == 2  # EXPOSES + RUNS
    assert all(r["from_id"] == ip.id for r in result.relationships)


def test_shodan_transform_skips_invalid_type():
    email = Email(value="a@b.com")
    transform = ShodanTransform()
    result = transform.run(email)
    assert result.entities == []
    assert result.relationships == []


def test_shodan_transform_simulation_fallback():
    """Quando a API falha, investigate_host retorna dados simulados."""
    ip = IPAddress(value="192.0.2.1")
    transform = ShodanTransform()

    with patch(
        "openm.transforms.shodan.ShodanService.investigate_host",
        return_value={
            "ip": "192.0.2.1",
            "source": "shodan_simulated",
            "ports": [80, 443],
            "services": [
                {
                    "port": 80,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.18.0",
                    "banner": "HTTP/1.1 200 OK...",
                    "cpe": [],
                },
                {
                    "port": 443,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.18.0",
                    "banner": "HTTP/1.1 200 OK...",
                    "cpe": [],
                },
            ],
            "location": {"country": "Unknown", "city": ""},
            "organization": "Simulated ISP",
            "os": "",
            "tags": [],
        },
    ):
        result = transform.run(ip)

    assert len(result.entities) == 3  # 2 portas + 1 metadata
    assert any(e.properties.get("source") == "shodan_simulated" for e in result.entities)
    assert any(r["properties"].get("provenance") == "shodan" for r in result.relationships)


def test_shodan_transform_domain_unresolvable():
    """Domain que não resolve → TransformResult vazio (linha 39)."""
    domain = Domain(value="invalid.invalid", properties={})
    transform = ShodanTransform()

    with patch(
        "openm.transforms.shodan.ShodanService.resolve_domain",
        return_value=None,
    ):
        result = transform.run(domain)

    assert result.entities == []
    assert result.relationships == []


def test_shodan_transform_duplicate_ports_skipped():
    """Portas duplicadas/None no loop de services (linha 80)."""
    ip = IPAddress(value="1.1.1.1")
    transform = ShodanTransform()

    with patch(
        "openm.transforms.shodan.ShodanService.investigate_host",
        return_value={
            "ip": "1.1.1.1",
            "source": "shodan",
            "ports": [80, 443],
            "services": [
                {"port": 80, "transport": "tcp", "product": "nginx", "version": "", "banner": "", "cpe": []},
                {"port": 80, "transport": "tcp", "product": "apache", "version": "", "banner": "", "cpe": []},
                {"port": None, "transport": "tcp", "product": "", "version": "", "banner": "", "cpe": []},
                {"port": 443, "transport": "tcp", "product": "nginx", "version": "", "banner": "", "cpe": []},
            ],
            "location": {"country": "US", "city": ""},
            "organization": "TestOrg",
            "os": "",
            "tags": [],
        },
    ):
        result = transform.run(ip)

    # Apenas 2 Device (portas 80 e 443) + 1 metadata = 3 entidades
    # Porta None e duplicata 80 são puladas
    device_entities = [e for e in result.entities if e.type == "Device" and e.properties.get("role") != "host_metadata"]
    assert len(device_entities) == 2
    ports = [e.properties["port"] for e in device_entities]
    assert sorted(ports) == [80, 443]


def test_shodan_transform_no_location_or_org():
    """Sem location.country e sem org → RUNS edge não é criado."""
    ip = IPAddress(value="1.1.1.1")
    transform = ShodanTransform()

    with patch(
        "openm.transforms.shodan.ShodanService.investigate_host",
        return_value={
            "ip": "1.1.1.1",
            "source": "shodan",
            "ports": [80],
            "services": [
                {"port": 80, "transport": "tcp", "product": "nginx", "version": "", "banner": "", "cpe": []},
            ],
            "location": {"country": "", "city": ""},
            "organization": "",
            "os": "",
            "tags": [],
        },
    ):
        result = transform.run(ip)

    # Apenas 1 Device (porta 80), sem metadata
    assert len(result.entities) == 1
    assert len(result.relationships) == 1  # apenas EXPOSES
    assert result.relationships[0]["type"] == "EXPOSES"


# ====================================================================
# Whois Transform
# ====================================================================

MOCK_WHOIS_DATA = {
    "domain": "example.com",
    "registrar": "Example Registrar, Inc.",
    "creation_date": "2020-01-15T00:00:00Z",
    "expiry_date": "2027-01-15T00:00:00Z",
    "updated_date": "2025-06-01T00:00:00Z",
    "nameservers": ["ns1.example.com", "ns2.example.com"],
    "status": ["clientTransferProhibited"],
    "dnssec": "unsigned",
    "registrant_name": "John Doe",
    "registrant_org": "Example Organization",
    "registrant_email": "admin@example.com",
    "registrant_country": "US",
    "admin_name": "Admin User",
    "admin_email": "admin@example.com",
    "admin_org": "Example Org",
    "tech_name": "Tech User",
    "tech_email": "tech@example.com",
    "tech_org": "Example Tech",
    "source": "whois",
    "raw": "(mock whois data)",
}


def test_whois_transform_domain():
    """Domain → WHOIS metadata + Person nodes + edges."""
    from openm.transforms.whois import WhoisTransform

    domain = Domain(value="example.com", properties={})
    transform = WhoisTransform()

    with patch(
        "openm.transforms.whois.WhoisService.investigate_domain",
        return_value=MOCK_WHOIS_DATA,
    ):
        result = transform.run(domain)

    # Should have: 1 Domain (annotated) + 1 registrant + 1 admin + 1 tech + 1 registrar = 5 entities
    assert len(result.entities) == 5

    # Check Domain annotation
    domain_entity = result.entities[0]
    assert domain_entity.type == "Domain"
    assert domain_entity.properties.get("whois_registrar") == "Example Registrar, Inc."
    assert domain_entity.properties.get("whois_creation_date") == "2020-01-15T00:00:00Z"
    assert domain_entity.properties.get("whois_expiry_date") == "2027-01-15T00:00:00Z"
    assert "ns1.example.com" in domain_entity.properties.get("whois_nameservers", [])
    assert "ns2.example.com" in domain_entity.properties.get("whois_nameservers", [])
    assert domain_entity.properties.get("whois_dnssec") == "unsigned"
    assert domain_entity.properties.get("whois_source") == "whois"

    # Check relationships
    rel_types = [r["type"] for r in result.relationships]
    assert "REGISTERED_BY" in rel_types
    assert "ADMIN_CONTACT" in rel_types
    assert "TECH_CONTACT" in rel_types

    # Check Person entities
    person_entities = [e for e in result.entities if e.type == "Person"]
    assert len(person_entities) >= 3

    # Check registrant
    registrant = [e for e in person_entities if e.properties.get("role") == "registrant"]
    assert len(registrant) == 1
    assert registrant[0].value == "John Doe"  # name takes priority over org

    # Check admin
    admin = [e for e in person_entities if e.properties.get("role") == "admin_contact"]
    assert len(admin) == 1
    assert admin[0].value == "Admin User"

    # Check tech
    tech = [e for e in person_entities if e.properties.get("role") == "tech_contact"]
    assert len(tech) == 1
    assert tech[0].value == "Tech User"

    # Check registrar
    registrar = [e for e in person_entities if e.properties.get("role") == "registrar"]
    assert len(registrar) == 1
    assert registrar[0].value == "Example Registrar, Inc."


def test_whois_transform_skips_non_domain():
    """WhoisTransform should return empty for non-Domain entities."""
    from openm.transforms.whois import WhoisTransform

    ip = IPAddress(value="1.1.1.1")
    transform = WhoisTransform()
    result = transform.run(ip)
    assert result.entities == []
    assert result.relationships == []


def test_whois_transform_simulation_fallback():
    """When WHOIS fails, investigate_domain returns simulated data."""
    from openm.transforms.whois import WhoisTransform

    domain = Domain(value="unknown-domain-12345.xyz", properties={})
    transform = WhoisTransform()

    with patch(
        "openm.transforms.whois.WhoisService.investigate_domain",
        return_value={
            "domain": "unknown-domain-12345.xyz",
            "registrar": "Example Registrar, Inc.",
            "creation_date": "2020-01-15T00:00:00Z",
            "expiry_date": "2027-01-15T00:00:00Z",
            "updated_date": "2025-06-01T00:00:00Z",
            "nameservers": ["ns1.example.com", "ns2.example.com"],
            "status": ["clientTransferProhibited"],
            "dnssec": "unsigned",
            "registrant_org": "Example Organization",
            "registrant_email": "admin@unknown-domain-12345.xyz",
            "registrant_country": "US",
            "admin_email": "admin@unknown-domain-12345.xyz",
            "tech_email": "tech@unknown-domain-12345.xyz",
            "source": "whois_simulated",
            "raw": "(simulated WHOIS data)",
        },
    ):
        result = transform.run(domain)

    assert len(result.entities) >= 3  # Domain + registrant + admin + tech + registrar
    assert any(
        e.properties.get("whois_source") == "whois_simulated"
        for e in result.entities
        if e.type == "Domain"
    )


def test_whois_transform_minimal_data():
    """WhoisTransform with minimal WHOIS data (only registrar)."""
    from openm.transforms.whois import WhoisTransform

    domain = Domain(value="minimal.com", properties={})
    transform = WhoisTransform()

    with patch(
        "openm.transforms.whois.WhoisService.investigate_domain",
        return_value={
            "domain": "minimal.com",
            "registrar": "Minimal Registrar",
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "nameservers": [],
            "status": [],
            "dnssec": None,
            "registrant_name": None,
            "registrant_org": None,
            "registrant_email": None,
            "registrant_country": None,
            "admin_name": None,
            "admin_email": None,
            "admin_org": None,
            "tech_name": None,
            "tech_email": None,
            "tech_org": None,
            "source": "whois",
            "raw": "(minimal)",
        },
    ):
        result = transform.run(domain)

    # Should have: 1 Domain + 1 registrar Person = 2 entities
    assert len(result.entities) == 2
    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "REGISTERED_BY"


# ====================================================================
# GeoIP Transform
# ====================================================================

MOCK_GEOIP_DATA = {
    "ip": "8.8.8.8",
    "country": "US",
    "country_name": "United States",
    "city": "Mountain View",
    "postal_code": "94043",
    "latitude": 37.4220,
    "longitude": -122.0841,
    "accuracy_radius": 10,
    "timezone": "America/Los_Angeles",
    "continent": "North America",
    "subdivision": "California",
    "organization": "Google LLC",
    "source": "maxmind_geolite2",
}


def test_geoip_transform_ip():
    """IPAddress → GeoIP metadata + LOCATED_IN + ASN edges."""
    from openm.transforms.geoip import GeoIPTransform

    ip = IPAddress(value="8.8.8.8")
    transform = GeoIPTransform()

    with patch(
        "openm.transforms.geoip.GeoIPService.investigate_ip",
        return_value=MOCK_GEOIP_DATA,
    ):
        result = transform.run(ip)

    # Should have: 1 IP (annotated) + 1 location Device + 1 org Device = 3 entities
    assert len(result.entities) == 3

    # Check IP annotation
    ip_entity = [e for e in result.entities if e.type == "IPAddress"][0]
    assert ip_entity.properties.get("geo_country") == "US"
    assert ip_entity.properties.get("geo_country_name") == "United States"
    assert ip_entity.properties.get("geo_city") == "Mountain View"
    assert ip_entity.properties.get("geo_latitude") == 37.4220
    assert ip_entity.properties.get("geo_longitude") == -122.0841
    assert ip_entity.properties.get("geo_source") == "maxmind_geolite2"

    # Check relationships
    rel_types = [r["type"] for r in result.relationships]
    assert "LOCATED_IN" in rel_types
    assert "ASN" in rel_types

    # Check location Device
    location_devices = [
        e for e in result.entities if e.type == "Device" and e.properties.get("role") == "geo_location"
    ]
    assert len(location_devices) == 1
    assert location_devices[0].value == "Mountain View, United States"
    assert location_devices[0].properties.get("country") == "US"
    assert location_devices[0].properties.get("latitude") == 37.4220

    # Check organization Device
    org_devices = [
        e for e in result.entities if e.type == "Device" and e.properties.get("role") == "organization"
    ]
    assert len(org_devices) == 1
    assert org_devices[0].value == "Google LLC"

    # Check LOCATED_IN relationship
    located_rel = [r for r in result.relationships if r["type"] == "LOCATED_IN"][0]
    assert located_rel["from_id"] == ip.id
    assert located_rel["properties"]["country"] == "US"
    assert located_rel["properties"]["city"] == "Mountain View"

    # Check ASN relationship
    asn_rel = [r for r in result.relationships if r["type"] == "ASN"][0]
    assert asn_rel["from_id"] == ip.id
    assert asn_rel["properties"]["organization"] == "Google LLC"


def test_geoip_transform_skips_non_ip():
    """GeoIPTransform should return empty for non-IPAddress entities."""
    from openm.transforms.geoip import GeoIPTransform

    domain = Domain(value="example.com")
    transform = GeoIPTransform()
    result = transform.run(domain)
    assert result.entities == []
    assert result.relationships == []


def test_geoip_transform_simulation_fallback():
    """When GeoIP DB is unavailable, investigate_ip returns simulated data."""
    from openm.transforms.geoip import GeoIPTransform

    ip = IPAddress(value="203.0.113.1")
    transform = GeoIPTransform()

    with patch(
        "openm.transforms.geoip.GeoIPService.investigate_ip",
        return_value={
            "ip": "203.0.113.1",
            "country": "AU",
            "country_name": "Australia",
            "city": "Sydney",
            "postal_code": "",
            "latitude": -33.8688,
            "longitude": 151.2093,
            "accuracy_radius": 50,
            "timezone": "",
            "continent": "",
            "subdivision": "",
            "organization": "Telstra",
            "source": "geoip_simulated",
        },
    ):
        result = transform.run(ip)

    assert len(result.entities) == 3
    ip_entity = [e for e in result.entities if e.type == "IPAddress"][0]
    assert ip_entity.properties.get("geo_source") == "geoip_simulated"
    assert ip_entity.properties.get("geo_country") == "AU"


def test_geoip_transform_no_org():
    """GeoIPTransform without organization data (no ASN edge)."""
    from openm.transforms.geoip import GeoIPTransform

    ip = IPAddress(value="10.0.0.1")
    transform = GeoIPTransform()

    with patch(
        "openm.transforms.geoip.GeoIPService.investigate_ip",
        return_value={
            "ip": "10.0.0.1",
            "country": "US",
            "country_name": "United States",
            "city": "New York",
            "postal_code": "",
            "latitude": 40.7128,
            "longitude": -74.0060,
            "accuracy_radius": 50,
            "timezone": "",
            "continent": "",
            "subdivision": "",
            "organization": "",
            "source": "geoip_simulated",
        },
    ):
        result = transform.run(ip)

    # Should have: 1 IP + 1 location Device = 2 entities (no org)
    assert len(result.entities) == 2
    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "LOCATED_IN"


def test_geoip_transform_no_location():
    """GeoIPTransform without city/country (no LOCATED_IN edge)."""
    from openm.transforms.geoip import GeoIPTransform

    ip = IPAddress(value="0.0.0.0")
    transform = GeoIPTransform()

    with patch(
        "openm.transforms.geoip.GeoIPService.investigate_ip",
        return_value={
            "ip": "0.0.0.0",
            "country": "",
            "country_name": "",
            "city": "",
            "postal_code": "",
            "latitude": None,
            "longitude": None,
            "accuracy_radius": 1000,
            "timezone": "",
            "continent": "",
            "subdivision": "",
            "organization": "Unknown ISP",
            "source": "geoip_simulated",
        },
    ):
        result = transform.run(ip)

    # Should have: 1 IP + 1 org Device = 2 entities (no location)
    assert len(result.entities) == 2
    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "ASN"


# ====================================================================
# WhoisService unit tests
# ====================================================================


def test_whois_service_parse_response():
    """Test WHOIS response parsing with realistic data."""
    from openm.services.whois_service import _parse_whois_response

    raw = """
    Domain Name: EXAMPLE.COM
    Registry Domain ID: 123456789_DOMAIN_COM-VRSN
    Registrar WHOIS Server: whois.example-registrar.com
    Registrar: Example Registrar, Inc.
    Updated Date: 2025-06-01T00:00:00Z
    Creation Date: 2020-01-15T00:00:00Z
    Registry Expiry Date: 2027-01-15T00:00:00Z
    Registrar: Example Registrar, Inc.
    Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
    Name Server: NS1.EXAMPLE.COM
    Name Server: NS2.EXAMPLE.COM
    DNSSEC: unsigned
    Registrant Organization: Example Organization
    Registrant Email: admin@example.com
    Admin Email: admin@example.com
    Tech Email: tech@example.com
    Country: US
    """

    result = _parse_whois_response(raw, "example.com")

    assert result["domain"] == "example.com"
    assert result["registrar"] == "Example Registrar, Inc."
    assert result["creation_date"] == "2020-01-15T00:00:00Z"
    assert result["expiry_date"] == "2027-01-15T00:00:00Z"
    assert result["updated_date"] == "2025-06-01T00:00:00Z"
    assert "ns1.example.com" in result["nameservers"]
    assert "ns2.example.com" in result["nameservers"]
    assert "clientTransferProhibited" in result["status"]
    assert result["dnssec"] == "unsigned"
    assert result["registrant_org"] == "Example Organization"
    assert result["registrant_email"] == "admin@example.com"
    assert result["admin_email"] == "admin@example.com"
    assert result["tech_email"] == "tech@example.com"
    assert result["registrant_country"] == "US"


def test_whois_service_parse_minimal():
    """Test WHOIS response parsing with minimal data."""
    from openm.services.whois_service import _parse_whois_response

    raw = """
    Domain Name: minimal.com
    Registrar: Minimal Registrar
    Creation Date: 2023-01-01T00:00:00Z
    """

    result = _parse_whois_response(raw, "minimal.com")

    assert result["domain"] == "minimal.com"
    assert result["registrar"] == "Minimal Registrar"
    assert result["creation_date"] == "2023-01-01T00:00:00Z"
    assert result["expiry_date"] is None
    assert result["nameservers"] == []
    assert result["registrant_org"] is None


def test_whois_service_extract_tld():
    """Test TLD extraction from domain names."""
    from openm.services.whois_service import _extract_tld

    assert _extract_tld("example.com") == "com"
    assert _extract_tld("example.co.uk") == "co.uk"
    assert _extract_tld("example.com.br") == "com.br"
    assert _extract_tld("example.org") == "org"
    assert _extract_tld("example.io") == "io"
    assert _extract_tld("example.xyz") == "xyz"
    assert _extract_tld("sub.example.com") == "com"


def test_whois_service_get_server():
    """Test WHOIS server resolution for different TLDs."""
    from openm.services.whois_service import _get_whois_server

    assert _get_whois_server("example.com") == "whois.verisign-grs.com"
    assert _get_whois_server("example.org") == "whois.pir.org"
    assert _get_whois_server("example.io") == "whois.nic.io"
    assert _get_whois_server("example.br") == "whois.registro.br"
    assert _get_whois_server("example.co.uk") == "whois.nic.uk"
    # Unknown TLD falls back to IANA
    assert _get_whois_server("example.unknown-tld") == "whois.iana.org"


def test_whois_service_investigate_domain_mocked():
    """Test WhoisService.investigate_domain with mocked socket."""
    from openm.services.whois_service import WhoisService

    mock_raw = """
    Domain Name: testdomain.com
    Registrar: Test Registrar
    Creation Date: 2021-06-15T00:00:00Z
    Registry Expiry Date: 2026-06-15T00:00:00Z
    Name Server: NS1.TESTDOMAIN.COM
    Name Server: NS2.TESTDOMAIN.COM
    Domain Status: clientTransferProhibited
    Registrant Organization: Test Org
    Registrant Email: admin@testdomain.com
    Country: BR
    """

    with patch(
        "openm.services.whois_service._query_whois_raw",
        return_value=mock_raw,
    ):
        result = WhoisService.investigate_domain("testdomain.com")

    assert result["domain"] == "testdomain.com"
    assert result["registrar"] == "Test Registrar"
    assert result["creation_date"] == "2021-06-15T00:00:00Z"
    assert result["expiry_date"] == "2026-06-15T00:00:00Z"
    assert "ns1.testdomain.com" in result["nameservers"]
    assert result["registrant_org"] == "Test Org"
    assert result["registrant_email"] == "admin@testdomain.com"
    assert result["registrant_country"] == "BR"
    assert result["source"] == "whois"


def test_whois_service_investigate_domain_fallback():
    """Test WhoisService fallback to simulated data when query fails."""
    from openm.services.whois_service import WhoisService

    with patch(
        "openm.services.whois_service._query_whois_raw",
        return_value=None,
    ):
        result = WhoisService.investigate_domain("nonexistent-domain-99999.com")

    assert result["source"] == "whois_simulated"
    assert result["registrar"] == "Example Registrar, Inc."
    assert result["creation_date"] == "2020-01-15T00:00:00Z"
    assert len(result["nameservers"]) >= 2
    assert result["registrant_org"] == "Example Organization"


# ====================================================================
# GeoIPService unit tests
# ====================================================================


def test_geoip_service_investigate_ip_simulated():
    """Test GeoIPService.investigate_ip returns simulated data."""
    from openm.services.geoip_service import GeoIPService

    result = GeoIPService.investigate_ip("8.8.8.8")

    assert result["ip"] == "8.8.8.8"
    assert result["country"] == "US"
    assert result["country_name"] == "United States"
    assert result["city"] == "San Jose"
    assert result["latitude"] is not None
    assert result["longitude"] is not None
    assert result["organization"] == "Google LLC"
    assert result["source"] == "geoip_simulated"


def test_geoip_service_investigate_ip_private():
    """Test GeoIPService with private IP ranges."""
    from openm.services.geoip_service import GeoIPService

    result = GeoIPService.investigate_ip("192.168.1.1")

    assert result["ip"] == "192.168.1.1"
    assert result["country"] == "US"
    assert result["city"] == "San Francisco"
    assert result["organization"] == "Private Network"
    assert result["source"] == "geoip_simulated"


def test_geoip_service_investigate_ip_unknown():
    """Test GeoIPService with unknown IP range."""
    from openm.services.geoip_service import GeoIPService

    result = GeoIPService.investigate_ip("255.255.255.255")

    assert result["ip"] == "255.255.255.255"
    # Falls back to default
    assert result["country"] == "US"
    assert result["source"] == "geoip_simulated"


def test_geoip_service_investigate_ip_brazil():
    """Test GeoIPService with Brazilian IP range."""
    from openm.services.geoip_service import GeoIPService

    result = GeoIPService.investigate_ip("90.0.0.1")

    assert result["ip"] == "90.0.0.1"
    assert result["country"] == "BR"
    assert result["country_name"] == "Brazil"
    assert result["city"] == "Sao Paulo"
    assert result["organization"] == "Vivo"
    assert result["source"] == "geoip_simulated"


# ====================================================================
# Transform Registry tests
# ====================================================================


def test_whois_transform_registered():
    """Verify WhoisTransform is registered in the TransformRegistry."""
    from openm.core.transform import TransformRegistry

    transforms = TransformRegistry.list_for_type("Domain")
    whois_names = [t["name"] for t in transforms]
    assert "whois_lookup" in whois_names


def test_geoip_transform_registered():
    """Verify GeoIPTransform is registered in the TransformRegistry."""
    from openm.core.transform import TransformRegistry

    transforms = TransformRegistry.list_for_type("IPAddress")
    geoip_names = [t["name"] for t in transforms]
    assert "geoip_lookup" in geoip_names


# ====================================================================
# GeoIPService — _get_reader coverage
# ====================================================================


def test_geoip_service_get_reader_no_maxminddb(monkeypatch):
    """Test _get_reader when maxminddb is not installed."""
    import openm.services.geoip_service as gs

    # Reset cached state
    gs.GeoIPService._reader = None
    gs.GeoIPService._reader_loaded = False

    monkeypatch.setattr(gs, "_HAS_MAXMIND", False)
    reader = gs.GeoIPService._get_reader()
    assert reader is None


def test_geoip_service_get_reader_db_not_found(monkeypatch, tmp_path):
    """Test _get_reader when GeoLite2 db file doesn't exist."""
    import openm.services.geoip_service as gs

    # Reset cached state
    gs.GeoIPService._reader = None
    gs.GeoIPService._reader_loaded = False

    monkeypatch.setattr(gs, "_HAS_MAXMIND", True)
    monkeypatch.setattr(gs, "GEOIP_DB_PATH", str(tmp_path / "nonexistent.mmdb"))
    # Also ensure alt paths don't exist
    monkeypatch.setattr(os.path, "isfile", lambda p: False)

    reader = gs.GeoIPService._get_reader()
    assert reader is None


def test_geoip_service_get_reader_alt_path_found(monkeypatch, tmp_path):
    """Test _get_reader when db is found at an alternative path."""
    import openm.services.geoip_service as gs

    # Reset cached state
    gs.GeoIPService._reader = None
    gs.GeoIPService._reader_loaded = False

    monkeypatch.setattr(gs, "_HAS_MAXMIND", True)
    monkeypatch.setattr(gs, "GEOIP_DB_PATH", str(tmp_path / "nonexistent.mmdb"))

    # Mock isfile to return True for the first alt path
    alt_path = "/usr/local/share/GeoIP/GeoLite2-City.mmdb"

    def mock_isfile(path):
        if path == alt_path:
            return True
        return False

    monkeypatch.setattr(os.path, "isfile", mock_isfile)

    # Mock maxminddb.open_database
    fake_reader = object()
    monkeypatch.setattr(gs.maxminddb, "open_database", lambda p: fake_reader)

    reader = gs.GeoIPService._get_reader()
    assert reader is fake_reader


def test_geoip_service_get_reader_open_error(monkeypatch, tmp_path):
    """Test _get_reader when maxminddb.open_database raises an exception."""
    import openm.services.geoip_service as gs

    # Reset cached state
    gs.GeoIPService._reader = None
    gs.GeoIPService._reader_loaded = False

    db_file = tmp_path / "GeoLite2-City.mmdb"
    db_file.write_text("corrupt data")

    monkeypatch.setattr(gs, "_HAS_MAXMIND", True)
    monkeypatch.setattr(gs, "GEOIP_DB_PATH", str(db_file))

    # Mock open_database to raise
    monkeypatch.setattr(gs.maxminddb, "open_database", lambda p: (_ for _ in ()).throw(ValueError("corrupt")))

    reader = gs.GeoIPService._get_reader()
    assert reader is None


# ====================================================================
# GeoIPService — lookup() coverage
# ====================================================================


def test_geoip_service_lookup_no_reader(monkeypatch):
    """Test lookup() when _get_reader returns None."""
    import openm.services.geoip_service as gs

    gs.GeoIPService._reader = None
    gs.GeoIPService._reader_loaded = False
    monkeypatch.setattr(gs, "_HAS_MAXMIND", False)

    result = gs.GeoIPService.lookup("8.8.8.8")
    assert result is None


def test_geoip_service_lookup_ip_not_found(monkeypatch):
    """Test lookup() when the IP is not in the database."""
    import openm.services.geoip_service as gs

    gs.GeoIPService._reader = None
    gs.GeoIPService._reader_loaded = False

    fake_reader = type("FakeReader", (), {"get": lambda self, ip: None})()
    monkeypatch.setattr(gs.GeoIPService, "_get_reader", lambda: fake_reader)

    result = gs.GeoIPService.lookup("0.0.0.0")
    assert result is None


def test_geoip_service_lookup_success(monkeypatch):
    """Test lookup() with a successful MaxMind response."""
    import openm.services.geoip_service as gs

    gs.GeoIPService._reader = None
    gs.GeoIPService._reader_loaded = False

    fake_response = {
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "city": {"names": {"en": "Mountain View"}},
        "location": {
            "latitude": 37.422,
            "longitude": -122.084,
            "accuracy_radius": 10,
            "time_zone": "America/Los_Angeles",
        },
        "postal": {"code": "94043"},
        "continent": {"names": {"en": "North America"}},
        "subdivisions": [{"names": {"en": "California"}}],
    }
    fake_reader = type("FakeReader", (), {"get": lambda self, ip: fake_response})()
    monkeypatch.setattr(gs.GeoIPService, "_get_reader", lambda: fake_reader)

    result = gs.GeoIPService.lookup("8.8.8.8")
    assert result is not None
    assert result["ip"] == "8.8.8.8"
    assert result["country"] == "US"
    assert result["country_name"] == "United States"
    assert result["city"] == "Mountain View"
    assert result["latitude"] == 37.422
    assert result["longitude"] == -122.084
    assert result["postal_code"] == "94043"
    assert result["timezone"] == "America/Los_Angeles"
    assert result["continent"] == "North America"
    assert result["subdivision"] == "California"
    assert result["source"] == "maxmind_geolite2"


def test_geoip_service_lookup_exception(monkeypatch):
    """Test lookup() when reader.get() raises an exception."""
    import openm.services.geoip_service as gs

    gs.GeoIPService._reader = None
    gs.GeoIPService._reader_loaded = False

    fake_reader = type("FakeReader", (), {"get": lambda self, ip: (_ for _ in ()).throw(RuntimeError("db error"))})()
    monkeypatch.setattr(gs.GeoIPService, "_get_reader", lambda: fake_reader)

    result = gs.GeoIPService.lookup("8.8.8.8")
    assert result is None


def test_geoip_service_investigate_ip_from_real_lookup(monkeypatch):
    """Test investigate_ip when lookup() returns real data (covers the `if result:` branch)."""
    import openm.services.geoip_service as gs

    gs.GeoIPService._reader = None
    gs.GeoIPService._reader_loaded = False

    fake_response = {
        "country": {"iso_code": "JP", "names": {"en": "Japan"}},
        "city": {"names": {"en": "Tokyo"}},
        "location": {"latitude": 35.6762, "longitude": 139.6503, "accuracy_radius": 20, "time_zone": "Asia/Tokyo"},
        "postal": {"code": "100-0001"},
        "continent": {"names": {"en": "Asia"}},
        "subdivisions": [{"names": {"en": "Tokyo"}}],
    }
    fake_reader = type("FakeReader", (), {"get": lambda self, ip: fake_response})()
    monkeypatch.setattr(gs.GeoIPService, "_get_reader", lambda: fake_reader)

    result = gs.GeoIPService.investigate_ip("60.0.0.1")
    assert result["source"] == "maxmind_geolite2"
    assert result["country"] == "JP"
    assert result["city"] == "Tokyo"


def test_geoip_service_investigate_ip_ipv6():
    """Test investigate_ip with an IPv6 address (covers non-IPv4 branch)."""
    from openm.services.geoip_service import GeoIPService

    result = GeoIPService.investigate_ip("2001:db8::1")
    assert result["ip"] == "2001:db8::1"
    assert result["source"] == "geoip_simulated"


def test_geoip_service_investigate_ip_malformed():
    """Test investigate_ip with a malformed IP (covers ValueError branch)."""
    from openm.services.geoip_service import GeoIPService

    result = GeoIPService.investigate_ip("not.an.ip.address")
    assert result["ip"] == "not.an.ip.address"
    assert result["source"] == "geoip_simulated"


# ====================================================================
# WhoisService — additional coverage
# ====================================================================


def test_whois_service_extract_tld_two_part():
    """Test TLD extraction for two-part TLDs like co.uk, com.br."""
    from openm.services.whois_service import _extract_tld

    assert _extract_tld("example.co.uk") == "co.uk"
    assert _extract_tld("example.com.br") == "com.br"
    assert _extract_tld("example.org.uk") == "org.uk"
    assert _extract_tld("example.net.au") == "net.au"
    assert _extract_tld("example.gov.br") == "gov.br"
    assert _extract_tld("example.ac.uk") == "ac.uk"
    assert _extract_tld("example.sch.uk") == "sch.uk"
    assert _extract_tld("example.nom.br") == "nom.br"


def test_whois_service_rate_limit(monkeypatch):
    """Test _rate_limit enforces minimum interval between requests."""
    import time
    from openm.services.whois_service import _rate_limit, _last_request, _MIN_INTERVAL

    # Clear state
    _last_request.clear()

    # Mock time.time to control timing
    fake_time = [0.0]

    def mock_time():
        return fake_time[0]

    monkeypatch.setattr(time, "time", mock_time)

    # First call at t=0
    _rate_limit("whois.test.com")
    # Should not have slept

    # Second call at t=0.5 (< _MIN_INTERVAL)
    fake_time[0] = 0.5
    # Mock time.sleep to track calls
    sleep_calls = []

    def mock_sleep(s):
        sleep_calls.append(s)
        fake_time[0] += s

    monkeypatch.setattr(time, "sleep", mock_sleep)

    _rate_limit("whois.test.com")
    assert len(sleep_calls) == 1
    assert sleep_calls[0] >= _MIN_INTERVAL - 0.5


def test_whois_service_query_whois_raw_success(monkeypatch):
    """Test _query_whois_raw with a successful socket connection."""
    import socket
    from openm.services.whois_service import _query_whois_raw, _last_request

    # Clear rate limit state
    _last_request.clear()

    # Mock socket.create_connection
    class FakeSocket:
        def __init__(self, *args, **kwargs):
            self.sent_data = b""
            self._recv_count = 0

        def sendall(self, data):
            self.sent_data = data

        def recv(self, bufsize):
            self._recv_count += 1
            if self._recv_count == 1:
                return b"Fake WHOIS response data\n"
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: FakeSocket())

    result = _query_whois_raw("example.com", "whois.test.com")
    assert result == "Fake WHOIS response data\n"


def test_whois_service_query_whois_raw_timeout(monkeypatch):
    """Test _query_whois_raw when socket times out."""
    import socket
    from openm.services.whois_service import _query_whois_raw, _last_request

    _last_request.clear()

    class FakeTimeoutSocket:
        def __init__(self, *args, **kwargs):
            pass

        def sendall(self, data):
            pass

        def recv(self, bufsize):
            raise socket.timeout("timed out")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: FakeTimeoutSocket())

    result = _query_whois_raw("example.com", "whois.test.com")
    assert result == ""


def test_whois_service_query_whois_raw_connection_error(monkeypatch):
    """Test _query_whois_raw when connection is refused."""
    import socket
    from openm.services.whois_service import _query_whois_raw, _last_request

    _last_request.clear()

    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda addr, timeout: (_ for _ in ()).throw(ConnectionRefusedError("refused")),
    )

    result = _query_whois_raw("example.com", "whois.test.com")
    assert result is None


def test_whois_service_query_whois_raw_gaierror(monkeypatch):
    """Test _query_whois_raw when DNS resolution fails."""
    import socket
    from openm.services.whois_service import _query_whois_raw, _last_request

    _last_request.clear()

    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda addr, timeout: (_ for _ in ()).throw(socket.gaierror("no address")),
    )

    result = _query_whois_raw("example.com", "whois.invalid")
    assert result is None


def test_whois_service_extract_tld_single_part():
    """Test _extract_tld with a single-part domain (no dot)."""
    from openm.services.whois_service import _extract_tld

    assert _extract_tld("localhost") == ""
    assert _extract_tld("") == ""


def test_whois_service_parse_response_org_fallback():
    """Test _parse_whois_response when only generic Organization field is present."""
    from openm.services.whois_service import _parse_whois_response

    raw = """
    Domain Name: org-only.com
    Organization: Generic Org Inc.
    Registrar: Some Registrar
    """

    result = _parse_whois_response(raw, "org-only.com")
    assert result["registrant_org"] == "Generic Org Inc."
    assert result["registrar"] == "Some Registrar"


def test_whois_service_parse_response_no_contacts():
    """Test _parse_whois_response with no contact information."""
    from openm.services.whois_service import _parse_whois_response

    raw = """
    Domain Name: nocontacts.com
    Registrar: Bare Registrar
    Creation Date: 2022-01-01T00:00:00Z
    """

    result = _parse_whois_response(raw, "nocontacts.com")
    assert result["domain"] == "nocontacts.com"
    assert result["registrar"] == "Bare Registrar"
    assert result["creation_date"] == "2022-01-01T00:00:00Z"
    assert result["registrant_name"] is None
    assert result["registrant_email"] is None
    assert result["admin_email"] is None
    assert result["tech_email"] is None


def test_whois_service_investigate_domain_empty_response(monkeypatch):
    """Test investigate_domain when WHOIS returns empty string."""
    from openm.services.whois_service import WhoisService

    with patch(
        "openm.services.whois_service._query_whois_raw",
        return_value="",
    ):
        result = WhoisService.investigate_domain("empty-response.com")

    # Should fall back to simulated data
    assert result["source"] == "whois_simulated"
    assert result["registrar"] == "Example Registrar, Inc."


def test_whois_service_investigate_domain_no_meaningful_data(monkeypatch):
    """Test investigate_domain when WHOIS returns data with no meaningful fields."""
    from openm.services.whois_service import WhoisService

    with patch(
        "openm.services.whois_service._query_whois_raw",
        return_value="Domain Name: bare.com\n",
    ):
        result = WhoisService.investigate_domain("bare.com")

    # Should fall back to simulated data (no registrar, dates, nameservers, or contacts)
    assert result["source"] == "whois_simulated"


# ---------------------------------------------------------------------------
# Tests for registro.br WHOIS format parsing
# ---------------------------------------------------------------------------

MOCK_BR_WHOIS_RAW = """
% 2026-06-26 11:13:02 (BRT -03:00)
% This query returned 1 object

domain:      exemplo.br
owner:       D. M. I.
ownerid:     00.000.000/0001-00
responsible: Fulano de Tal
country:     BR
owner-c:     DEMI
admin-c:     DEMI
tech-c:      DEMI
nserver:     ns1.exemplo.br
nserver:     ns2.exemplo.br
e-mail:      demi@registro.br
created:     20000101 #123
changed:     20250625
expires:     20270101
status:      published
"""


def test_whois_service_parse_br_format():
    """Test _parse_whois_response with registro.br format."""
    from openm.services.whois_service import _parse_whois_response

    result = _parse_whois_response(MOCK_BR_WHOIS_RAW, "exemplo.br")

    assert result["domain"] == "exemplo.br"
    assert result["registrant_org"] == "D. M. I."
    assert result["registrant_name"] == "Fulano de Tal"
    assert result["registrant_email"] == "demi@registro.br"
    assert result["registrant_country"] == "BR"
    assert "ns1.exemplo.br" in result["nameservers"]
    assert "ns2.exemplo.br" in result["nameservers"]


def test_whois_service_parse_br_format_no_garbage():
    """Test that registro.br comment lines are NOT parsed as data."""
    from openm.services.whois_service import _parse_whois_response

    result = _parse_whois_response(MOCK_BR_WHOIS_RAW, "exemplo.br")

    # Ensure garbage lines are NOT captured as values
    assert result["registrant_org"] != "% This query returned 1 object"
    assert result["registrant_name"] != "% This query returned 1 object"
    assert result["registrant_org"] != "% 2026-06-26 11:13:02 (BRT -03:00)"
    assert result["registrant_name"] != "% 2026-06-26 11:13:02 (BRT -03:00)"


def test_is_garbage_value():
    """Test _is_garbage_value function."""
    from openm.services.whois_service import _is_garbage_value

    # Garbage values
    assert _is_garbage_value("") is True
    assert _is_garbage_value("   ") is True
    assert _is_garbage_value(None) is True
    assert _is_garbage_value("% This query returned 1 object") is True
    assert _is_garbage_value("% 2026-06-26 11:13:02 (BRT -03:00)") is True
    assert _is_garbage_value("this query returned 1 object") is True

    # Valid values
    assert _is_garbage_value("D. M. I.") is False
    assert _is_garbage_value("Fulano de Tal") is False
    assert _is_garbage_value("demi@registro.br") is False
    assert _is_garbage_value("BR") is False


def test_clean_value():
    """Test _clean_value function in WhoisTransform."""
    from openm.transforms.whois import _clean_value

    # Garbage → None
    assert _clean_value("") is None
    assert _clean_value("   ") is None
    assert _clean_value(None) is None
    assert _clean_value("% This query returned 1 object") is None
    assert _clean_value("% 2026-06-26 11:13:02 (BRT -03:00)") is None
    assert _clean_value("this query returned 1 object") is None

    # Valid values
    assert _clean_value("D. M. I.") == "D. M. I."
    assert _clean_value("Fulano de Tal") == "Fulano de Tal"
    assert _clean_value("demi@registro.br") == "demi@registro.br"
    assert _clean_value("BR") == "BR"
    assert _clean_value("  BR  ") == "BR"


def test_whois_transform_br_format():
    """Test WhoisTransform with registro.br WHOIS data."""
    from openm.transforms.whois import WhoisTransform
    from openm.services.whois_service import _parse_whois_response

    br_data = _parse_whois_response(MOCK_BR_WHOIS_RAW, "exemplo.br")
    br_data["source"] = "whois"

    domain = Domain(value="exemplo.br", properties={})
    transform = WhoisTransform()

    with patch(
        "openm.transforms.whois.WhoisService.investigate_domain",
        return_value=br_data,
    ):
        result = transform.run(domain)

    # Should have: 1 Domain + 1 registrant = 2 entities (no admin/tech/registrar in .br format)
    assert len(result.entities) >= 2

    # Check registrant Person
    person_entities = [e for e in result.entities if e.type == "Person"]
    registrant = [e for e in person_entities if e.properties.get("role") == "registrant"]
    assert len(registrant) == 1
    assert registrant[0].value == "Fulano de Tal"  # name preferred over org
    assert registrant[0].properties["email"] == "demi@registro.br"
    assert registrant[0].properties["organization"] == "D. M. I."
    assert registrant[0].properties["country"] == "BR"

    # Check relationship
    rel_types = [r["type"] for r in result.relationships]
    assert "REGISTERED_BY" in rel_types


# ====================================================================
# VirusTotal Transform
# ====================================================================

MOCK_VT_DOMAIN_FLAGGED = {
    "value": "example.com",
    "type": "Domain",
    "source": "virustotal",
    "available": True,
    "reputation": -41,
    "last_analysis_stats": {
        "malicious": 4,
        "suspicious": 1,
        "undetected": 9,
        "harmless": 83,
        "timeout": 0,
    },
    "flagged_by": [
        {"engine": "Kaspersky", "category": "malicious",
         "result": "malware site"},
        {"engine": "PhishTank", "category": "suspicious",
         "result": "phishing"},
        {"engine": "Sophos", "category": "malicious", "result": "Mal/Phish"},
    ],
    "checked_at": "2025-06-26T12:00:00+00:00",
}

MOCK_VT_DOMAIN_CLEAN = {
    "value": "clean.com",
    "type": "Domain",
    "source": "virustotal",
    "available": True,
    "reputation": 0,
    "last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 5,
        "harmless": 90, "timeout": 0,
    },
    "flagged_by": [],
    "checked_at": "2025-06-26T12:00:00+00:00",
}

MOCK_VT_NOT_FOUND = {
    "value": "missing.com",
    "type": "Domain",
    "source": "virustotal",
    "available": False,
    "reputation": None,
    "last_analysis_stats": None,
    "flagged_by": [],
    "checked_at": "2025-06-26T12:00:00+00:00",
}


def test_virustotal_transform_registered():
    """VirusTotalTransform deve aparecer em TransformRegistry.list_all()."""
    from openm.core.transform import TransformRegistry

    transforms = TransformRegistry.list_all()
    names = [t["name"] for t in transforms]
    assert "virustotal_lookup" in names

    # E em list_for_type para Domain e IPAddress
    for entity_type in ("Domain", "IPAddress"):
        compatible = TransformRegistry.list_for_type(entity_type)
        assert any(t["name"] == "virustotal_lookup" for t in compatible), (
            f"virustotal_lookup não disponível para {entity_type}"
        )


def test_virustotal_transform_with_flagged_engines():
    """Domain com 3 engines flagged → entidade enriquecida + 3 Devices + 3 edges."""
    from openm.transforms.virustotal import VirusTotalTransform

    domain = Domain(value="example.com", properties={})
    transform = VirusTotalTransform()

    with patch(
        "openm.transforms.virustotal.VirusTotalService.investigate_entity",
        return_value=MOCK_VT_DOMAIN_FLAGGED,
    ) as mock_investigate:
        result = transform.run(domain)

    # 1 Domain (enriquecida) + 3 Device (engines) = 4 entidades
    assert len(result.entities) == 4
    assert len(result.relationships) == 3

    # Edge type
    assert all(r["type"] == "FLAGGED_BY" for r in result.relationships)

    # Engines como Device com role=antivirus_engine
    device_entities = [e for e in result.entities if e.type == "Device"]
    assert len(device_entities) == 3
    engines = {e.value for e in device_entities}
    assert engines == {"Kaspersky", "PhishTank", "Sophos"}
    assert all(e.properties["role"] == "antivirus_engine" for e in device_entities)

    # Properties da entidade Domain
    domain_entity = [e for e in result.entities if e.type == "Domain"][0]
    assert domain_entity.properties["virustotal_reputation"] == -41
    assert domain_entity.properties["virustotal_malicious_count"] == 4
    assert domain_entity.properties["virustotal_suspicious_count"] == 1
    assert domain_entity.properties["virustotal_harmless_count"] == 83
    assert domain_entity.properties["virustotal_undetected_count"] == 9
    assert domain_entity.properties["virustotal_flagged"] is True
    assert domain_entity.properties["virustotal_available"] is True
    assert "virustotal_checked_at" in domain_entity.properties

    # Args da investigate_entity
    mock_investigate.assert_called_once_with("Domain", "example.com")


def test_virustotal_transform_clean_entity():
    """Domain sem flags → entidade enriquecida (sem Devices)."""
    from openm.transforms.virustotal import VirusTotalTransform

    domain = Domain(value="clean.com", properties={})
    transform = VirusTotalTransform()

    with patch(
        "openm.transforms.virustotal.VirusTotalService.investigate_entity",
        return_value=MOCK_VT_DOMAIN_CLEAN,
    ):
        result = transform.run(domain)

    # Apenas a Domain enriquecida — nenhum Device
    assert len(result.entities) == 1
    assert result.entities[0].type == "Domain"
    assert len(result.relationships) == 0

    domain_entity = result.entities[0]
    assert domain_entity.properties["virustotal_flagged"] is False
    assert domain_entity.properties["virustotal_malicious_count"] == 0
    assert domain_entity.properties["virustotal_suspicious_count"] == 0
    assert domain_entity.properties["virustotal_available"] is True


def test_virustotal_transform_no_data():
    """API retorna 404 → entidade anotada com virustotal_available=False,
    sem Devices/edges FLAGGED_BY."""
    from openm.transforms.virustotal import VirusTotalTransform

    domain = Domain(value="missing.com", properties={})
    transform = VirusTotalTransform()

    with patch(
        "openm.transforms.virustotal.VirusTotalService.investigate_entity",
        return_value=MOCK_VT_NOT_FOUND,
    ):
        result = transform.run(domain)

    # A entidade enriquecida é criada com flag de indisponibilidade
    assert len(result.entities) == 1
    assert len(result.relationships) == 0
    enriched = result.entities[0]
    assert enriched.type == "Domain"
    assert enriched.id == domain.id  # id preservado
    assert enriched.properties["virustotal_available"] is False
    assert enriched.properties["virustotal_flagged"] is False
    assert enriched.properties["virustotal_malicious_count"] == 0


def test_virustotal_transform_ip_input():
    """IPAddress → IPAddress enriquecida + edges (mesmo pattern do Domain)."""
    from openm.transforms.virustotal import VirusTotalTransform

    mock_ip = {
        "value": "1.1.1.1",
        "type": "IPAddress",
        "source": "virustotal",
        "available": True,
        "reputation": -22,
        "last_analysis_stats": {
            "malicious": 2, "suspicious": 0, "undetected": 15,
            "harmless": 70, "timeout": 0,
        },
        "flagged_by": [
            {"engine": "Kaspersky", "category": "malicious", "result": "C2"},
        ],
        "checked_at": "2025-06-26T12:00:00+00:00",
    }

    ip = IPAddress(value="1.1.1.1")
    transform = VirusTotalTransform()

    with patch(
        "openm.transforms.virustotal.VirusTotalService.investigate_entity",
        return_value=mock_ip,
    ) as mock_investigate:
        result = transform.run(ip)

    # 1 IPAddress enriquecida + 1 Device (Kaspersky) = 2 entidades
    assert len(result.entities) == 2
    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "FLAGGED_BY"

    ip_entity = [e for e in result.entities if e.type == "IPAddress"][0]
    assert ip_entity.properties["virustotal_malicious_count"] == 2
    assert ip_entity.properties["virustotal_flagged"] is True

    # Args corretos para IPAddress
    mock_investigate.assert_called_once_with("IPAddress", "1.1.1.1")


def test_virustotal_transform_preserves_entity_id():
    """A entidade enriquecida mantém o mesmo id da entidade original."""
    from openm.transforms.virustotal import VirusTotalTransform

    domain = Domain(value="example.com", properties={})
    transform = VirusTotalTransform()

    with patch(
        "openm.transforms.virustotal.VirusTotalService.investigate_entity",
        return_value=MOCK_VT_DOMAIN_FLAGGED,
    ):
        result = transform.run(domain)

    domain_entity = [e for e in result.entities if e.type == "Domain"][0]
    assert domain_entity.id == domain.id


def test_virustotal_transform_skips_invalid_type():
    """Email não é aceito (input_types=[Domain, IPAddress])."""
    from openm.transforms.virustotal import VirusTotalTransform

    email = Email(value="x@y.com")
    transform = VirusTotalTransform()
    result = transform.run(email)
    assert result.entities == []
    assert result.relationships == []


def test_virustotal_transform_investigate_called_with_correct_args():
    """Verifica args exatos passados para investigate_entity."""
    from openm.transforms.virustotal import VirusTotalTransform

    domain = Domain(value="foo.bar", properties={})
    transform = VirusTotalTransform()

    with patch(
        "openm.transforms.virustotal.VirusTotalService.investigate_entity",
        return_value=MOCK_VT_NOT_FOUND,
    ) as mock_investigate:
        transform.run(domain)

    mock_investigate.assert_called_once_with("Domain", "foo.bar")


def test_virustotal_transform_preserves_existing_properties():
    """Propriedades já existentes na entidade são preservadas."""
    from openm.transforms.virustotal import VirusTotalTransform

    domain = Domain(
        value="example.com",
        properties={"whois_registrar": "X", "geo_country": "US"},
    )
    transform = VirusTotalTransform()

    with patch(
        "openm.transforms.virustotal.VirusTotalService.investigate_entity",
        return_value=MOCK_VT_DOMAIN_FLAGGED,
    ):
        result = transform.run(domain)

    domain_entity = [e for e in result.entities if e.type == "Domain"][0]
    assert domain_entity.properties.get("whois_registrar") == "X"
    assert domain_entity.properties.get("geo_country") == "US"
    assert domain_entity.properties.get("virustotal_flagged") is True


def test_virustotal_transform_flagged_by_edge_properties():
    """Edges FLAGGED_BY carregam category/result/checked_at."""
    from openm.transforms.virustotal import VirusTotalTransform

    domain = Domain(value="example.com", properties={})
    transform = VirusTotalTransform()

    with patch(
        "openm.transforms.virustotal.VirusTotalService.investigate_entity",
        return_value=MOCK_VT_DOMAIN_FLAGGED,
    ):
        result = transform.run(domain)

    flagged_edges = [r for r in result.relationships if r["type"] == "FLAGGED_BY"]
    assert len(flagged_edges) == 3
    for edge in flagged_edges:
        assert "category" in edge["properties"]
        assert "result" in edge["properties"]
        assert "source" in edge["properties"]
        assert "checked_at" in edge["properties"]
        # from_id aponta para a entidade original
        assert edge["from_id"] == domain.id
