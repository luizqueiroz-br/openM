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
    assert registrant[0].value == "Example Organization"

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
