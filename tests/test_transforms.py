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
