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
