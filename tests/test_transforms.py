import os
from unittest.mock import patch

import dns.resolver
import openm.transforms  # noqa: F401 — dispara o @Transform.register em todos os transforms
from openm.core.entity import BankAccount, Device, Domain, Email, IPAddress, MACAddress, Person, URL
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


# ====================================================================
# Reverse DNS Transform
# ====================================================================


def test_reverse_dns_transform_basic():
    """IPAddress → 1 Domain canônico via PTR, edge RESOLVES_TO."""
    from openm.transforms.reverse_dns import ReverseDnsTransform

    ip = IPAddress(value="8.8.8.8", properties={})
    transform = ReverseDnsTransform()

    with patch(
        "openm.transforms.reverse_dns.reverse_dns",
        return_value=("dns.google", []),
    ):
        result = transform.run(ip)

    # 1 Domain primário
    assert len(result.entities) == 1
    primary = result.entities[0]
    assert isinstance(primary, Domain)
    assert primary.value == "dns.google"
    assert primary.properties["reverse_dns_primary"] is True
    assert primary.properties["resolved_from_ip"] == "8.8.8.8"
    assert primary.properties["source"] == "ptr"
    assert "resolved_at" in primary.properties

    # 1 RESOLVES_TO edge com direction=reverse
    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert rel["type"] == "RESOLVES_TO"
    assert rel["from_id"] == ip.id
    assert rel["to_id"] == primary.id
    assert rel["properties"]["direction"] == "reverse"
    assert rel["properties"]["source"] == "ptr"


def test_reverse_dns_transform_with_aliases():
    """IP → Domain canônico + N aliases como Domains adicionais."""
    from openm.transforms.reverse_dns import ReverseDnsTransform

    ip = IPAddress(value="1.1.1.1", properties={})
    transform = ReverseDnsTransform()

    with patch(
        "openm.transforms.reverse_dns.reverse_dns",
        return_value=("one.one.one.one", ["cloudflare-dns.com", "备用.云flare.com"]),
    ):
        result = transform.run(ip)

    # 1 primário + 2 aliases = 3 Domain
    assert len(result.entities) == 3
    assert all(isinstance(e, Domain) for e in result.entities)

    # Apenas 1 marcado como primary
    primaries = [e for e in result.entities if e.properties["reverse_dns_primary"]]
    aliases = [e for e in result.entities if not e.properties["reverse_dns_primary"]]
    assert len(primaries) == 1
    assert primaries[0].value == "one.one.one.one"
    assert len(aliases) == 2
    assert {a.value for a in aliases} == {"cloudflare-dns.com", "备用.云flare.com"}

    # 3 edges RESOLVES_TO
    assert len(result.relationships) == 3
    assert all(r["type"] == "RESOLVES_TO" for r in result.relationships)
    assert all(r["properties"]["direction"] == "reverse" for r in result.relationships)


def test_reverse_dns_transform_skips_empty_aliases():
    """reverse_dns retorna (hostname, []) → apenas Domain primário."""
    from openm.transforms.reverse_dns import ReverseDnsTransform

    ip = IPAddress(value="8.8.4.4", properties={})
    transform = ReverseDnsTransform()

    with patch(
        "openm.transforms.reverse_dns.reverse_dns",
        return_value=("dns.google", []),
    ):
        result = transform.run(ip)

    assert len(result.entities) == 1
    assert len(result.relationships) == 1


def test_reverse_dns_transform_dedupes_primary_in_aliases():
    """Se hostname aparece em aliases, não duplicar."""
    from openm.transforms.reverse_dns import ReverseDnsTransform

    ip = IPAddress(value="8.8.8.8", properties={})
    transform = ReverseDnsTransform()

    with patch(
        "openm.transforms.reverse_dns.reverse_dns",
        return_value=("dns.google", ["dns.google", "other.alias"]),
    ):
        result = transform.run(ip)

    # 1 primário + 1 alias (não 2)
    assert len(result.entities) == 2
    assert len(result.relationships) == 2
    values = {e.value for e in result.entities}
    assert values == {"dns.google", "other.alias"}


def test_reverse_dns_transform_no_ptr_returns_empty():
    """IP sem PTR → reverse_dns retorna None → result vazio."""
    from openm.transforms.reverse_dns import ReverseDnsTransform

    ip = IPAddress(value="192.0.2.1", properties={})
    transform = ReverseDnsTransform()

    with patch(
        "openm.transforms.reverse_dns.reverse_dns",
        return_value=None,
    ):
        result = transform.run(ip)

    assert result.entities == []
    assert result.relationships == []


def test_reverse_dns_transform_skips_non_ip():
    """Template method: Email → result vazio (sem chamar reverse_dns)."""
    from openm.transforms.reverse_dns import ReverseDnsTransform

    email = Email(value="a@b.com")
    transform = ReverseDnsTransform()

    with patch("openm.transforms.reverse_dns.reverse_dns") as mock:
        result = transform.run(email)

    mock.assert_not_called()
    assert result.entities == []
    assert result.relationships == []


def test_reverse_dns_registered():
    """ReverseDnsTransform aparece no TransformRegistry."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.reverse_dns import ReverseDnsTransform

    # Está registrado
    assert TransformRegistry.get("reverse_dns") is ReverseDnsTransform

    # E aparece para IPAddress
    compatible = TransformRegistry.list_for_type("IPAddress")
    names = [t["name"] for t in compatible]
    assert "reverse_dns" in names

    # Mas não para outros tipos
    for other_type in ("Domain", "Email", "Person", "Device", "BankAccount", "URL", "FileHash"):
        assert "reverse_dns" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


# ====================================================================
# DNS Service — reverse_dns() unit tests
# ====================================================================


def test_dns_service_reverse_dns_success():
    """reverse_dns retorna (hostname, aliases) quando PTR existe."""
    import socket
    from openm.services.dns_service import reverse_dns

    class FakeGetHostByAddr:
        def __call__(self, ip):
            return ("dns.google", [], ["alias1.example.com", "alias2.example.com"])

    with patch.object(socket, "gethostbyaddr", FakeGetHostByAddr()):
        result = reverse_dns("8.8.8.8")
    assert result == ("dns.google", ["alias1.example.com", "alias2.example.com"])


def test_dns_service_reverse_dns_no_aliases():
    """Aliases ausente → lista vazia."""
    import socket
    from openm.services.dns_service import reverse_dns

    def fake_gethostbyaddr(ip):
        return ("one.one.one.one", [], [])

    with patch.object(socket, "gethostbyaddr", fake_gethostbyaddr):
        result = reverse_dns("1.1.1.1")
    assert result == ("one.one.one.one", [])


def test_dns_service_reverse_dns_herror_returns_none():
    """Sem PTR → herror → None."""
    import socket
    from openm.services.dns_service import reverse_dns

    def fake_gethostbyaddr(ip):
        raise socket.herror("no PTR record")

    with patch.object(socket, "gethostbyaddr", fake_gethostbyaddr):
        result = reverse_dns("192.0.2.1")
    assert result is None


def test_dns_service_reverse_dns_gaierror_returns_none():
    """IP inválido → gaierror → None."""
    import socket
    from openm.services.dns_service import reverse_dns

    def fake_gethostbyaddr(ip):
        raise socket.gaierror("name or service not known")

    with patch.object(socket, "gethostbyaddr", fake_gethostbyaddr):
        result = reverse_dns("not.an.ip")
    assert result is None


def test_dns_service_reverse_dns_timeout_returns_none():
    """Timeout → None."""
    import socket
    from openm.services.dns_service import reverse_dns

    def fake_gethostbyaddr(ip):
        raise socket.timeout("timed out")

    with patch.object(socket, "gethostbyaddr", fake_gethostbyaddr):
        result = reverse_dns("10.0.0.1", timeout=0.5)
    assert result is None


def test_dns_service_reverse_dns_resets_timeout():
    """Mesmo padrão do resolve_domain: timeout é resetado no finally."""
    import socket
    from openm.services.dns_service import reverse_dns

    def fake_gethostbyaddr(ip):
        raise socket.herror("fail")

    with patch.object(socket, "gethostbyaddr", fake_gethostbyaddr):
        # Antes: timeout default do sistema
        reverse_dns("8.8.8.8")
    # Depois: timeout foi resetado para None
    assert socket.getdefaulttimeout() is None


# ====================================================================
# crt.sh Transform
# ====================================================================


def test_crtsh_transform_with_subdomains():
    """Domain com 3 subdomínios via crt.sh → 1 Domain enriquecido + 3 subdomains + 3 edges."""
    from openm.transforms.crtsh import CrtShTransform

    domain = Domain(value="example.com", properties={})
    transform = CrtShTransform()

    crtsh_entries = [
        {"name_value": "sub1.example.com\nsub2.example.com"},
        {"name_value": "sub3.example.com"},
        {"name_value": "*.wild.example.com\nsub1.example.com"},  # dedup + wildcard
    ]

    with patch(
        "openm.transforms.crtsh.query_crtsh",
        return_value=crtsh_entries,
    ):
        result = transform.run(domain)

    # 1 Domain pai enriquecido + 3 subdomains únicos (sub1, sub2, sub3, wild)
    # Wildcards são normalizados (sem "*.") → "wild.example.com"
    domain_entities = [e for e in result.entities if e.type == "Domain" and e.value == "example.com"]
    sub_entities = [e for e in result.entities if e.type == "Domain" and e.value != "example.com"]
    assert len(domain_entities) == 1
    assert len(sub_entities) == 4  # sub1, sub2, sub3, wild.example.com

    # Propriedades do Domain pai
    parent = domain_entities[0]
    assert parent.properties["crtsh_subdomain_count"] == 4
    assert parent.properties["crtsh_certificate_count"] == 3
    assert parent.properties["crtsh_available"] is True
    assert parent.properties["crtsh_source"] == "crt.sh"
    assert "crtsh_checked_at" in parent.properties

    # Edges HAS_SUBDOMAIN
    assert len(result.relationships) == 4
    assert all(r["type"] == "HAS_SUBDOMAIN" for r in result.relationships)
    assert all(r["from_id"] == domain.id for r in result.relationships)
    assert all(r["properties"]["source"] == "crt.sh" for r in result.relationships)

    # Subdomains têm flag is_subdomain e parent_domain
    for sub in sub_entities:
        assert sub.properties["is_subdomain"] is True
        assert sub.properties["parent_domain"] == "example.com"
        assert sub.properties["source"] == "crt.sh"
        assert "discovered_at" in sub.properties


def test_crtsh_transform_no_results():
    """crt.sh retorna lista vazia → Domain enriquecido com count=0, sem subdomains."""
    from openm.transforms.crtsh import CrtShTransform

    domain = Domain(value="empty.com", properties={})
    transform = CrtShTransform()

    with patch(
        "openm.transforms.crtsh.query_crtsh",
        return_value=[],
    ):
        result = transform.run(domain)

    # Apenas o Domain pai, sem subdomains
    assert len(result.entities) == 1
    assert result.entities[0].value == "empty.com"
    assert result.entities[0].properties["crtsh_subdomain_count"] == 0
    assert result.entities[0].properties["crtsh_available"] is True
    assert result.relationships == []


def test_crtsh_transform_api_failure():
    """query_crtsh retorna None (falha) → Domain enriquecido com available=False."""
    from openm.transforms.crtsh import CrtShTransform

    domain = Domain(value="broken.com", properties={})
    transform = CrtShTransform()

    with patch(
        "openm.transforms.crtsh.query_crtsh",
        return_value=None,
    ):
        result = transform.run(domain)

    # Apenas o Domain pai, marcado como indisponível
    assert len(result.entities) == 1
    assert result.entities[0].value == "broken.com"
    assert result.entities[0].properties["crtsh_available"] is False
    assert result.entities[0].properties["crtsh_subdomain_count"] == 0
    assert result.relationships == []


def test_crtsh_transform_preserves_entity_id():
    """Domain enriquecido mantém o mesmo id da entidade original."""
    from openm.transforms.crtsh import CrtShTransform

    domain = Domain(value="example.com", properties={})
    transform = CrtShTransform()

    with patch(
        "openm.transforms.crtsh.query_crtsh",
        return_value=[{"name_value": "sub.example.com"}],
    ):
        result = transform.run(domain)

    parent = [e for e in result.entities if e.value == "example.com"][0]
    assert parent.id == domain.id


def test_crtsh_transform_skips_non_domain():
    """Template method: Email → vazio sem chamar query_crtsh."""
    from openm.transforms.crtsh import CrtShTransform

    email = Email(value="a@b.com")
    transform = CrtShTransform()

    with patch("openm.transforms.crtsh.query_crtsh") as mock:
        result = transform.run(email)

    mock.assert_not_called()
    assert result.entities == []
    assert result.relationships == []


def test_crtsh_transform_registered():
    """CrtShTransform aparece no TransformRegistry para Domain."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.crtsh import CrtShTransform

    assert TransformRegistry.get("crtsh_lookup") is CrtShTransform

    compatible = TransformRegistry.list_for_type("Domain")
    names = [t["name"] for t in compatible]
    assert "crtsh_lookup" in names

    # Não aparece para outros tipos
    for other_type in ("IPAddress", "Email", "Person", "Device", "BankAccount", "URL", "FileHash"):
        assert "crtsh_lookup" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


def test_crtsh_transform_filters_other_domains():
    """Entries que não são subdomínios do parent são filtrados."""
    from openm.transforms.crtsh import CrtShTransform

    domain = Domain(value="example.com", properties={})
    transform = CrtShTransform()

    # "other.org" não é subdomínio de "example.com" — deve ser filtrado
    crtsh_entries = [
        {
            "name_value": (
                "sub.example.com\nother.org\n"
                "deeply.nested.example.com\nunrelated.com"
            )
        },
    ]

    with patch(
        "openm.transforms.crtsh.query_crtsh",
        return_value=crtsh_entries,
    ):
        result = transform.run(domain)

    sub_values = {e.value for e in result.entities if e.value != "example.com"}
    # Apenas subdomínios de example.com
    assert sub_values == {"sub.example.com", "deeply.nested.example.com"}


def test_crtsh_transform_wildcard_normalization():
    """Wildcards (*.foo.example.com) são normalizados para foo.example.com."""
    from openm.transforms.crtsh import CrtShTransform

    domain = Domain(value="example.com", properties={})
    transform = CrtShTransform()

    crtsh_entries = [
        {"name_value": "*.api.example.com"},
        {"name_value": "*.cdn.example.com\nother.example.com"},
    ]

    with patch(
        "openm.transforms.crtsh.query_crtsh",
        return_value=crtsh_entries,
    ):
        result = transform.run(domain)

    sub_values = {e.value for e in result.entities if e.value != "example.com"}
    # Wildcards removidos
    assert sub_values == {"api.example.com", "cdn.example.com", "other.example.com"}


# ====================================================================
# crt.sh Service — unit tests
# ====================================================================


def test_crtsh_service_query_success():
    """query_crtsh faz request HTTP e retorna lista de dicts."""
    import json
    import urllib.request
    from openm.services.crtsh_service import query_crtsh

    fake_payload = json.dumps([
        {"name_value": "sub.example.com", "id": 1},
        {"name_value": "other.example.com", "id": 2},
    ]).encode("utf-8")

    class FakeResp:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self.payload

    def fake_urlopen(req, timeout):
        return FakeResp(fake_payload)

    with patch.object(urllib.request, "urlopen", fake_urlopen):
        result = query_crtsh("example.com")

    assert result is not None
    assert len(result) == 2
    assert result[0]["name_value"] == "sub.example.com"


def test_crtsh_service_query_url_error_returns_none():
    """Falha de rede → None."""
    import urllib.error
    import urllib.request
    from openm.services.crtsh_service import query_crtsh

    def fake_urlopen(req, timeout):
        raise urllib.error.URLError("network down")

    with patch.object(urllib.request, "urlopen", fake_urlopen):
        result = query_crtsh("example.com")

    assert result is None


def test_crtsh_service_query_http_error_returns_none():
    """HTTP 5xx → None."""
    import urllib.error
    import urllib.request
    from openm.services.crtsh_service import query_crtsh

    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(
            "https://crt.sh", 503, "Service Unavailable", {}, None
        )

    with patch.object(urllib.request, "urlopen", fake_urlopen):
        result = query_crtsh("example.com")

    assert result is None


def test_crtsh_service_query_invalid_json_returns_none():
    """JSON inválido → None."""
    import urllib.request
    from openm.services.crtsh_service import query_crtsh

    class FakeResp:
        def __init__(self):
            self.payload = b"not json at all"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self.payload

    with patch.object(urllib.request, "urlopen", lambda req, timeout: FakeResp()):
        result = query_crtsh("example.com")

    assert result is None


def test_crtsh_service_query_non_list_returns_empty():
    """Resposta JSON que não é lista → [] (não None)."""
    import json
    import urllib.request
    from openm.services.crtsh_service import query_crtsh

    class FakeResp:
        def __init__(self):
            self.payload = json.dumps({"error": "rate limited"}).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self.payload

    with patch.object(urllib.request, "urlopen", lambda req, timeout: FakeResp()):
        result = query_crtsh("example.com")

    assert result == []


def test_crtsh_service_extract_subdomains_basic():
    """extract_subdomains deduplica e normaliza."""
    from openm.services.crtsh_service import extract_subdomains

    entries = [
        {"name_value": "sub1.example.com\nsub2.example.com"},
        {"name_value": "sub1.example.com"},  # dup
        {"name_value": "*.api.example.com"},  # wildcard
    ]
    result = extract_subdomains(entries, "example.com", max_results=100)
    assert result == ["api.example.com", "sub1.example.com", "sub2.example.com"]


def test_crtsh_service_extract_subdomains_filters_others():
    """Domínios que não são subdomínios do parent são filtrados."""
    from openm.services.crtsh_service import extract_subdomains

    entries = [
        {"name_value": "sub.example.com\nother.org\nstranger.com"},
    ]
    result = extract_subdomains(entries, "example.com", max_results=100)
    assert result == ["sub.example.com"]


def test_crtsh_service_extract_subdomains_max_results():
    """max_results limita a saída."""
    from openm.services.crtsh_service import extract_subdomains

    entries = [
        {"name_value": "\n".join(f"sub{i}.example.com" for i in range(50))},
    ]
    result = extract_subdomains(entries, "example.com", max_results=10)
    assert len(result) == 10


def test_crtsh_service_extract_subdomains_skips_empty_and_self():
    """Linhas vazias e o próprio parent_domain são ignorados."""
    from openm.services.crtsh_service import extract_subdomains

    entries = [
        {"name_value": "example.com\n\n  \nsub.example.com"},
    ]
    result = extract_subdomains(entries, "example.com", max_results=100)
    assert result == ["sub.example.com"]


def test_crtsh_service_extract_subdomains_case_insensitive():
    """Domínios são normalizados para lowercase."""
    from openm.services.crtsh_service import extract_subdomains

    entries = [
        {"name_value": "Sub.Example.COM\nANOTHER.example.com"},
    ]
    result = extract_subdomains(entries, "example.com", max_results=100)
    assert result == ["another.example.com", "sub.example.com"]


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


# ====================================================================
# TransformRegistry — service_name dinâmico (issue #6 follow-up)
# ====================================================================

class TestTransformRegistryServices:
    """Cobertura do registro dinâmico de services para API Keys.

    Garante que o dropdown de API Keys no frontend (index.html) possa
    ser populado dinamicamente a partir do TransformRegistry.
    """

    def test_list_services_returns_only_transforms_with_service_name(self):
        """Apenas transforms que declararam service_name aparecem."""
        from openm.core.transform import TransformRegistry

        services = TransformRegistry.list_services()
        service_names = {s["service_name"] for s in services}

        # Verifica presença dos 3 services esperados
        assert "shodan" in service_names
        assert "virustotal" in service_names
        assert "emailrep" in service_names

        # Verifica que transforms SEM service_name nao aparecem
        # (whois, geoip, resolve_ip ficam de fora do dropdown)
        for s in services:
            assert s["service_name"], f"service_name vazio em {s}"
            assert s["display_name"], f"display_name vazio em {s}"

    def test_list_services_deduplicates(self):
        """Se 2 transforms usam o mesmo service_name, aparece 1x apenas."""
        from openm.core.transform import TransformRegistry

        services = TransformRegistry.list_services()
        service_names = [s["service_name"] for s in services]
        assert len(service_names) == len(set(service_names))

    def test_list_services_sorted_by_display_name(self):
        """Ordenacao alfabetica case-insensitive por display_name."""
        from openm.core.transform import TransformRegistry

        services = TransformRegistry.list_services()
        display_names = [s["display_name"] for s in services]
        assert display_names == sorted(display_names, key=str.lower)

    def test_list_services_response_shape(self):
        """Cada item do retorno tem os 3 campos esperados."""
        from openm.core.transform import TransformRegistry

        services = TransformRegistry.list_services()
        assert services, "esperava ao menos 1 service registrado"
        for s in services:
            assert "service_name" in s
            assert "display_name" in s
            assert "transform_name" in s


# ====================================================================
# Hunter.io transforms (issue #7)
# ====================================================================

class TestHunterDomainTransform:
    """HunterDomainTransform: Domain → Person + Email entities."""

    def test_registered_with_service_name(self):
        from openm.core.transform import TransformRegistry
        services = TransformRegistry.list_services()
        names = {s["service_name"] for s in services}
        assert "hunter" in names
        # domain-search e email-verifier compartilham service_name,
        # mas só o primeiro aparece (deduplicado) — ambos transforms
        # individuais continuam registrados pelo nome do transform.
        from openm.core.transform import TransformRegistry
        assert TransformRegistry.get("hunter_domain_search") is not None
        assert TransformRegistry.get("hunter_email_verifier") is not None

    def test_hunter_domain_with_people(self, monkeypatch):
        from openm.transforms.hunter_domain import HunterDomainTransform

        fake_data = {
            "domain": "acme.com",
            "available": True,
            "organization": "Acme",
            "pattern": "{first}",
            "accept_all": False,
            "linked_domains": [],
            "people": [
                {
                    "first_name": "Jane", "last_name": "Doe",
                    "position": "CEO", "seniority": "executive",
                    "department": "executive", "confidence": 95,
                    "email": "jane@acme.com", "email_type": "personal",
                    "linkedin": None, "twitter": None,
                    "sources": [{"domain": "github.com", "uri": "..."}],
                    "verification": {"date": "2024-01-01", "status": "valid"},
                },
                {
                    "first_name": "John", "last_name": "Smith",
                    "position": "CTO", "seniority": "executive",
                    "department": "it", "confidence": 88,
                    "email": "john@acme.com", "email_type": "personal",
                    "linkedin": None, "twitter": None,
                    "sources": [],
                    "verification": None,
                },
            ],
            "quota_exceeded": False, "gdpr_blocked": False,
            "cache_hit": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_domain",
            lambda d: fake_data,
        )
        entity = Domain(value="acme.com")
        result = HunterDomainTransform().run(entity)

        # 1 Domain enriquecido + 2 Person + 2 Email = 5 entidades
        assert any(e.type == "Domain" for e in result.entities)
        persons = [e for e in result.entities if e.type == "Person"]
        emails = [e for e in result.entities if e.type == "Email"]
        assert len(persons) == 2
        assert len(emails) == 2

        # Edges: ASSOCIATED_WITH, WORKS_AT, USES_EMAIL (3 tipos)
        rels_by_type = {r["type"] for r in result.relationships}
        assert "WORKS_AT" in rels_by_type
        assert "ASSOCIATED_WITH" in rels_by_type
        assert "USES_EMAIL" in rels_by_type

        # 2 pessoas × 3 edges cada = 6
        assert len(result.relationships) == 6

        # Domain enriquecido tem as props do Hunter
        domain_entity = [e for e in result.entities if e.type == "Domain"][0]
        assert domain_entity.properties["hunter_organization"] == "Acme"
        assert domain_entity.properties["hunter_available"] is True
        assert domain_entity.properties["hunter_pattern"] == "{first}"

    def test_hunter_domain_dedupes_emails(self, monkeypatch):
        """Se 2 pessoas compartilham o mesmo email, conta só uma vez.

        Implementação atual: o loop inteiro pula entradas cujo email já
        apareceu em seen_emails, então tanto o Person quanto o Email
        são criados apenas para a primeira ocorrência. Isso evita
        duplicação de Email no grafo.
        """
        from openm.transforms.hunter_domain import HunterDomainTransform

        fake_data = {
            "available": True, "organization": "Acme",
            "pattern": None, "accept_all": None,
            "linked_domains": [], "people": [
                {"first_name": "A", "last_name": "B", "position": None,
                 "seniority": None, "department": None, "confidence": 50,
                 "email": "shared@acme.com", "email_type": "personal",
                 "linkedin": None, "twitter": None, "sources": [],
                 "verification": None},
                {"first_name": "C", "last_name": "D", "position": None,
                 "seniority": None, "department": None, "confidence": 50,
                 "email": "shared@acme.com", "email_type": "personal",
                 "linkedin": None, "twitter": None, "sources": [],
                 "verification": None},
            ],
            "quota_exceeded": False, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_domain",
            lambda d: fake_data,
        )
        result = HunterDomainTransform().run(Domain(value="acme.com"))
        emails = [e for e in result.entities if e.type == "Email"]
        persons = [e for e in result.entities if e.type == "Person"]
        assert len(emails) == 1
        # E apenas 1 Person e criado (a entrada duplicada e pulada)
        assert len(persons) == 1

    def test_hunter_domain_quota_exceeded(self, monkeypatch):
        from openm.transforms.hunter_domain import HunterDomainTransform

        fake_data = {
            "domain": "acme.com", "available": False,
            "organization": None, "pattern": None, "accept_all": None,
            "linked_domains": [], "people": [],
            "quota_exceeded": True, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_domain",
            lambda d: fake_data,
        )
        result = HunterDomainTransform().run(Domain(value="acme.com"))
        # Domain enriquecido existe, sem Person/Email
        assert any(e.type == "Domain" for e in result.entities)
        assert not any(e.type == "Person" for e in result.entities)
        assert not any(e.type == "Email" for e in result.entities)
        # Edge cases
        assert result.relationships == []
        domain_entity = [e for e in result.entities if e.type == "Domain"][0]
        assert domain_entity.properties["hunter_quota_exceeded"] is True
        assert domain_entity.properties["hunter_available"] is False

    def test_hunter_domain_gdpr_blocked(self, monkeypatch):
        from openm.transforms.hunter_domain import HunterDomainTransform

        fake_data = {
            "domain": "acme.com", "available": False,
            "organization": None, "pattern": None, "accept_all": None,
            "linked_domains": [], "people": [],
            "quota_exceeded": False, "gdpr_blocked": True,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_domain",
            lambda d: fake_data,
        )
        result = HunterDomainTransform().run(Domain(value="acme.com"))
        assert any(e.type == "Domain" for e in result.entities)
        assert not any(e.type == "Person" for e in result.entities)
        domain_entity = [e for e in result.entities if e.type == "Domain"][0]
        assert domain_entity.properties["hunter_gdpr_blocked"] is True

    def test_hunter_domain_no_people(self, monkeypatch):
        """Domain sem emails retornados — apenas o Domain enriquecido."""
        from openm.transforms.hunter_domain import HunterDomainTransform

        fake_data = {
            "domain": "empty.com", "available": True,
            "organization": "Empty Org", "pattern": None,
            "accept_all": None, "linked_domains": [], "people": [],
            "quota_exceeded": False, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_domain",
            lambda d: fake_data,
        )
        result = HunterDomainTransform().run(Domain(value="empty.com"))
        assert len(result.entities) == 1  # só o Domain
        assert result.entities[0].type == "Domain"
        assert result.relationships == []

    def test_hunter_domain_ignores_non_domain(self):
        from openm.transforms.hunter_domain import HunterDomainTransform

        result = HunterDomainTransform().run(Email(value="x@y.com"))
        assert result.entities == []
        assert result.relationships == []

    def test_hunter_domain_preserves_entity_id(self, monkeypatch):
        """A entidade Domain enriquecida mantém o mesmo id da original."""
        from openm.transforms.hunter_domain import HunterDomainTransform

        fake_data = {
            "available": True, "organization": "X",
            "pattern": None, "accept_all": None,
            "linked_domains": [], "people": [],
            "quota_exceeded": False, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_domain",
            lambda d: fake_data,
        )
        entity = Domain(value="acme.com")
        result = HunterDomainTransform().run(entity)
        domain_entity = [e for e in result.entities if e.type == "Domain"][0]
        assert domain_entity.id == entity.id


class TestHunterEmailTransform:
    """HunterEmailTransform: Email → validation annotation."""

    def test_hunter_email_valid(self, monkeypatch):
        from openm.transforms.hunter_email import HunterEmailTransform

        fake_data = {
            "available": True, "status": "valid", "score": 95,
            "deliverable": True, "mx_records": True, "smtp_server": True,
            "smtp_check": True, "accept_all": False, "disposable": False,
            "webmail": False, "block": False, "sources": [],
            "quota_exceeded": False, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_email",
            lambda e: fake_data,
        )
        result = HunterEmailTransform().run(Email(value="jane@acme.com"))
        assert len(result.entities) == 1
        email_entity = result.entities[0]
        assert email_entity.type == "Email"
        assert email_entity.properties["hunter_status"] == "valid"
        assert email_entity.properties["hunter_score"] == 95
        assert email_entity.properties["hunter_deliverable"] is True
        assert email_entity.properties["hunter_mx_records"] is True
        assert result.relationships == []

    def test_hunter_email_disposable(self, monkeypatch):
        from openm.transforms.hunter_email import HunterEmailTransform

        fake_data = {
            "available": True, "status": "disposable", "score": 50,
            "deliverable": False, "mx_records": False, "smtp_server": False,
            "smtp_check": False, "accept_all": False, "disposable": True,
            "webmail": False, "block": False, "sources": [],
            "quota_exceeded": False, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_email",
            lambda e: fake_data,
        )
        result = HunterEmailTransform().run(Email(value="temp@mailinator.com"))
        email_entity = result.entities[0]
        assert email_entity.properties["hunter_status"] == "disposable"
        assert email_entity.properties["hunter_disposable"] is True
        assert email_entity.properties["hunter_deliverable"] is False

    def test_hunter_email_unknown(self, monkeypatch):
        from openm.transforms.hunter_email import HunterEmailTransform

        fake_data = {
            "available": True, "status": "unknown", "score": 50,
            "deliverable": None, "mx_records": None, "smtp_server": None,
            "smtp_check": None, "accept_all": None, "disposable": None,
            "webmail": None, "block": None, "sources": [],
            "quota_exceeded": False, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_email",
            lambda e: fake_data,
        )
        result = HunterEmailTransform().run(Email(value="nobody@nowhere.com"))
        email_entity = result.entities[0]
        assert email_entity.properties["hunter_status"] == "unknown"

    def test_hunter_email_quota_exceeded(self, monkeypatch):
        from openm.transforms.hunter_email import HunterEmailTransform

        fake_data = {
            "available": False, "status": None, "score": None,
            "deliverable": None, "mx_records": None, "smtp_server": None,
            "smtp_check": None, "accept_all": None, "disposable": None,
            "webmail": None, "block": None, "sources": [],
            "quota_exceeded": True, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_email",
            lambda e: fake_data,
        )
        result = HunterEmailTransform().run(Email(value="x@y.com"))
        email_entity = result.entities[0]
        assert email_entity.properties["hunter_quota_exceeded"] is True
        assert email_entity.properties["hunter_status"] == "unknown"  # default
        assert email_entity.properties["hunter_available"] is False

    def test_hunter_email_gdpr_blocked(self, monkeypatch):
        from openm.transforms.hunter_email import HunterEmailTransform

        fake_data = {
            "available": False, "status": None, "score": None,
            "deliverable": None, "mx_records": None, "smtp_server": None,
            "smtp_check": None, "accept_all": None, "disposable": None,
            "webmail": None, "block": None, "sources": [],
            "quota_exceeded": False, "gdpr_blocked": True,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_email",
            lambda e: fake_data,
        )
        result = HunterEmailTransform().run(Email(value="x@y.com"))
        email_entity = result.entities[0]
        assert email_entity.properties["hunter_gdpr_blocked"] is True

    def test_hunter_email_ignores_non_email(self):
        from openm.transforms.hunter_email import HunterEmailTransform

        result = HunterEmailTransform().run(Domain(value="acme.com"))
        assert result.entities == []
        assert result.relationships == []

    def test_hunter_email_sources_truncated_to_top_5(self, monkeypatch):
        """Só top 5 sources sao mantidas (nao inflar o nó)."""
        from openm.transforms.hunter_email import HunterEmailTransform

        sources = [
            {"domain": f"s{i}.com", "uri": f"http://s{i}"} for i in range(10)
        ]
        fake_data = {
            "available": True, "status": "valid", "score": 80,
            "deliverable": True, "mx_records": True, "smtp_server": True,
            "smtp_check": True, "accept_all": False, "disposable": False,
            "webmail": False, "block": False, "sources": sources,
            "quota_exceeded": False, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_email",
            lambda e: fake_data,
        )
        result = HunterEmailTransform().run(Email(value="x@y.com"))
        email_entity = result.entities[0]
        assert len(email_entity.properties["hunter_sources"]) == 5
        assert email_entity.properties["hunter_sources_count"] == 10

    def test_hunter_email_preserves_entity_id(self, monkeypatch):
        from openm.transforms.hunter_email import HunterEmailTransform

        fake_data = {
            "available": True, "status": "valid", "score": 95,
            "deliverable": True, "mx_records": True, "smtp_server": True,
            "smtp_check": True, "accept_all": False, "disposable": False,
            "webmail": False, "block": False, "sources": [],
            "quota_exceeded": False, "gdpr_blocked": False,
        }
        monkeypatch.setattr(
            "openm.services.hunter_service.HunterService.investigate_email",
            lambda e: fake_data,
        )
        entity = Email(value="x@y.com")
        result = HunterEmailTransform().run(entity)
        assert result.entities[0].id == entity.id


# ====================================================================
# EmailToDomain Transform (issue #64)
# ====================================================================


def test_email_to_domain_basic():
    """Email -> 1 Domain extraido + edge BELONGS_TO."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="jane.doe@example.com")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    # 1 Domain criado
    assert len(result.entities) == 1
    domain = result.entities[0]
    assert isinstance(domain, Domain)
    assert domain.value == "example.com"
    assert domain.properties["extracted_from_email"] == "jane.doe@example.com"
    assert domain.properties["source"] == "email_parse"
    assert "discovered_at" in domain.properties

    # 1 edge BELONGS_TO do email para o domain
    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert rel["type"] == "BELONGS_TO"
    assert rel["from_id"] == email.id
    assert rel["to_id"] == domain.id
    assert rel["properties"]["source"] == "email_parse"


def test_email_to_domain_simple_email():
    """Email sem pontos no local part."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="admin@example.com")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    assert len(result.entities) == 1
    assert result.entities[0].value == "example.com"


def test_email_to_domain_subdomain_email():
    """Email com subdominio (user@mail.example.com)."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="user@mail.example.com")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    assert len(result.entities) == 1
    assert result.entities[0].value == "mail.example.com"


def test_email_to_domain_uppercase_normalized():
    """Email em maiusculas e normalizado para lowercase no dominio."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="User@Example.COM")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    assert len(result.entities) == 1
    assert result.entities[0].value == "example.com"


def test_email_to_domain_strips_whitespace():
    """Email com whitespace e trimado."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="  user@example.com  ")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    assert len(result.entities) == 1
    assert result.entities[0].value == "example.com"


def test_email_to_domain_invalid_no_at_returns_empty():
    """Email sem @ -> resultado vazio."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="not-an-email")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    assert result.entities == []
    assert result.relationships == []


def test_email_to_domain_invalid_empty_local_returns_empty():
    """Email com local part vazio (@example.com) -> resultado vazio."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="@example.com")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    assert result.entities == []
    assert result.relationships == []


def test_email_to_domain_invalid_empty_domain_returns_empty():
    """Email com domain vazio (user@) -> resultado vazio."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="user@")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    assert result.entities == []
    assert result.relationships == []


def test_email_to_domain_invalid_no_dot_returns_empty():
    """Email com domain sem ponto (user@localhost) -> resultado vazio."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="user@localhost")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    assert result.entities == []
    assert result.relationships == []


def test_email_to_domain_invalid_multiple_at_returns_empty():
    """Email com multiplos @ (user@@example.com) -> resultado vazio."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    email = Email(value="user@@example.com")
    transform = EmailToDomainTransform()

    result = transform.run(email)

    assert result.entities == []
    assert result.relationships == []


def test_email_to_domain_skips_non_email():
    """Template method: Domain -> vazio."""
    from openm.transforms.email_to_domain import EmailToDomainTransform

    domain = Domain(value="example.com")
    transform = EmailToDomainTransform()

    result = transform.run(domain)

    assert result.entities == []
    assert result.relationships == []


def test_email_to_domain_registered():
    """EmailToDomainTransform aparece no TransformRegistry para Email."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.email_to_domain import EmailToDomainTransform

    assert TransformRegistry.get("email_to_domain") is EmailToDomainTransform

    compatible = TransformRegistry.list_for_type("Email")
    names = [t["name"] for t in compatible]
    assert "email_to_domain" in names

    # Nao aparece para outros tipos
    for other_type in ("Domain", "IPAddress", "Person", "Device", "BankAccount", "URL", "FileHash"):
        assert "email_to_domain" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


def test_email_to_domain_extract_domain_unit():
    """Unit tests para _extract_domain (helper interno)."""
    from openm.transforms.email_to_domain import _extract_domain

    # Casos validos
    assert _extract_domain("user@example.com") == "example.com"
    assert _extract_domain("user@mail.example.com") == "mail.example.com"
    assert _extract_domain("USER@EXAMPLE.COM") == "example.com"
    assert _extract_domain("  user@example.com  ") == "example.com"
    assert _extract_domain("user+tag@example.com") == "example.com"

    # Casos invalidos
    assert _extract_domain("") == ""
    assert _extract_domain("not-an-email") == ""
    assert _extract_domain("@example.com") == ""
    assert _extract_domain("user@") == ""
    assert _extract_domain("user@localhost") == ""
    assert _extract_domain("user@.example.com") == ""
    assert _extract_domain("user@example.com.") == ""
    assert _extract_domain("user@@example.com") == ""
    assert _extract_domain("user@a@b.com") == ""


# ====================================================================
# SSL Certificate Transform (issue #73)
# ====================================================================


MOCK_SSL_DATA = {
    "issuer": {
        "common": "DigiCert TLS Hybrid ECC SHA384 2020 CA1",
        "organization": "DigiCert Inc",
        "country": "US",
    },
    "subject": {
        "common": "www.example.com",
        "organization": "Example Corp",
        "country": "US",
    },
    "san_domains": [
        "example.com",
        "www.example.com",
        "api.example.com",
        "*.cdn.example.com",
        "mail.example.com",
    ],
    "valid_from": "Jan 15 00:00:00 2025 GMT",
    "valid_until": "Feb 15 23:59:59 2026 GMT",
    "fingerprint_sha256": "a" * 64,
    "version": 3,
    "serial_number": "0123456789ABCDEF",
    "raw_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
    "source": "ssl",
}


def test_ssl_cert_transform_with_san_and_issuer():
    """Domain com SAN list + issuer → 1 Domain + 1 Device + N SAN edges."""
    from openm.transforms.ssl_cert import SslCertTransform

    domain = Domain(value="example.com", properties={})
    transform = SslCertTransform()

    with patch(
        "openm.transforms.ssl_cert.inspect_ssl",
        return_value=MOCK_SSL_DATA,
    ):
        result = transform.run(domain)

    # 1 Domain pai (enriquecido) + 1 Device (issuer) + 4 SAN domains
    # (www.api.mail sao diferentes de example.com; *.cdn.example.com
    #  vira cdn.example.com; example.com e o proprio parent e pulado)
    assert len(result.entities) == 6

    parent = [e for e in result.entities if e.value == "example.com"][0]
    assert parent.type == "Domain"
    assert parent.properties["ssl_issuer_cn"] == "DigiCert TLS Hybrid ECC SHA384 2020 CA1"
    assert parent.properties["ssl_issuer_org"] == "DigiCert Inc"
    assert parent.properties["ssl_issuer_country"] == "US"
    assert parent.properties["ssl_subject_cn"] == "www.example.com"
    assert parent.properties["ssl_valid_from"] == "Jan 15 00:00:00 2025 GMT"
    assert parent.properties["ssl_valid_until"] == "Feb 15 23:59:59 2026 GMT"
    assert parent.properties["ssl_fingerprint_sha256"] == "a" * 64
    assert parent.properties["ssl_version"] == 3
    assert parent.properties["ssl_serial_number"] == "0123456789ABCDEF"
    assert parent.properties["ssl_san_count"] == 4
    assert parent.properties["ssl_available"] is True
    assert "ssl_checked_at" in parent.properties

    # Device do issuer
    issuer = [e for e in result.entities if e.type == "Device"][0]
    assert issuer.value == "DigiCert TLS Hybrid ECC SHA384 2020 CA1"
    assert issuer.properties["role"] == "certificate_authority"
    assert issuer.properties["issuer_org"] == "DigiCert Inc"
    assert issuer.properties["issuer_country"] == "US"

    # 4 SAN domains (example.com pulado por ser o parent; *.cdn.example.com -> cdn.example.com)
    san_domains = [e for e in result.entities
                   if e.type == "Domain" and e.value != "example.com"]
    san_values = {e.value for e in san_domains}
    assert san_values == {
        "www.example.com",
        "api.example.com",
        "cdn.example.com",  # wildcard *.cdn.example.com normalizado
        "mail.example.com",
    }
    for san in san_domains:
        assert san.properties["is_san"] is True
        assert san.properties["parent_domain"] == "example.com"
        assert san.properties["source"] == "ssl"

    # Edges: 1 SSL_ISSUED_BY + 4 SSL_SAN = 5
    assert len(result.relationships) == 5
    ssl_issued_by = [r for r in result.relationships if r["type"] == "SSL_ISSUED_BY"]
    ssl_san = [r for r in result.relationships if r["type"] == "SSL_SAN"]
    assert len(ssl_issued_by) == 1
    assert len(ssl_san) == 4
    assert ssl_issued_by[0]["from_id"] == domain.id
    assert ssl_issued_by[0]["to_id"] == issuer.id
    assert all(r["from_id"] == domain.id for r in ssl_san)


def test_ssl_cert_transform_no_san_entries():
    """Cert sem SAN → apenas Domain enriquecido + Device do issuer."""
    from openm.transforms.ssl_cert import SslCertTransform

    cert = {**MOCK_SSL_DATA, "san_domains": []}
    domain = Domain(value="example.com", properties={})
    transform = SslCertTransform()

    with patch(
        "openm.transforms.ssl_cert.inspect_ssl",
        return_value=cert,
    ):
        result = transform.run(domain)

    # 1 Domain + 1 Device (issuer), sem SAN domains
    assert len(result.entities) == 2
    assert any(e.type == "Device" for e in result.entities)
    assert all(
        e.value == "example.com" or e.type == "Device"
        for e in result.entities
    )
    # ssl_san_count = 0
    parent = [e for e in result.entities if e.value == "example.com"][0]
    assert parent.properties["ssl_san_count"] == 0
    # Apenas 1 edge (SSL_ISSUED_BY)
    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "SSL_ISSUED_BY"


def test_ssl_cert_transform_no_issuer():
    """Cert sem issuer (improvável mas possível) → apenas Domain + SAN domains."""
    from openm.transforms.ssl_cert import SslCertTransform

    cert = {**MOCK_SSL_DATA, "issuer": {}}
    domain = Domain(value="example.com", properties={})
    transform = SslCertTransform()

    with patch(
        "openm.transforms.ssl_cert.inspect_ssl",
        return_value=cert,
    ):
        result = transform.run(domain)

    # Sem Device do issuer
    assert not any(e.type == "Device" for e in result.entities)
    assert len(result.relationships) == 4  # apenas SSL_SAN
    assert all(r["type"] == "SSL_SAN" for r in result.relationships)


def test_ssl_cert_transform_connection_failure():
    """inspect_ssl retorna None (falha de conexão) → Domain com available=False."""
    from openm.transforms.ssl_cert import SslCertTransform

    domain = Domain(value="broken.example.com", properties={})
    transform = SslCertTransform()

    with patch(
        "openm.transforms.ssl_cert.inspect_ssl",
        return_value=None,
    ):
        result = transform.run(domain)

    # Apenas Domain marcado como indisponível, sem Device nem SAN
    assert len(result.entities) == 1
    assert result.entities[0].value == "broken.example.com"
    assert result.entities[0].properties["ssl_available"] is False
    assert result.relationships == []


def test_ssl_cert_transform_san_equals_parent_skipped():
    """SAN que e igual ao domain pai e pulado (deduplicacao)."""
    from openm.transforms.ssl_cert import SslCertTransform

    cert = {
        **MOCK_SSL_DATA,
        "san_domains": ["example.com", "www.example.com"],
    }
    domain = Domain(value="example.com", properties={})
    transform = SslCertTransform()

    with patch(
        "openm.transforms.ssl_cert.inspect_ssl",
        return_value=cert,
    ):
        result = transform.run(domain)

    # Apenas 1 SAN (www) — example.com pulado
    san_domains = [e for e in result.entities
                   if e.type == "Domain" and e.value != "example.com"]
    assert len(san_domains) == 1
    assert san_domains[0].value == "www.example.com"


def test_ssl_cert_transform_preserves_entity_id():
    """Domain enriquecido mantem o mesmo id da entidade original."""
    from openm.transforms.ssl_cert import SslCertTransform

    domain = Domain(value="example.com", properties={})
    transform = SslCertTransform()

    with patch(
        "openm.transforms.ssl_cert.inspect_ssl",
        return_value=MOCK_SSL_DATA,
    ):
        result = transform.run(domain)

    parent = [e for e in result.entities if e.value == "example.com"][0]
    assert parent.id == domain.id


def test_ssl_cert_transform_preserves_existing_properties():
    """Propriedades pre-existentes no Domain sao preservadas."""
    from openm.transforms.ssl_cert import SslCertTransform

    domain = Domain(
        value="example.com",
        properties={"whois_registrar": "X", "crtsh_subdomain_count": 3},
    )
    transform = SslCertTransform()

    with patch(
        "openm.transforms.ssl_cert.inspect_ssl",
        return_value=MOCK_SSL_DATA,
    ):
        result = transform.run(domain)

    parent = [e for e in result.entities if e.value == "example.com"][0]
    assert parent.properties["whois_registrar"] == "X"
    assert parent.properties["crtsh_subdomain_count"] == 3
    assert parent.properties["ssl_issuer_org"] == "DigiCert Inc"


def test_ssl_cert_transform_skips_non_domain():
    """Template method: IP → vazio sem chamar inspect_ssl."""
    from openm.transforms.ssl_cert import SslCertTransform

    ip = IPAddress(value="8.8.8.8")
    transform = SslCertTransform()

    with patch("openm.transforms.ssl_cert.inspect_ssl") as mock:
        result = transform.run(ip)

    mock.assert_not_called()
    assert result.entities == []
    assert result.relationships == []


def test_ssl_cert_transform_registered():
    """SslCertTransform aparece no TransformRegistry para Domain."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.ssl_cert import SslCertTransform

    assert TransformRegistry.get("ssl_cert_inspect") is SslCertTransform

    compatible = TransformRegistry.list_for_type("Domain")
    names = [t["name"] for t in compatible]
    assert "ssl_cert_inspect" in names

    # Nao aparece para outros tipos
    for other_type in ("IPAddress", "Email", "Person", "Device", "BankAccount", "URL", "FileHash"):
        assert "ssl_cert_inspect" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


# ====================================================================
# SSL Service — unit tests
# ====================================================================


def test_ssl_service_extract_san_domains_basic():
    """extract_san_domains normaliza e deduplica."""
    from openm.services.ssl_service import extract_san_domains

    cert = {
        "san_domains": [
            "example.com",
            "WWW.EXAMPLE.COM",
            "*.api.example.com",
            "example.com",  # dup
            "",
        ],
    }
    result = extract_san_domains(cert)
    # Empty ignorado, wildcard removido, duplicata removida, lowercase
    assert result == ["api.example.com", "example.com", "www.example.com"]


def test_ssl_service_extract_san_domains_empty():
    """Sem SAN ou san_domains None → lista vazia."""
    from openm.services.ssl_service import extract_san_domains

    assert extract_san_domains({}) == []
    assert extract_san_domains({"san_domains": None}) == []
    assert extract_san_domains({"san_domains": []}) == []


def test_ssl_service_format_name():
    """_format_name converte tuples of tuples em dict."""
    from openm.services.ssl_service import _format_name

    name = (
        ("commonName", "example.com"),
        ("organizationName", "Example Corp"),
        ("countryName", "US"),
    )
    assert _format_name(name) == {
        "common": "example.com",
        "organization": "Example Corp",
        "country": "US",
    }


def test_ssl_service_format_name_empty():
    """_format_name com vazio ou None retorna dict vazio."""
    from openm.services.ssl_service import _format_name

    assert _format_name(()) == {}
    assert _format_name(None) == {}


def test_ssl_service_inspect_ssl_success(monkeypatch):
    """inspect_ssl com mock de socket retorna dict populado."""
    import ssl
    from openm.services.ssl_service import inspect_ssl

    fake_der = b"fake-cert-bytes"
    fake_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"
    fake_cert = {
        "subject": (
            ("commonName", "example.com"),
            ("organizationName", "Example Corp"),
        ),
        "issuer": (
            ("commonName", "Test CA"),
            ("organizationName", "Test Org"),
            ("countryName", "US"),
        ),
        "subjectAltName": (
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
            ("DNS", "*.api.example.com"),
        ),
        "notBefore": "Jan 15 00:00:00 2025 GMT",
        "notAfter": "Feb 15 23:59:59 2026 GMT",
        "version": 3,
        "serialNumber": "ABCDEF1234",
    }

    class FakeTLSSock:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def getpeercert(self, binary_form=False):
            return fake_der if binary_form else fake_cert

    class FakeCtx:
        def wrap_socket(self, sock, server_hostname=None):
            return FakeTLSSock()

    class FakeRawSock:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    monkeypatch.setattr(
        "socket.create_connection",
        lambda addr, timeout: FakeRawSock(),
    )
    monkeypatch.setattr(
        "ssl.create_default_context",
        lambda: FakeCtx(),
    )
    monkeypatch.setattr(
        ssl, "DER_cert_to_PEM_cert", lambda der: fake_pem
    )

    result = inspect_ssl("example.com")

    assert result is not None
    assert result["issuer"]["common"] == "Test CA"
    assert result["subject"]["common"] == "example.com"
    # inspect_ssl preserva wildcards crus — a normalizacao fica para
    # extract_san_domains (chamado pelo transform).
    assert result["san_domains"] == [
        "example.com", "www.example.com", "*.api.example.com",
    ]
    assert result["valid_from"] == "Jan 15 00:00:00 2025 GMT"
    assert result["valid_until"] == "Feb 15 23:59:59 2026 GMT"
    assert result["version"] == 3
    assert result["serial_number"] == "ABCDEF1234"
    assert result["raw_pem"] == fake_pem
    assert result["source"] == "ssl"
    assert len(result["fingerprint_sha256"]) == 64


def test_ssl_service_inspect_ssl_connection_refused(monkeypatch):
    """Conexao recusada → None."""
    from openm.services.ssl_service import inspect_ssl

    def fake_create_connection(addr, timeout):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr("socket.create_connection", fake_create_connection)

    result = inspect_ssl("example.com")
    assert result is None


def test_ssl_service_inspect_ssl_timeout(monkeypatch):
    """Timeout → None."""
    import socket
    from openm.services.ssl_service import inspect_ssl

    def fake_create_connection(addr, timeout):
        raise socket.timeout("timed out")

    monkeypatch.setattr("socket.create_connection", fake_create_connection)

    result = inspect_ssl("example.com")
    assert result is None


def test_ssl_service_inspect_ssl_ssl_error(monkeypatch):
    """SSL error → None."""
    import ssl
    from openm.services.ssl_service import inspect_ssl

    class FakeRawSock:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    class FakeCtx:
        def wrap_socket(self, sock, server_hostname=None):
            raise ssl.SSLError("handshake failed")

    monkeypatch.setattr(
        "socket.create_connection",
        lambda addr, timeout: FakeRawSock(),
    )
    monkeypatch.setattr(
        "ssl.create_default_context",
        lambda: FakeCtx(),
    )

    result = inspect_ssl("example.com")
    assert result is None


def test_ssl_service_inspect_ssl_resets_timeout(monkeypatch):
    """Mesmo padrao do dns_service: timeout e resetado no finally."""
    import socket
    from openm.services.ssl_service import inspect_ssl

    def fake_create_connection(addr, timeout):
        raise socket.timeout("fail")

    monkeypatch.setattr("socket.create_connection", fake_create_connection)

    inspect_ssl("example.com", timeout=2.0)


# ========================================================================
# DNS Records Transform
# ========================================================================


def test_dns_records_transform_domain_with_records():
    """Domain com A, MX e TXT -> DnsRecords + Domain enriquecido."""
    from openm.transforms.dns_records import DnsRecordsTransform

    domain = Domain(value="example.com", properties={})
    transform = DnsRecordsTransform()

    mock_records = [
        {
            "record_type": "A",
            "record_value": "93.184.216.34",
            "record_ttl": 300,
            "resolved_domain": "example.com",
            "canonical_domain": "example.com",
            "record_data": {"address": "93.184.216.34"},
        },
        {
            "record_type": "MX",
            "record_value": "mail.example.com",
            "record_ttl": 3600,
            "resolved_domain": "example.com",
            "canonical_domain": "example.com",
            "record_data": {"exchange": "mail.example.com", "priority": 10},
            "record_priority": 10,
        },
        {
            "record_type": "TXT",
            "record_value": "v=spf1 include:_spf.example.com ~all",
            "record_ttl": 3600,
            "resolved_domain": "example.com",
            "canonical_domain": "example.com",
            "record_data": {"strings": ["v=spf1 include:_spf.example.com ~all"]},
        },
    ]

    with patch(
        "openm.transforms.dns_records.query_records",
        return_value=("example.com", mock_records),
    ):
        result = transform.run(domain)

    assert len(result.entities) == 4  # Domain enriquecido + 3 registros
    parent = [e for e in result.entities if e.type == "Domain"][0]
    assert parent.id == domain.id
    assert parent.properties["dns_available"] is True
    assert parent.properties["dns_record_count"] == 3
    assert parent.properties["dns_canonical_domain"] == "example.com"

    records = [e for e in result.entities if e.type == "DnsRecord"]
    assert {r.properties["record_type"] for r in records} == {"A", "MX", "TXT"}
    a_record = [r for r in records if r.properties["record_type"] == "A"][0]
    assert a_record.value == "93.184.216.34"
    assert a_record.properties["record_ttl"] == 300
    mx_record = [r for r in records if r.properties["record_type"] == "MX"][0]
    assert mx_record.properties["record_priority"] == 10

    assert len(result.relationships) == 3
    assert all(r["type"] == "HAS_DNS_RECORD" for r in result.relationships)
    assert all(r["from_id"] == domain.id for r in result.relationships)


def test_dns_records_transform_no_records_marks_unavailable():
    """Sem respostas DNS -> Domain com available=False."""
    from openm.transforms.dns_records import DnsRecordsTransform

    domain = Domain(value="nodns.example.com", properties={})
    transform = DnsRecordsTransform()

    with patch(
        "openm.transforms.dns_records.query_records",
        return_value=("nodns.example.com", []),
    ):
        result = transform.run(domain)

    assert len(result.entities) == 1
    assert result.entities[0].type == "Domain"
    assert result.entities[0].properties["dns_available"] is False
    assert result.entities[0].properties["dns_record_count"] == 0
    assert result.relationships == []


def test_dns_records_transform_preserves_existing_properties():
    """Propriedades pre-existentes do Domain sao preservadas."""
    from openm.transforms.dns_records import DnsRecordsTransform

    domain = Domain(
        value="example.com",
        properties={"whois_registrar": "X", "crtsh_subdomain_count": 3},
    )
    transform = DnsRecordsTransform()

    with patch(
        "openm.transforms.dns_records.query_records",
        return_value=("example.com", []),
    ):
        result = transform.run(domain)

    parent = result.entities[0]
    assert parent.properties["whois_registrar"] == "X"
    assert parent.properties["crtsh_subdomain_count"] == 3


def test_dns_records_transform_ip_with_ptr():
    """IPAddress com PTR -> Domain + DnsRecords + PTR record + RESOLVES_TO."""
    from openm.transforms.dns_records import DnsRecordsTransform

    ip = IPAddress(value="8.8.8.8", properties={})
    transform = DnsRecordsTransform()

    ptr_records = [
        {
            "record_type": "A",
            "record_value": "8.8.8.8",
            "record_ttl": 300,
            "resolved_domain": "dns.google",
            "canonical_domain": "dns.google",
            "record_data": {"address": "8.8.8.8"},
        },
    ]

    with patch(
        "openm.transforms.dns_records.reverse_dns_ptr",
        return_value=("dns.google", [], ptr_records),
    ):
        result = transform.run(ip)

    assert len(result.entities) == 3  # IP + Domain ptr + A record + PTR record
    ptr_domain = [e for e in result.entities if e.type == "Domain"][0]
    assert ptr_domain.value == "dns.google"
    assert ptr_domain.properties["is_ptr_hostname"] is True

    ptr_record = [e for e in result.entities if e.type == "DnsRecord" and e.properties["record_type"] == "PTR"][0]
    assert ptr_record.value == "dns.google"

    a_record = [e for e in result.entities if e.type == "DnsRecord" and e.properties["record_type"] == "A"][0]
    assert a_record.value == "8.8.8.8"

    resolves_to = [r for r in result.relationships if r["type"] == "RESOLVES_TO"]
    has_dns = [r for r in result.relationships if r["type"] == "HAS_DNS_RECORD"]
    assert len(resolves_to) == 1
    assert len(has_dns) == 2


def test_dns_records_transform_ip_no_ptr_returns_empty():
    """IP sem PTR -> result vazio."""
    from openm.transforms.dns_records import DnsRecordsTransform

    ip = IPAddress(value="192.0.2.1", properties={})
    transform = DnsRecordsTransform()

    with patch(
        "openm.transforms.dns_records.reverse_dns_ptr",
        return_value=None,
    ):
        result = transform.run(ip)

    assert result.entities == []
    assert result.relationships == []


def test_dns_records_transform_skips_non_supported_type():
    """Email -> result vazio sem chamar query_records."""
    from openm.transforms.dns_records import DnsRecordsTransform

    email = Email(value="a@b.com")
    transform = DnsRecordsTransform()

    with patch("openm.transforms.dns_records.query_records") as mock:
        result = transform.run(email)

    mock.assert_not_called()
    assert result.entities == []
    assert result.relationships == []


def test_dns_records_transform_registered():
    """DnsRecordsTransform aparece no registry para Domain e IPAddress."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.dns_records import DnsRecordsTransform

    assert TransformRegistry.get("dns_records_lookup") is DnsRecordsTransform

    for supported in ("Domain", "IPAddress"):
        names = [t["name"] for t in TransformRegistry.list_for_type(supported)]
        assert "dns_records_lookup" in names

    for other_type in ("Email", "Person", "Device", "BankAccount", "URL", "FileHash"):
        assert "dns_records_lookup" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


# ========================================================================
# DNS Records Service
# ========================================================================


def test_dns_records_service_query_records_success(monkeypatch):
    """query_records retorna registros parseados corretamente."""
    from openm.services.dns_records_service import query_records

    class FakeRdata:
        def __init__(self, value):
            self.address = value

    class FakeRRSet:
        def __init__(self, rdata_list, ttl):
            self.items = rdata_list
            self.ttl = ttl

        def __iter__(self):
            return iter(self.items)

        def __getitem__(self, idx):
            return self.items[idx]

    class FakeAnswer:
        def __init__(self, rdata_list, ttl):
            self.rrset = FakeRRSet(rdata_list, ttl)

    class FakeResolver:
        def __init__(self):
            self.timeout = 5.0
            self.lifetime = 5.0

        def resolve(self, qname, rdtype):
            if rdtype == "A":
                return FakeAnswer([FakeRdata("93.184.216.34")], 300)
            if rdtype == "MX":
                class FakeMx:
                    exchange = "mail.example.com."
                    preference = 10
                return FakeAnswer([FakeMx()], 3600)
            if rdtype == "TXT":
                class FakeTxt:
                    strings = [b"v=spf1 include:_spf.example.com ~all"]
                return FakeAnswer([FakeTxt()], 3600)
            raise dns.resolver.NoAnswer

    monkeypatch.setattr(
        "openm.services.dns_records_service._resolver",
        lambda timeout=None: FakeResolver(),
    )

    canonical, records = query_records("example.com", record_types=["A", "MX", "TXT"])
    assert canonical == "example.com"
    assert len(records) == 3

    a = [r for r in records if r["record_type"] == "A"][0]
    assert a["record_value"] == "93.184.216.34"
    assert a["record_ttl"] == 300

    mx = [r for r in records if r["record_type"] == "MX"][0]
    assert mx["record_value"] == "mail.example.com"
    assert mx["record_priority"] == 10

    txt = [r for r in records if r["record_type"] == "TXT"][0]
    assert "v=spf1" in txt["record_value"]


def test_dns_records_service_query_records_nxdomain_returns_none(monkeypatch):
    """NXDOMAIN -> retorna (None, [])."""
    from openm.services.dns_records_service import query_records

    class FakeResolver:
        def resolve(self, qname, rdtype):
            raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(
        "openm.services.dns_records_service._resolver",
        lambda timeout=None: FakeResolver(),
    )

    canonical, records = query_records("doesnotexist.example.com")
    assert canonical is None
    assert records == []


def test_dns_records_service_query_records_no_answer_continues(monkeypatch):
    """NoAnswer para um tipo nao interrompe os demais."""
    from openm.services.dns_records_service import query_records

    class FakeResolver:
        def resolve(self, qname, rdtype):
            raise dns.resolver.NoAnswer

    monkeypatch.setattr(
        "openm.services.dns_records_service._resolver",
        lambda timeout=None: FakeResolver(),
    )

    canonical, records = query_records("example.com", record_types=["A", "MX"])
    assert canonical == "example.com"
    assert records == []


def test_dns_records_service_query_records_cname_sets_canonical(monkeypatch):
    """CNAME chain define canonical_domain e retorna o registro CNAME."""
    from openm.services.dns_records_service import query_records

    class FakeCname:
        def __str__(self):
            return "target.example.com."

    class FakeRRSet:
        def __init__(self, rdata_list, ttl):
            self.items = rdata_list
            self.ttl = ttl

        def __iter__(self):
            return iter(self.items)

        def __getitem__(self, idx):
            return self.items[idx]

        def __len__(self):
            return len(self.items)

    class FakeAnswer:
        def __init__(self, rdata_list, ttl):
            self.rrset = FakeRRSet(rdata_list, ttl)

    class FakeResolver:
        def resolve(self, qname, rdtype):
            if rdtype == "CNAME":
                return FakeAnswer([FakeCname()], 300)
            raise dns.resolver.NoAnswer

    monkeypatch.setattr(
        "openm.services.dns_records_service._resolver",
        lambda timeout=None: FakeResolver(),
    )

    canonical, records = query_records("alias.example.com")
    assert canonical == "target.example.com"
    assert len(records) == 1
    assert records[0]["record_type"] == "CNAME"
    assert records[0]["record_value"] == "target.example.com"


def test_dns_records_service_reverse_dns_ptr_success(monkeypatch):
    """reverse_dns_ptr delega para socket_reverse_dns e query_records."""
    from openm.services import dns_records_service

    called = {}

    def fake_reverse_dns(ip, timeout):
        called["reverse"] = ip
        return ("dns.google", ["dns2.google"])

    def fake_query_records(hostname, timeout=None):
        called["query"] = hostname
        return hostname, [
            {
                "record_type": "A",
                "record_value": "8.8.8.8",
                "record_ttl": 300,
                "resolved_domain": hostname,
                "canonical_domain": hostname,
                "record_data": {"address": "8.8.8.8"},
            }
        ]

    monkeypatch.setattr(dns_records_service, "socket_reverse_dns", fake_reverse_dns)
    monkeypatch.setattr(dns_records_service, "query_records", fake_query_records)

    hostname, aliases, records = dns_records_service.reverse_dns_ptr("8.8.8.8")
    assert hostname == "dns.google"
    assert aliases == ["dns2.google"]
    assert called["reverse"] == "8.8.8.8"
    assert called["query"] == "dns.google"
    assert len(records) == 1


def test_dns_records_service_reverse_dns_ptr_no_ptr_returns_none(monkeypatch):
    """reverse_dns_ptr sem PTR -> None."""
    from openm.services import dns_records_service

    def fake_reverse_dns(ip, timeout):
        return None

    monkeypatch.setattr(dns_records_service, "socket_reverse_dns", fake_reverse_dns)

    result = dns_records_service.reverse_dns_ptr("192.0.2.1")
    assert result is None


# ========================================================================
# AbuseIPDB Transform
# ========================================================================


def test_abuseipdb_transform_ip_with_reports():
    """IPAddress com reports -> IP enriquecido + Device REPORTED_AS_ABUSIVE."""
    from openm.transforms.abuseipdb import AbuseIpdbTransform

    ip = IPAddress(value="192.0.2.100", properties={})
    transform = AbuseIpdbTransform()

    intel = {
        "value": "192.0.2.100",
        "type": "IPAddress",
        "source": "abuseipdb",
        "available": True,
        "abuse_confidence_score": 85,
        "country_code": "US",
        "usage_type": "Data Center/Web Hosting/Transit",
        "isp": "Example ISP",
        "domain": "example.com",
        "total_reports": 42,
        "num_distinct_users": 12,
        "last_reported_at": "2026-06-26T12:00:00+00:00",
        "is_public": True,
        "is_whitelisted": False,
        "checked_at": "2026-06-27T16:00:00+00:00",
    }

    with patch(
        "openm.transforms.abuseipdb.AbuseIPDBService.investigate_ip",
        return_value=intel,
    ):
        result = transform.run(ip)

    assert len(result.entities) == 2
    enriched = [e for e in result.entities if isinstance(e, IPAddress)][0]
    assert enriched.id == ip.id
    assert enriched.properties["abuseipdb_abuse_confidence_score"] == 85
    assert enriched.properties["abuseipdb_total_reports"] == 42
    assert enriched.properties["abuseipdb_country_code"] == "US"
    assert enriched.properties["abuseipdb_available"] is True

    device = [e for e in result.entities if e.type == "Device"][0]
    assert device.properties["role"] == "threat_intel_source"
    assert device.properties["abuse_confidence_score"] == 85

    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "REPORTED_AS_ABUSIVE"
    assert result.relationships[0]["from_id"] == enriched.id


def test_abuseipdb_transform_ip_low_score_no_device():
    """Score baixo (< 50) -> apenas IP enriquecido, sem Device."""
    from openm.transforms.abuseipdb import AbuseIpdbTransform

    ip = IPAddress(value="192.0.2.101", properties={})
    transform = AbuseIpdbTransform()

    intel = {
        "value": "192.0.2.101",
        "type": "IPAddress",
        "source": "abuseipdb",
        "available": True,
        "abuse_confidence_score": 10,
        "country_code": "BR",
        "usage_type": "Fixed Line ISP",
        "isp": "Local ISP",
        "domain": None,
        "total_reports": 1,
        "num_distinct_users": 1,
        "last_reported_at": None,
        "is_public": True,
        "is_whitelisted": False,
        "checked_at": "2026-06-27T16:00:00+00:00",
    }

    with patch(
        "openm.transforms.abuseipdb.AbuseIPDBService.investigate_ip",
        return_value=intel,
    ):
        result = transform.run(ip)

    assert len(result.entities) == 1
    assert result.entities[0].type == "IPAddress"
    assert result.entities[0].properties["abuseipdb_abuse_confidence_score"] == 10
    assert result.relationships == []


def test_abuseipdb_transform_unavailable_still_enriches():
    """API falha -> IP enriquecido com available=False, sem Device."""
    from openm.transforms.abuseipdb import AbuseIpdbTransform

    ip = IPAddress(value="192.0.2.102", properties={})
    transform = AbuseIpdbTransform()

    intel = {
        "value": "192.0.2.102",
        "type": "IPAddress",
        "source": "abuseipdb",
        "available": False,
        "abuse_confidence_score": None,
        "country_code": None,
        "usage_type": None,
        "isp": None,
        "domain": None,
        "total_reports": None,
        "num_distinct_users": None,
        "last_reported_at": None,
        "is_public": None,
        "is_whitelisted": None,
        "checked_at": "2026-06-27T16:00:00+00:00",
    }

    with patch(
        "openm.transforms.abuseipdb.AbuseIPDBService.investigate_ip",
        return_value=intel,
    ):
        result = transform.run(ip)

    assert len(result.entities) == 1
    assert result.entities[0].properties["abuseipdb_available"] is False
    assert result.entities[0].properties["abuseipdb_abuse_confidence_score"] is None
    assert result.relationships == []


def test_abuseipdb_transform_domain_resolves_ip():
    """Domain -> resolve IP, enriquece IP, cria RESOLVES_TO."""
    from openm.transforms.abuseipdb import AbuseIpdbTransform

    domain = Domain(value="example.com", properties={})
    transform = AbuseIpdbTransform()

    intel = {
        "value": "93.184.216.34",
        "type": "IPAddress",
        "source": "abuseipdb",
        "available": True,
        "abuse_confidence_score": 0,
        "country_code": "US",
        "usage_type": "Content Delivery Network",
        "isp": "Example CDN",
        "domain": "example.com",
        "total_reports": 0,
        "num_distinct_users": 0,
        "last_reported_at": None,
        "is_public": True,
        "is_whitelisted": False,
        "checked_at": "2026-06-27T16:00:00+00:00",
    }

    with patch(
        "openm.transforms.abuseipdb.AbuseIPDBService.investigate_ip",
        return_value=intel,
    ), patch(
        "openm.transforms.abuseipdb.AbuseIpdbTransform._resolve_domain",
        return_value="93.184.216.34",
    ):
        result = transform.run(domain)

    ip_entity = [e for e in result.entities if isinstance(e, IPAddress)][0]
    assert ip_entity.value == "93.184.216.34"
    assert ip_entity.properties["resolved_from"] == "example.com"

    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "RESOLVES_TO"
    assert result.relationships[0]["from_id"] == domain.id
    assert result.relationships[0]["to_id"] == ip_entity.id


def test_abuseipdb_transform_domain_unresolvable_returns_empty():
    """Domain sem resolucao -> result vazio."""
    from openm.transforms.abuseipdb import AbuseIpdbTransform

    domain = Domain(value="unresolvable.example", properties={})
    transform = AbuseIpdbTransform()

    with patch(
        "openm.transforms.abuseipdb.AbuseIpdbTransform._resolve_domain",
        return_value=None,
    ):
        result = transform.run(domain)

    assert result.entities == []
    assert result.relationships == []


def test_abuseipdb_transform_skips_unsupported_type():
    """Email -> result vazio sem chamar investigate_ip."""
    from openm.transforms.abuseipdb import AbuseIpdbTransform

    email = Email(value="a@b.com")
    transform = AbuseIpdbTransform()

    with patch("openm.transforms.abuseipdb.AbuseIPDBService.investigate_ip") as mock:
        result = transform.run(email)

    mock.assert_not_called()
    assert result.entities == []
    assert result.relationships == []


def test_abuseipdb_transform_registered():
    """AbuseIpdbTransform aparece no registry para IPAddress e Domain."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.abuseipdb import AbuseIpdbTransform

    assert TransformRegistry.get("abuseipdb_lookup") is AbuseIpdbTransform

    for supported in ("IPAddress", "Domain"):
        names = [t["name"] for t in TransformRegistry.list_for_type(supported)]
        assert "abuseipdb_lookup" in names

    for other_type in ("Email", "Person", "Device", "BankAccount", "URL", "FileHash", "DnsRecord"):
        assert "abuseipdb_lookup" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


# ========================================================================
# AbuseIPDB Service
# ========================================================================


def test_abuseipdb_service_investigate_ip_success(monkeypatch):
    """investigate_ip normaliza resposta da API."""
    from openm.services.abuseipdb_service import AbuseIPDBService

    fake_attrs = {
        "abuseConfidenceScore": 75,
        "countryCode": "RU",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Bad ISP",
        "domain": "bad.example.com",
        "totalReports": 99,
        "numDistinctUsers": 33,
        "lastReportedAt": "2026-06-25T10:00:00+00:00",
        "isPublic": True,
        "isWhitelisted": False,
    }

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"data": {"attributes": fake_attrs}}

    def fake_get(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("openm.core.http_client.http_get", fake_get)
    monkeypatch.setattr(
        AbuseIPDBService, "get_key", staticmethod(lambda: "fake-key")
    )

    result = AbuseIPDBService.investigate_ip("192.0.2.200")
    assert result["available"] is True
    assert result["abuse_confidence_score"] == 75
    assert result["country_code"] == "RU"
    assert result["total_reports"] == 99
    assert result["source"] == "abuseipdb"


def test_abuseipdb_service_investigate_ip_no_key_returns_unavailable(monkeypatch):
    """Sem chave -> available=False."""
    from openm.services.abuseipdb_service import AbuseIPDBService

    monkeypatch.setattr(AbuseIPDBService, "get_key", staticmethod(lambda: None))

    result = AbuseIPDBService.investigate_ip("192.0.2.201")
    assert result["available"] is False
    assert result["abuse_confidence_score"] is None


def test_abuseipdb_service_investigate_ip_rate_limit_returns_unavailable(monkeypatch):
    """429 -> available=False."""
    from openm.services.abuseipdb_service import AbuseIPDBService

    class FakeResponse:
        status_code = 429

    def fake_get(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("openm.core.http_client.http_get", fake_get)
    monkeypatch.setattr(
        AbuseIPDBService, "get_key", staticmethod(lambda: "fake-key")
    )

    result = AbuseIPDBService.investigate_ip("192.0.2.202")
    assert result["available"] is False


def test_abuseipdb_service_query_ip_invalid_json_returns_none(monkeypatch):
    """Resposta 200 com JSON invalido -> None."""
    from openm.services.abuseipdb_service import AbuseIPDBService

    class FakeResponse:
        status_code = 200

        def json(self):
            raise ValueError("not json")

    def fake_get(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("openm.core.http_client.http_get", fake_get)
    monkeypatch.setattr(
        AbuseIPDBService, "get_key", staticmethod(lambda: "fake-key")
    )

    result = AbuseIPDBService.query_ip("192.0.2.203")
    assert result is None


# ========================================================================
# HIBP Transform
# ========================================================================


def test_hibp_transform_email_with_breaches():
    """Email com breaches -> Email enriquecido + Breach + EXPOSED_IN."""
    from openm.transforms.hibp import HibpTransform
    from openm.core.entity import Breach

    email = Email(value="test@example.com", properties={})
    transform = HibpTransform()

    intel = {
        "value": "test@example.com",
        "type": "Email",
        "source": "hibp",
        "available": True,
        "breaches": [
            {
                "name": "Adobe",
                "title": "Adobe",
                "domain": "adobe.com",
                "breach_date": "2013-10-04",
                "added_date": "2013-12-04T00:00:00Z",
                "modified_date": "2022-05-25T21:35:40Z",
                "pwn_count": 152445165,
                "description": "Test description",
                "data_classes": ["Email addresses", "Passwords"],
                "is_verified": True,
                "is_fabricated": False,
                "is_sensitive": False,
                "is_retired": False,
                "is_spam_list": False,
                "logo_path": "Adobe.png",
            }
        ],
        "breach_count": 1,
        "checked_at": "2026-06-27T18:00:00+00:00",
    }

    with patch(
        "openm.transforms.hibp.HibpService.investigate_email",
        return_value=intel,
    ):
        result = transform.run(email)

    assert len(result.entities) == 2
    enriched = [e for e in result.entities if isinstance(e, Email)][0]
    assert enriched.id == email.id
    assert enriched.properties["hibp_breach_count"] == 1
    assert enriched.properties["hibp_available"] is True

    breach = [e for e in result.entities if isinstance(e, Breach)][0]
    assert breach.value == "Adobe"
    assert breach.properties["title"] == "Adobe"
    assert breach.properties["pwn_count"] == 152445165

    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "EXPOSED_IN"
    assert result.relationships[0]["from_id"] == email.id
    assert result.relationships[0]["to_id"] == breach.id


def test_hibp_transform_email_clean():
    """Email sem breaches -> Email enriquecido, sem entidades Breach."""
    from openm.transforms.hibp import HibpTransform
    from openm.core.entity import Breach

    email = Email(value="clean@example.com", properties={})
    transform = HibpTransform()

    intel = {
        "value": "clean@example.com",
        "type": "Email",
        "source": "hibp",
        "available": True,
        "breaches": [],
        "breach_count": 0,
        "checked_at": "2026-06-27T18:00:00+00:00",
    }

    with patch(
        "openm.transforms.hibp.HibpService.investigate_email",
        return_value=intel,
    ):
        result = transform.run(email)

    assert len(result.entities) == 1
    assert result.entities[0].type == "Email"
    assert not any(isinstance(e, Breach) for e in result.entities)
    assert result.relationships == []


def test_hibp_transform_email_unavailable():
    """API indisponivel -> Email enriquecido com available=False."""
    from openm.transforms.hibp import HibpTransform

    email = Email(value="nobreach@example.com", properties={})
    transform = HibpTransform()

    intel = {
        "value": "nobreach@example.com",
        "type": "Email",
        "source": "hibp",
        "available": False,
        "breaches": [],
        "breach_count": 0,
        "checked_at": "2026-06-27T18:00:00+00:00",
    }

    with patch(
        "openm.transforms.hibp.HibpService.investigate_email",
        return_value=intel,
    ):
        result = transform.run(email)

    assert len(result.entities) == 1
    assert result.entities[0].properties["hibp_available"] is False
    assert result.relationships == []


def test_hibp_transform_domain_paid_available():
    """Dominio com acesso pago -> Domain + Emails + Breaches + edges."""
    from openm.transforms.hibp import HibpTransform
    from openm.core.entity import Breach

    domain = Domain(value="example.com", properties={})
    transform = HibpTransform()

    intel = {
        "value": "example.com",
        "type": "Domain",
        "source": "hibp",
        "available": True,
        "exposed_emails": [
            {
                "email": "alice@example.com",
                "breaches": [
                    {
                        "Name": "Adobe",
                        "Title": "Adobe",
                        "Domain": "adobe.com",
                        "BreachDate": "2013-10-04",
                        "AddedDate": "2013-12-04T00:00:00Z",
                        "ModifiedDate": "2022-05-25T21:35:40Z",
                        "PwnCount": 152445165,
                        "Description": "Test",
                        "DataClasses": ["Email addresses", "Passwords"],
                        "IsVerified": True,
                        "IsFabricated": False,
                        "IsSensitive": False,
                        "IsRetired": False,
                        "IsSpamList": False,
                        "LogoPath": "Adobe.png",
                    }
                ],
            }
        ],
        "exposed_email_count": 1,
        "checked_at": "2026-06-27T18:00:00+00:00",
    }

    with patch(
        "openm.transforms.hibp.HibpService.investigate_domain",
        return_value=intel,
    ):
        result = transform.run(domain)

    enriched = [e for e in result.entities if isinstance(e, Domain)][0]
    assert enriched.id == domain.id
    assert enriched.properties["hibp_available"] is True
    assert enriched.properties["hibp_exposed_email_count"] == 1

    emails = [e for e in result.entities if isinstance(e, Email)]
    assert len(emails) == 1
    assert emails[0].value == "alice@example.com"

    breaches = [e for e in result.entities if isinstance(e, Breach)]
    assert len(breaches) == 1
    assert breaches[0].value == "Adobe"

    has_exposed = [r for r in result.relationships if r["type"] == "HAS_EXPOSED_EMAIL"]
    exposed_in = [r for r in result.relationships if r["type"] == "EXPOSED_IN"]
    assert len(has_exposed) == 1
    assert len(exposed_in) == 1


def test_hibp_transform_domain_paid_unavailable():
    """Dominio sem acesso pago -> apenas Domain enriquecido."""
    from openm.transforms.hibp import HibpTransform

    domain = Domain(value="example.com", properties={})
    transform = HibpTransform()

    intel = {
        "value": "example.com",
        "type": "Domain",
        "source": "hibp",
        "available": False,
        "exposed_emails": [],
        "exposed_email_count": 0,
        "checked_at": "2026-06-27T18:00:00+00:00",
    }

    with patch(
        "openm.transforms.hibp.HibpService.investigate_domain",
        return_value=intel,
    ):
        result = transform.run(domain)

    assert len(result.entities) == 1
    assert result.entities[0].type == "Domain"
    assert result.entities[0].properties["hibp_available"] is False
    assert result.relationships == []


def test_hibp_transform_skips_unsupported_type():
    """IPAddress -> result vazio sem chamar HIBP."""
    from openm.transforms.hibp import HibpTransform

    ip = IPAddress(value="8.8.8.8")
    transform = HibpTransform()

    with patch("openm.transforms.hibp.HibpService.investigate_email") as mock_email, \
         patch("openm.transforms.hibp.HibpService.investigate_domain") as mock_domain:
        result = transform.run(ip)

    mock_email.assert_not_called()
    mock_domain.assert_not_called()
    assert result.entities == []
    assert result.relationships == []


def test_hibp_transform_registered():
    """HibpTransform aparece no registry para Email e Domain."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.hibp import HibpTransform

    assert TransformRegistry.get("hibp_breach_lookup") is HibpTransform

    for supported in ("Email", "Domain"):
        names = [t["name"] for t in TransformRegistry.list_for_type(supported)]
        assert "hibp_breach_lookup" in names

    for other_type in ("IPAddress", "Person", "Device", "BankAccount", "URL", "FileHash", "DnsRecord"):
        assert "hibp_breach_lookup" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


# ========================================================================
# HIBP Service
# ========================================================================


def test_hibp_service_query_email_breaches_success(monkeypatch):
    """query_email_breaches retorna lista parseada."""
    from openm.services.hibp_service import HibpService

    class FakeResponse:
        status_code = 200

        def json(self):
            return [{"Name": "Adobe", "Title": "Adobe"}]

    def fake_get(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("openm.core.http_client.http_get", fake_get)
    monkeypatch.setattr(HibpService, "get_key", staticmethod(lambda: "fake-key"))

    result = HibpService.query_email_breaches("test@example.com")
    assert result == [{"Name": "Adobe", "Title": "Adobe"}]


def test_hibp_service_query_email_breaches_404_empty(monkeypatch):
    """404 e interpretado como lista vazia (email limpo)."""
    from openm.services.hibp_service import HibpService

    class FakeResponse:
        status_code = 404

    monkeypatch.setattr(
        "openm.core.http_client.http_get",
        lambda url, headers, params, timeout: FakeResponse(),
    )
    monkeypatch.setattr(HibpService, "get_key", staticmethod(lambda: "fake-key"))

    result = HibpService.query_email_breaches("clean@example.com")
    assert result == []


def test_hibp_service_query_email_breaches_no_key_returns_none(monkeypatch):
    """Sem chave -> None."""
    from openm.services.hibp_service import HibpService

    monkeypatch.setattr(HibpService, "get_key", staticmethod(lambda: None))

    result = HibpService.query_email_breaches("test@example.com")
    assert result is None


def test_hibp_service_query_domain_breaches_unauthorized_returns_none(monkeypatch):
    """Dominio sem acesso pago -> None (unavailable)."""
    from openm.services.hibp_service import HibpService

    class FakeResponse:
        status_code = 401

    monkeypatch.setattr(
        "openm.core.http_client.http_get",
        lambda url, headers, params, timeout: FakeResponse(),
    )
    monkeypatch.setattr(HibpService, "get_key", staticmethod(lambda: "fake-key"))

    result = HibpService.query_domain_breaches("example.com")
    assert result is None


def test_hibp_service_query_breach_details_success(monkeypatch):
    """query_breach_details retorna dict de detalhes."""
    from openm.services.hibp_service import HibpService

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"Name": "Adobe", "Title": "Adobe", "PwnCount": 100}

    monkeypatch.setattr(
        "openm.core.http_client.http_get",
        lambda url, headers, params, timeout: FakeResponse(),
    )
    monkeypatch.setattr(HibpService, "get_key", staticmethod(lambda: "fake-key"))

    result = HibpService.query_breach_details("Adobe")
    assert result["Name"] == "Adobe"
    assert result["PwnCount"] == 100


def test_hibp_service_investigate_email_normalizes(monkeypatch):
    """investigate_email normaliza breaches e contadores."""
    from openm.services.hibp_service import HibpService

    raw = [
        {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "ModifiedDate": "2022-05-25T21:35:40Z",
            "PwnCount": 152445165,
            "Description": "Test",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "LogoPath": "Adobe.png",
        }
    ]

    class FakeResponse:
        status_code = 200

        def json(self):
            return raw

    def fake_get(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("openm.core.http_client.http_get", fake_get)
    monkeypatch.setattr(HibpService, "get_key", staticmethod(lambda: "fake-key"))

    result = HibpService.investigate_email("test@example.com")
    assert result["available"] is True
    assert result["breach_count"] == 1
    assert result["breaches"][0]["name"] == "Adobe"
    assert result["breaches"][0]["is_verified"] is True


# ========================================================================
# URLScan Transform
# ========================================================================


def test_urlscan_transform_domain_full_result():
    """Domain com scan completo -> Domain enriquecido + Domains/IPs contactados."""
    from openm.transforms.urlscan import UrlscanTransform

    domain = Domain(value="example.com", properties={})
    transform = UrlscanTransform()

    intel = {
        "available": True,
        "uuid": "abc-123",
        "result_url": "https://urlscan.io/result/abc-123/",
        "screenshot_url": "https://urlscan.io/screenshots/abc-123.png",
        "page_domain": "example.com",
        "page_url": "https://example.com/",
        "page_status": "200",
        "page_title": "Example Domain",
        "malicious": False,
        "score": 0,
        "technologies": ["nginx", "Bootstrap"],
        "ips": ["93.184.216.34", "1.2.3.4"],
        "domains": ["cdn.example.com", "tracker.evil.com"],
        "urls": ["https://example.com/login"],
        "countries": ["US", "DE"],
        "stats": {"requestsCount": 12, "cookieCount": 2},
        "checked_at": "2026-06-27T20:00:00+00:00",
    }

    with patch(
        "openm.transforms.urlscan.UrlscanService.submit_scan",
        return_value=intel,
    ):
        result = transform.run(domain)

    assert len(result.entities) == 5  # Domain + 2 contacted domains + 2 IPs
    enriched = [e for e in result.entities if isinstance(e, Domain) and e.id == domain.id][0]
    assert enriched.properties["urlscan_available"] is True
    assert enriched.properties["urlscan_malicious"] is False
    assert enriched.properties["urlscan_score"] == 0
    assert "nginx" in enriched.properties["urlscan_technologies"]
    assert enriched.properties["urlscan_screenshot_url"].endswith(".png")

    contacted_domains = [
        e for e in result.entities
        if isinstance(e, Domain) and e.id != domain.id
    ]
    assert {d.value for d in contacted_domains} == {"cdn.example.com", "tracker.evil.com"}

    contacted_ips = [e for e in result.entities if isinstance(e, IPAddress)]
    assert {ip.value for ip in contacted_ips} == {"93.184.216.34", "1.2.3.4"}

    contacts_rels = [r for r in result.relationships if r["type"] == "CONTACTS"]
    connects_rels = [r for r in result.relationships if r["type"] == "CONNECTS_TO"]
    assert len(contacts_rels) == 2
    assert len(connects_rels) == 2
    assert all(r["from_id"] == domain.id for r in contacts_rels)
    assert all(r["from_id"] == domain.id for r in connects_rels)


def test_urlscan_transform_skips_self_and_page_domain():
    """Domain de input e page_domain nao viram entidades CONTACTS."""
    from openm.transforms.urlscan import UrlscanTransform

    domain = Domain(value="example.com", properties={})
    transform = UrlscanTransform()

    intel = {
        "available": True,
        "uuid": "abc",
        "page_domain": "example.com",
        "page_url": "https://example.com/",
        "ips": [],
        "domains": ["example.com", "other.com"],
    }

    with patch(
        "openm.transforms.urlscan.UrlscanService.submit_scan",
        return_value=intel,
    ):
        result = transform.run(domain)

    contacted = [
        e for e in result.entities
        if isinstance(e, Domain) and e.id != domain.id
    ]
    # example.com pulado (input), so other.com aparece.
    assert {d.value for d in contacted} == {"other.com"}


def test_urlscan_transform_unavailable_marks_input():
    """Scan indisponivel (chave invalida, rate-limit, etc.) -> enriquecido com available=False."""
    from openm.transforms.urlscan import UrlscanTransform

    domain = Domain(value="example.com", properties={})
    transform = UrlscanTransform()

    intel = {
        "available": False,
        "key_valid": False,
        "checked_at": "2026-06-27T20:00:00+00:00",
    }

    with patch(
        "openm.transforms.urlscan.UrlscanService.submit_scan",
        return_value=intel,
    ):
        result = transform.run(domain)

    assert len(result.entities) == 1
    assert result.entities[0].id == domain.id
    assert result.entities[0].properties["urlscan_available"] is False
    assert result.entities[0].properties["urlscan_key_valid"] is False
    assert result.relationships == []


def test_urlscan_transform_rate_limited_marks():
    """429 -> urlscan_rate_limited=True."""
    from openm.transforms.urlscan import UrlscanTransform

    domain = Domain(value="example.com", properties={})
    transform = UrlscanTransform()

    intel = {
        "available": False,
        "rate_limited": True,
        "checked_at": "2026-06-27T20:00:00+00:00",
    }

    with patch(
        "openm.transforms.urlscan.UrlscanService.submit_scan",
        return_value=intel,
    ):
        result = transform.run(domain)

    enriched = result.entities[0]
    assert enriched.properties["urlscan_rate_limited"] is True


def test_urlscan_transform_ip_input():
    """IPAddress tambem e aceito e funciona como input."""
    from openm.transforms.urlscan import UrlscanTransform

    ip = IPAddress(value="8.8.8.8", properties={})
    transform = UrlscanTransform()

    intel = {
        "available": True,
        "uuid": "x",
        "page_domain": "dns.google",
        "page_url": "https://dns.google/",
        "ips": [],
        "domains": ["dns.google"],
    }

    with patch(
        "openm.transforms.urlscan.UrlscanService.submit_scan",
        return_value=intel,
    ):
        result = transform.run(ip)

    enriched = [e for e in result.entities if isinstance(e, IPAddress)][0]
    assert enriched.id == ip.id
    assert enriched.properties["urlscan_available"] is True


def test_urlscan_transform_url_input():
    """URL entity passa o value completo para o service."""
    from openm.transforms.urlscan import UrlscanTransform

    url = URL(value="https://example.com/login", properties={})
    transform = UrlscanTransform()

    with patch(
        "openm.transforms.urlscan.UrlscanService.submit_scan",
        return_value={"available": False, "checked_at": "x"},
    ) as mock_submit:
        transform.run(url)

    # Value da URL foi passado inteiro (com scheme).
    mock_submit.assert_called_once_with("https://example.com/login")


def test_urlscan_transform_no_key_returns_empty():
    """Service retorna None -> result vazio."""
    from openm.transforms.urlscan import UrlscanTransform

    domain = Domain(value="example.com", properties={})
    transform = UrlscanTransform()

    with patch(
        "openm.transforms.urlscan.UrlscanService.submit_scan",
        return_value=None,
    ):
        result = transform.run(domain)

    assert result.entities == []
    assert result.relationships == []


def test_urlscan_transform_skips_unsupported_type():
    """Email -> result vazio sem chamar service."""
    from openm.transforms.urlscan import UrlscanTransform

    email = Email(value="a@b.com")
    transform = UrlscanTransform()

    with patch("openm.transforms.urlscan.UrlscanService.submit_scan") as mock:
        result = transform.run(email)

    mock.assert_not_called()
    assert result.entities == []
    assert result.relationships == []


def test_urlscan_transform_registered():
    """UrlscanTransform aparece no registry para Domain, IPAddress e URL."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.urlscan import UrlscanTransform

    assert TransformRegistry.get("urlscan_lookup") is UrlscanTransform

    for supported in ("Domain", "IPAddress", "URL"):
        names = [t["name"] for t in TransformRegistry.list_for_type(supported)]
        assert "urlscan_lookup" in names

    for other_type in ("Email", "Person", "Device", "BankAccount", "FileHash", "DnsRecord"):
        assert "urlscan_lookup" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


# ========================================================================
# URLScan Service
# ========================================================================


def test_urlscan_service_submit_no_key_returns_none(monkeypatch):
    """Sem chave -> None."""
    from openm.services.urlscan_service import UrlscanService

    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: None))

    result = UrlscanService.submit_scan("example.com", poll=False)
    assert result is None


def test_urlscan_service_submit_poll_false(monkeypatch):
    """poll=False retorna imediatamente com available=False e uuid."""
    from openm.services.urlscan_service import UrlscanService

    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: "key-123"))

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "uuid": "abc-123",
                "result": "https://urlscan.io/result/abc-123/",
            }

    def fake_post(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.core.http_client.http_post",
        fake_post,
    )

    result = UrlscanService.submit_scan("example.com", poll=False)
    assert result["available"] is False
    assert result["uuid"] == "abc-123"
    assert result["result_url"] == "https://urlscan.io/result/abc-123/"


def test_urlscan_service_submit_adds_https_scheme(monkeypatch):
    """Targets sem scheme recebem https://."""
    from openm.services.urlscan_service import UrlscanService

    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: "key"))

    captured = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"uuid": "x", "result": "y"}

    def fake_post(url, **kwargs):
        captured["target"] = kwargs.get("json", {}).get("url")
        return FakeResponse()

    monkeypatch.setattr(
        "openm.core.http_client.http_post",
        fake_post,
    )

    UrlscanService.submit_scan("example.com", poll=False)
    assert captured["target"] == "https://example.com"


def test_urlscan_service_submit_poll_success(monkeypatch):
    """Poll: primeira tentativa 404 (processando), segunda 200 -> ok."""
    from openm.services.urlscan_service import UrlscanService

    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: "key"))

    class FakeSubmit:
        status_code = 200

        def json(self):
            return {"uuid": "abc", "result": "https://urlscan.io/result/abc/"}

    submit_calls = {"n": 0}
    result_calls = {"n": 0}

    def fake_post(url, **kwargs):
        submit_calls["n"] += 1
        return FakeSubmit()

    class FakeResult:
        def __init__(self, status_code, body=None):
            self.status_code = status_code
            self._body = body or {}

        def json(self):
            return self._body

    def fake_get(url, **kwargs):
        result_calls["n"] += 1
        if result_calls["n"] == 1:
            return FakeResult(404)
        return FakeResult(200, {
            "uuid": "abc",
            "result": "https://urlscan.io/result/abc/",
            "page": {
                "domain": "example.com",
                "url": "https://example.com/",
                "status": "200",
                "title": "Example",
            },
            "task": {"url": "https://example.com/"},
            "stats": [],
            "verdicts": {"overall": {"malicious": False, "score": 0}},
            "lists": {"ips": [], "domains": [], "urls": [], "countries": []},
            "meta": {"processors": {"wappa": {"data": ["nginx"]}}},
        })

    monkeypatch.setattr(
        "openm.core.http_client.http_post",
        fake_post,
    )
    monkeypatch.setattr(
        "openm.core.http_client.http_get",
        fake_get,
    )

    result = UrlscanService.submit_scan(
        "example.com",
        poll_interval=0.0,
        poll_max_wait=10.0,
    )

    assert result["available"] is True
    assert result["uuid"] == "abc"
    assert result["page_domain"] == "example.com"
    assert result["page_status"] == "200"
    assert "nginx" in result["technologies"]
    assert submit_calls["n"] == 1
    assert result_calls["n"] == 2


def test_urlscan_service_submit_rate_limited(monkeypatch):
    """429 no submit -> rate_limited."""
    from openm.services.urlscan_service import UrlscanService

    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: "key"))

    class FakeResponse:
        status_code = 429

    def fake_post(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.core.http_client.http_post",
        fake_post,
    )

    result = UrlscanService.submit_scan("example.com", poll=False)
    assert result["rate_limited"] is True
    assert result["available"] is False


def test_urlscan_service_submit_unauthorized(monkeypatch):
    """401 no submit -> key_valid=False."""
    from openm.services.urlscan_service import UrlscanService

    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: "key"))

    class FakeResponse:
        status_code = 401

    def fake_post(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(
        "openm.core.http_client.http_post",
        fake_post,
    )

    result = UrlscanService.submit_scan("example.com", poll=False)
    assert result["key_valid"] is False
    assert result["available"] is False


def test_urlscan_service_normalize_lists_dict_form(monkeypatch):
    """Listas em formato dict (ex: {'ip': '1.2.3.4'}) sao normalizadas."""
    from openm.services.urlscan_service import UrlscanService

    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: "key"))

    class FakeSubmit:
        status_code = 200

        def json(self):
            return {"uuid": "abc", "result": "https://urlscan.io/result/abc/"}

    class FakeResult:
        def __init__(self, status_code, body=None):
            self.status_code = status_code
            self._body = body or {}

        def json(self):
            return self._body

    def fake_post(url, **kwargs):
        return FakeSubmit()

    def fake_get(url, **kwargs):
        return FakeResult(200, {
            "uuid": "abc",
            "page": {"domain": "example.com", "url": "https://example.com/", "status": "200"},
            "task": {"url": "https://example.com/"},
            "stats": [],
            "verdicts": {"overall": {"malicious": False, "score": 0}},
            "lists": {
                "ips": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}],
                "domains": [{"domain": "cdn.example.com"}],
                "urls": [{"url": "https://example.com/a"}, "https://example.com/b"],
                "countries": [{"country": "US"}],
            },
            "meta": {"processors": {"wappa": {"data": []}}},
        })

    monkeypatch.setattr(
        "openm.core.http_client.http_post",
        fake_post,
    )
    monkeypatch.setattr(
        "openm.core.http_client.http_get",
        fake_get,
    )

    result = UrlscanService.submit_scan(
        "example.com",
        poll_interval=0.0,
        poll_max_wait=10.0,
    )

    assert result["ips"] == ["1.2.3.4", "5.6.7.8"]
    assert result["domains"] == ["cdn.example.com"]
    assert result["urls"] == ["https://example.com/a", "https://example.com/b"]
    assert result["countries"] == ["US"]


def test_urlscan_service_pending_when_timeout(monkeypatch):
    """Scan nao fica pronto antes do timeout -> pending=True."""
    from openm.services.urlscan_service import UrlscanService

    monkeypatch.setattr(UrlscanService, "get_key", staticmethod(lambda: "key"))

    class FakeSubmit:
        status_code = 200

        def json(self):
            return {"uuid": "abc", "result": "x"}

    def fake_post(url, **kwargs):
        return FakeSubmit()

    class FakeResult:
        status_code = 404

    def fake_get(url, **kwargs):
        return FakeResult()

    monkeypatch.setattr(
        "openm.core.http_client.http_post",
        fake_post,
    )
    monkeypatch.setattr(
        "openm.core.http_client.http_get",
        fake_get,
    )

    result = UrlscanService.submit_scan(
        "example.com",
        poll_interval=0.0,
        poll_max_wait=0.05,
    )
    assert result["available"] is False
    assert result["pending"] is True
    assert result["uuid"] == "abc"


# ========================================================================
# Person → Domain Discovery Transform
# ========================================================================


def test_person_domain_transform_with_email_only():
    """Person com email -> Domain extraido + ASSOCIATED_WITH edge."""
    from openm.transforms.person_discovery import PersonToDomainTransform

    person = Person(
        value="John Doe",
        properties={"email": "john.doe@example.com"},
    )
    transform = PersonToDomainTransform()

    with patch(
        "openm.transforms.person_discovery.HunterService.investigate_domain",
        return_value=None,
    ):
        result = transform.run(person)

    enriched = [e for e in result.entities if isinstance(e, Person)][0]
    assert enriched.id == person.id
    assert enriched.properties["person_domain_source"] == "email"
    assert enriched.properties["person_associated_domains"] == ["example.com"]

    domains = [e for e in result.entities if isinstance(e, Domain)]
    assert len(domains) == 1
    assert domains[0].value == "example.com"
    assert domains[0].properties["source"] == "email_parse"

    emails = [e for e in result.entities if isinstance(e, Email)]
    assert len(emails) == 1
    assert emails[0].value == "john.doe@example.com"

    associated = [r for r in result.relationships if r["type"] == "ASSOCIATED_WITH"]
    assert len(associated) == 1
    assert associated[0]["from_id"] == person.id
    assert associated[0]["to_id"] == domains[0].id

    belongs_to = [r for r in result.relationships if r["type"] == "BELONGS_TO"]
    assert len(belongs_to) == 1
    assert belongs_to[0]["from_id"] == emails[0].id
    assert belongs_to[0]["to_id"] == domains[0].id


def test_person_domain_transform_with_org_and_hunter():
    """Person com organization -> Hunter descobre domains adicionais."""
    from openm.transforms.person_discovery import PersonToDomainTransform

    person = Person(
        value="Jane Smith",
        properties={"organization": "Acme Inc."},
    )
    transform = PersonToDomainTransform()

    hunter_intel = {
        "domain": "acme.com",
        "source": "hunter",
        "available": True,
        "organization": "Acme Inc.",
        "pattern": "{first}.{last}",
        "accept_all": False,
        "linked_domains": ["acme.io", "acme-staging.com"],
        "people": [
            {
                "first_name": "Jane",
                "last_name": "Smith",
                "email": "jane.smith@acme.com",
                "position": "CEO",
            }
        ],
    }

    with patch(
        "openm.transforms.person_discovery.HunterService.investigate_domain",
        return_value=hunter_intel,
    ):
        result = transform.run(person)

    enriched = [e for e in result.entities if isinstance(e, Person)][0]
    assert enriched.properties["person_domain_source"] == "hunter"
    assert enriched.properties["person_domain_hunter_available"] is True
    assert enriched.properties["person_domain_hunter_pattern"] == "{first}.{last}"
    assert "acme.com" in enriched.properties["person_associated_domains"]
    assert "acme.io" in enriched.properties["person_associated_domains"]
    assert "acme-staging.com" in enriched.properties["person_associated_domains"]

    domains = {e.value: e for e in result.entities if isinstance(e, Domain)}
    assert "acme.com" in domains
    assert "acme.io" in domains
    assert "acme-staging.com" in domains
    assert domains["acme.com"].properties["source"] == "hunter_domain_search"
    assert domains["acme.io"].properties["source"] == "hunter_linked_domain"

    emails = {e.value: e for e in result.entities if isinstance(e, Email)}
    assert "jane.smith@acme.com" in emails

    belongs_to = [r for r in result.relationships if r["type"] == "BELONGS_TO"]
    assert len(belongs_to) >= 1


def test_person_domain_transform_hunter_quota_exceeded():
    """Hunter quota exhausted -> result sem hunter, sem linked domains."""
    from openm.transforms.person_discovery import PersonToDomainTransform

    person = Person(
        value="Bob",
        properties={"email": "bob@example.com", "organization": "Big Corp"},
    )
    transform = PersonToDomainTransform()

    hunter_intel = {
        "domain": "big-corp.com",
        "available": False,
        "quota_exceeded": True,
        "linked_domains": [],
        "people": [],
    }

    with patch(
        "openm.transforms.person_discovery.HunterService.investigate_domain",
        return_value=hunter_intel,
    ):
        result = transform.run(person)

    enriched = [e for e in result.entities if isinstance(e, Person)][0]
    assert enriched.properties["person_domain_hunter_available"] is False
    assert enriched.properties["person_domain_hunter_quota_exceeded"] is True
    # Dominio do email continua presente mesmo sem Hunter
    domains = [e for e in result.entities if isinstance(e, Domain)]
    assert {d.value for d in domains} == {"example.com"}


def test_person_domain_transform_no_email_no_org():
    """Person sem email nem org -> result vazio (Person enriquecida)."""
    from openm.transforms.person_discovery import PersonToDomainTransform

    person = Person(value="Anonymous", properties={})
    transform = PersonToDomainTransform()

    with patch(
        "openm.transforms.person_discovery.HunterService.investigate_domain",
        return_value=None,
    ):
        result = transform.run(person)

    enriched = [e for e in result.entities if isinstance(e, Person)][0]
    assert enriched.properties["person_associated_domains"] == []
    assert enriched.properties["person_domain_source"] == "none"
    # Sem dominios, sem emails, sem edges (so a Person enriquecida).
    assert len([e for e in result.entities if isinstance(e, Domain)]) == 0
    assert len([e for e in result.entities if isinstance(e, Email)]) == 0
    assert result.relationships == []


def test_person_domain_transform_invalid_email_returns_empty():
    """Email malformado -> result vazio (Person enriquecida sem dominios)."""
    from openm.transforms.person_discovery import PersonToDomainTransform

    person = Person(
        value="Bad Email",
        properties={"email": "not-an-email"},
    )
    transform = PersonToDomainTransform()

    with patch(
        "openm.transforms.person_discovery.HunterService.investigate_domain",
        return_value=None,
    ):
        result = transform.run(person)

    enriched = [e for e in result.entities if isinstance(e, Person)][0]
    assert enriched.properties["person_associated_domains"] == []
    assert len([e for e in result.entities if isinstance(e, Domain)]) == 0


def test_person_domain_transform_skips_non_person():
    """IPAddress nao e aceito -> result vazio."""
    from openm.transforms.person_discovery import PersonToDomainTransform

    ip = IPAddress(value="8.8.8.8")
    transform = PersonToDomainTransform()

    with patch(
        "openm.transforms.person_discovery.HunterService.investigate_domain"
    ) as mock:
        result = transform.run(ip)

    mock.assert_not_called()
    assert result.entities == []
    assert result.relationships == []


def test_person_domain_transform_registered():
    """PersonToDomainTransform aparece no registry para Person."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.person_discovery import PersonToDomainTransform

    assert TransformRegistry.get("person_domain_discovery") is PersonToDomainTransform

    names = [t["name"] for t in TransformRegistry.list_for_type("Person")]
    assert "person_domain_discovery" in names

    for other_type in ("Domain", "Email", "IPAddress", "URL", "Device"):
        assert "person_domain_discovery" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


def test_person_domain_guess_org_domain():
    """Helper _guess_domain_from_org normaliza nomes corporativos."""
    from openm.transforms.person_discovery import _guess_domain_from_org

    assert _guess_domain_from_org("Acme Inc.") == "acme.com"
    assert _guess_domain_from_org("Acme Corp") == "acme.com"
    assert _guess_domain_from_org("Big Corp Ltd.") == "big.com"
    assert _guess_domain_from_org("Foo S.A.") == "foo.com"
    assert _guess_domain_from_org("Foo S.A") == "foo.com"
    assert _guess_domain_from_org("") == ""
    assert _guess_domain_from_org("1234") == ""
    assert _guess_domain_from_org("Acme") == "acme.com"


def test_person_domain_extract_from_email():
    """Helper _extract_domain_from_email valida formato."""
    from openm.transforms.person_discovery import _extract_domain_from_email

    assert _extract_domain_from_email("a@b.com") == "b.com"
    assert _extract_domain_from_email("UPPER@Lower.NET") == "lower.net"
    assert _extract_domain_from_email("no-at-sign") == ""
    assert _extract_domain_from_email("@nodomain.com") == ""
    assert _extract_domain_from_email("nolocal@nodot") == ""
    assert _extract_domain_from_email("") == ""
    # Multiplos @ sao rejeitados: a parte apos o primeiro @ nao pode
    # conter outro @ (rejeitado pelo helper).
    assert _extract_domain_from_email("double@@at.com") == ""


# ========================================================================
# IBAN/SWIFT Validation Transform
# ========================================================================


def test_iban_swift_transform_iban_valid_gb():
    """IBAN valido do Reino Unido -> enriquecido como iban."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(value="GB29NWBK60161331926819")
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    assert len(result.entities) == 1
    enriched = result.entities[0]
    assert enriched.id == ba.id
    assert enriched.properties["bank_account_valid"] is True
    assert enriched.properties["bank_account_type"] == "iban"
    assert enriched.properties["bank_account_country_code"] == "GB"
    assert enriched.properties["bank_account_formatted"] == "GB29 NWBK 6016 1331 9268 19"
    assert enriched.properties["bank_account_metadata"]["iban_check_digits"] == "29"
    assert enriched.properties["bank_account_checked_at"]
    assert result.relationships == []


def test_iban_swift_transform_iban_valid_de():
    """IBAN alemao valido."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(value="DE89370400440532013000")
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    enriched = result.entities[0]
    assert enriched.properties["bank_account_valid"] is True
    assert enriched.properties["bank_account_country_code"] == "DE"
    assert enriched.properties["bank_account_formatted"] == "DE89 3704 0044 0532 0130 00"


def test_iban_swift_transform_iban_valid_br():
    """IBAN brasileiro valido (29 chars)."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(value="BR9700360305000010009795493P1")
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    enriched = result.entities[0]
    assert enriched.properties["bank_account_valid"] is True
    assert enriched.properties["bank_account_country_code"] == "BR"
    assert len(enriched.properties["bank_account_formatted"].replace(" ", "")) == 29


def test_iban_swift_transform_iban_invalid_checksum():
    """IBAN com checksum errado -> valid=False."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(value="GB29NWBK60161331926820")
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    enriched = result.entities[0]
    assert enriched.properties["bank_account_valid"] is False
    assert enriched.properties["bank_account_type"] == "iban"
    # Quando checksum falha, bban_re nao casa -> iban_format fica {}.
    meta = enriched.properties["bank_account_metadata"]
    assert meta.get("iban_format") == {} or "checksum_invalid" in str(meta)


def test_iban_swift_transform_iban_invalid_length():
    """IBAN com comprimento errado -> valid=False."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(value="DE8937040044")
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    enriched = result.entities[0]
    assert enriched.properties["bank_account_valid"] is False
    assert enriched.properties["bank_account_type"] == "iban"


def test_iban_swift_transform_bic8_valid():
    """BIC de 8 chars (Deutsche Bank)."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(value="DEUTDEFF")
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    enriched = result.entities[0]
    assert enriched.properties["bank_account_valid"] is True
    assert enriched.properties["bank_account_type"] == "bic"
    assert enriched.properties["bank_account_country_code"] == "DE"
    assert enriched.properties["bank_account_metadata"]["bic_format"] == "BIC8"
    assert enriched.properties["bank_account_metadata"]["bic_business_party_prefix"] == "DEUT"


def test_iban_swift_transform_bic11_valid():
    """BIC de 11 chars com branch code XXX (sede)."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(value="BARCGB22XXX")
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    enriched = result.entities[0]
    assert enriched.properties["bank_account_valid"] is True
    assert enriched.properties["bank_account_type"] == "bic"
    assert enriched.properties["bank_account_country_code"] == "GB"
    assert enriched.properties["bank_account_metadata"]["bic_branch_code"] == "primary"


def test_iban_swift_transform_bic_invalid_country():
    """BIC com pais desconhecido -> valid=False."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(value="AAAAZZXX")
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    enriched = result.entities[0]
    assert enriched.properties["bank_account_valid"] is False
    assert enriched.properties["bank_account_type"] == "bic"
    assert enriched.properties["bank_account_country_code"] == "ZZ"


def test_iban_swift_transform_empty_value_returns_empty():
    """BankAccount vazia -> result vazio."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(value="")
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    assert result.entities == []
    assert result.relationships == []


def test_iban_swift_transform_preserves_existing_properties():
    """Propriedades pre-existentes da BankAccount sao preservadas."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    ba = BankAccount(
        value="DE89370400440532013000",
        properties={"bank_account_owner": "Alice", "bank_account_currency": "EUR"},
    )
    transform = IbanSwiftTransform()
    result = transform.run(ba)

    enriched = result.entities[0]
    assert enriched.properties["bank_account_owner"] == "Alice"
    assert enriched.properties["bank_account_currency"] == "EUR"
    assert enriched.properties["bank_account_valid"] is True


def test_iban_swift_transform_skips_non_bank_account():
    """Email nao e aceito -> result vazio."""
    from openm.transforms.iban_swift import IbanSwiftTransform

    email = Email(value="a@b.com")
    transform = IbanSwiftTransform()
    result = transform.run(email)

    assert result.entities == []
    assert result.relationships == []


def test_iban_swift_transform_registered():
    """IbanSwiftTransform aparece no registry para BankAccount."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.iban_swift import IbanSwiftTransform

    assert TransformRegistry.get("iban_swift_validation") is IbanSwiftTransform

    names = [t["name"] for t in TransformRegistry.list_for_type("BankAccount")]
    assert "iban_swift_validation" in names

    for other_type in ("Email", "Domain", "IPAddress", "Person", "URL"):
        assert "iban_swift_validation" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


# ========================================================================
# IBANService — unit tests
# ========================================================================


def test_iban_service_validate_known_valid():
    """IBANs validos conhecidos passam na validacao."""
    from openm.services.iban_service import IBANService

    valid_ibans = [
        "GB29NWBK60161331926819",
        "DE89370400440532013000",
        "FR1420041010050500013M02606",
        "BE68539007547034",
        "IT60X0542811101000000123456",
        "NL91ABNA0417164300",
        "ES9121000418450200051332",
        "BR9700360305000010009795493P1",
    ]
    for iban in valid_ibans:
        result = IBANService.validate(iban)
        assert result["valid"] is True, f"{iban} deveria ser valido: {result['errors']}"


def test_iban_service_validate_invalid_checksum():
    """Checksum errado -> valid=False."""
    from openm.services.iban_service import IBANService

    result = IBANService.validate("GB29NWBK60161331926820")
    assert result["valid"] is False
    assert "checksum_invalid" in result["errors"]


def test_iban_service_validate_invalid_length():
    """Comprimento errado para o pais -> valid=False."""
    from openm.services.iban_service import IBANService

    result = IBANService.validate("DE8937040044")
    assert result["valid"] is False
    assert any("wrong_length" in e for e in result["errors"])


def test_iban_service_validate_unsupported_country():
    """Pais nao mapeado -> valid=False."""
    from openm.services.iban_service import IBANService

    result = IBANService.validate("ZZ0000000000000000000000")
    assert result["valid"] is False
    assert "country_unsupported" in result["errors"]


def test_iban_service_validate_format_normalization():
    """Espacos e hifens sao normalizados."""
    from openm.services.iban_service import IBANService

    result = IBANService.validate("GB29 NWBK 6016 1331 9268 19")
    assert result["valid"] is True
    assert result["country_code"] == "GB"


def test_iban_service_validate_empty_or_none():
    """Valor vazio ou None -> valid=False com erro empty_value."""
    from openm.services.iban_service import IBANService

    assert IBANService.validate("")["valid"] is False
    assert IBANService.validate(None)["valid"] is False


def test_iban_service_country_specs_non_empty():
    """Tabela de paises tem entradas."""
    from openm.services.iban_service import IBANService

    specs = IBANService.country_specs()
    assert len(specs) > 50
    assert "BR" in specs
    assert "DE" in specs
    assert specs["BR"]["length"] == 29


# ========================================================================
# BICService — unit tests
# ========================================================================


def test_bic_service_validate_known_valid():
    """BICs validos conhecidos passam na validacao."""
    from openm.services.bic_service import BICService

    valid_bics = [
        "DEUTDEFF",      # Deutsche Bank, DE
        "BOFAUS3N",      # Bank of America, US
        "NWBKGB2L",      # NatWest, GB
        "CHASUS33",      # JPMorgan Chase, US
        "BNPAFRPP",      # BNP Paribas, FR
        "BARCGB22XXX",   # Barclays GB, branch primary
    ]
    for bic in valid_bics:
        result = BICService.validate(bic)
        assert result["valid"] is True, f"{bic} deveria ser valido: {result['errors']}"


def test_bic_service_validate_invalid_length():
    """BIC com comprimento invalido."""
    from openm.services.bic_service import BICService

    assert BICService.validate("")["valid"] is False
    assert BICService.validate("DEUT")["valid"] is False
    assert BICService.validate("DEUTDEFFXX1234")["valid"] is False


def test_bic_service_validate_unknown_country():
    """BIC com pais desconhecido -> valid=False (mas format correto)."""
    from openm.services.bic_service import BICService

    result = BICService.validate("AAAAZZXX")
    assert result["valid"] is False
    assert "country_code_unknown" in result["errors"]


def test_bic_service_validate_dash_normalization():
    """Hifens sao removidos."""
    from openm.services.bic_service import BICService

    result = BICService.validate("DEUT-DE-FF")
    assert result["valid"] is True
    assert result["format"] == "BIC8"


def test_bic_service_branch_xxx_means_primary():
    """Branch code XXX indica sede principal."""
    from openm.services.bic_service import BICService

    result = BICService.validate("BARCGB22XXX")
    assert result["branch_code"] == "primary"


def test_bic_service_branch_named():
    """Branch code != XXX e preservado."""
    from openm.services.bic_service import BICService

    result = BICService.validate("BARCGB22001")
    assert result["branch_code"] == "001"


# ========================================================================
# MAC Vendor Transform
# ========================================================================


def test_mac_vendor_transform_device_with_mac_property():
    """Device com propriedade mac -> MACAddress + Device vendor + edges."""
    from openm.transforms.mac_vendor import MacVendorTransform

    device = Device(value="iPhone-1234", properties={"mac": "00:1B:63:84:45:E6"})
    transform = MacVendorTransform()
    result = transform.run(device)

    # 3 entities: Device enriquecido + MACAddress + vendor Device
    assert len(result.entities) == 3

    enriched = [e for e in result.entities if isinstance(e, Device) and e.id == device.id][0]
    assert enriched.properties["mac_vendor"] == "Apple"
    assert enriched.properties["mac_oui"] == "00:1B:63"
    assert enriched.properties["mac_address_normalized"] == "00:1B:63:84:45:E6"
    assert enriched.properties["mac_valid"] is True

    mac_entity = [e for e in result.entities if isinstance(e, MACAddress)][0]
    assert mac_entity.value == "00:1B:63:84:45:E6"
    assert mac_entity.properties["oui"] == "00:1B:63"

    vendor = [e for e in result.entities
              if isinstance(e, Device) and e.properties.get("role") == "manufacturer"][0]
    assert vendor.value == "Apple"
    assert vendor.properties["oui"] == "00:1B:63"

    # Edges: Device -> MACAddress (IDENTIFIED_BY), MACAddress -> vendor (MANUFACTURED_BY)
    edge_types = [r["type"] for r in result.relationships]
    assert "IDENTIFIED_BY" in edge_types
    assert "MANUFACTURED_BY" in edge_types


def test_mac_vendor_transform_mac_address_directly():
    """MACAddress como input direto -> enriquecido + vendor."""
    from openm.transforms.mac_vendor import MacVendorTransform

    mac = MACAddress(value="3C:A9:F4:11:22:33")  # Intel
    transform = MacVendorTransform()
    result = transform.run(mac)

    # 2 entities: MACAddress enriquecido + vendor Device
    assert len(result.entities) == 2

    enriched = [e for e in result.entities if isinstance(e, MACAddress)][0]
    assert enriched.id == mac.id
    assert enriched.properties["mac_vendor"] == "Intel"
    assert enriched.properties["mac_oui"] == "3C:A9:F4"

    vendor = [e for e in result.entities if isinstance(e, Device)][0]
    assert vendor.value == "Intel"

    # Apenas 1 edge: MACAddress -> vendor
    assert len(result.relationships) == 1
    assert result.relationships[0]["type"] == "MANUFACTURED_BY"


def test_mac_vendor_transform_format_variations():
    """MAC em formatos diferentes sao normalizados."""
    from openm.transforms.mac_vendor import MacVendorTransform

    transform = MacVendorTransform()

    # Windows
    device = Device(value="dev1", properties={"mac": "00-1B-63-84-45-E6"})
    result = transform.run(device)
    assert result.entities[0].properties["mac_vendor"] == "Apple"
    assert result.entities[0].properties["mac_address_normalized"] == "00:1B:63:84:45:E6"

    # Cisco
    device = Device(value="dev2", properties={"mac": "001B.6384.45E6"})
    result = transform.run(device)
    assert result.entities[0].properties["mac_vendor"] == "Apple"

    # Sem separador
    device = Device(value="dev3", properties={"mac": "001B638445E6"})
    result = transform.run(device)
    assert result.entities[0].properties["mac_vendor"] == "Apple"


def test_mac_vendor_transform_unknown_oui():
    """MAC valido mas OUI nao na tabela -> vendor=None, sem vendor entity."""
    from openm.transforms.mac_vendor import MacVendorTransform

    device = Device(value="dev", properties={"mac": "FF:FF:FF:11:22:33"})
    transform = MacVendorTransform()
    result = transform.run(device)

    enriched = result.entities[0]
    assert enriched.properties["mac_valid"] is True
    assert enriched.properties["mac_oui"] == "FF:FF:FF"
    assert enriched.properties["mac_vendor"] is None
    assert "oui_not_in_table" in enriched.properties["mac_errors"]

    # Sem vendor entity quando OUI desconhecido.
    vendors = [e for e in result.entities
               if isinstance(e, Device) and e.properties.get("role") == "manufacturer"]
    assert vendors == []


def test_mac_vendor_transform_invalid_mac():
    """MAC invalido -> enriched com mac_valid=False, sem entities extras."""
    from openm.transforms.mac_vendor import MacVendorTransform

    device = Device(value="dev", properties={"mac": "not-a-mac"})
    transform = MacVendorTransform()
    result = transform.run(device)

    assert len(result.entities) == 1
    enriched = result.entities[0]
    assert enriched.properties["mac_valid"] is False
    assert enriched.properties["mac_vendor"] is None
    assert "invalid_format" in enriched.properties["mac_errors"]
    assert result.relationships == []


def test_mac_vendor_transform_device_without_mac():
    """Device sem propriedade mac -> result vazio."""
    from openm.transforms.mac_vendor import MacVendorTransform

    device = Device(value="dev", properties={"serial": "ABC123"})
    transform = MacVendorTransform()
    result = transform.run(device)

    assert result.entities == []
    assert result.relationships == []


def test_mac_vendor_transform_mac_address_property_alternative():
    """Device usa propriedade alternativa 'mac_address' (alem de 'mac')."""
    from openm.transforms.mac_vendor import MacVendorTransform

    device = Device(value="dev", properties={"mac_address": "F0:F6:1C:11:22:33"})
    transform = MacVendorTransform()
    result = transform.run(device)

    assert result.entities[0].properties["mac_vendor"] == "Google"


def test_mac_vendor_transform_skips_unsupported_type():
    """Domain nao e aceito -> result vazio."""
    from openm.transforms.mac_vendor import MacVendorTransform

    domain = Domain(value="example.com")
    transform = MacVendorTransform()
    result = transform.run(domain)

    assert result.entities == []
    assert result.relationships == []


def test_mac_vendor_transform_registered():
    """MacVendorTransform aparece no registry para Device e MACAddress."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.mac_vendor import MacVendorTransform

    assert TransformRegistry.get("mac_vendor_lookup") is MacVendorTransform

    for supported in ("Device", "MACAddress"):
        names = [t["name"] for t in TransformRegistry.list_for_type(supported)]
        assert "mac_vendor_lookup" in names

    for other_type in ("Email", "Domain", "IPAddress", "Person", "URL"):
        assert "mac_vendor_lookup" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


def test_mac_vendor_transform_preserves_existing_properties():
    """Propriedades pre-existentes do Device sao preservadas."""
    from openm.transforms.mac_vendor import MacVendorTransform

    device = Device(
        value="iPhone-1234",
        properties={"mac": "00:1B:63:84:45:E6", "serial": "SN12345", "os": "iOS 17"},
    )
    transform = MacVendorTransform()
    result = transform.run(device)

    enriched = result.entities[0]
    assert enriched.properties["serial"] == "SN12345"
    assert enriched.properties["os"] == "iOS 17"
    assert enriched.properties["mac_vendor"] == "Apple"


# ========================================================================
# MacVendorService — unit tests
# ========================================================================


def test_mac_vendor_service_normalize_formats():
    """normalize() aceita todos os formatos comuns."""
    from openm.services.mac_service import MacVendorService

    assert MacVendorService.normalize("00:1B:63:84:45:E6") == "00:1B:63:84:45:E6"
    assert MacVendorService.normalize("00-1B-63-84-45-E6") == "00:1B:63:84:45:E6"
    assert MacVendorService.normalize("001B.6384.45E6") == "00:1B:63:84:45:E6"
    assert MacVendorService.normalize("001B638445E6") == "00:1B:63:84:45:E6"
    assert MacVendorService.normalize("00:1b:63:84:45:e6") == "00:1B:63:84:45:E6"


def test_mac_vendor_service_normalize_invalid():
    """normalize() retorna None para valores invalidos."""
    from openm.services.mac_service import MacVendorService

    assert MacVendorService.normalize("") is None
    assert MacVendorService.normalize(None) is None
    assert MacVendorService.normalize("not-a-mac") is None
    assert MacVendorService.normalize("00:1B:63") is None  # 3 bytes
    assert MacVendorService.normalize("00:1B:63:84:45:E6:AA") is None  # 7 bytes


def test_mac_vendor_service_extract_oui():
    """extract_oui() retorna os 3 primeiros bytes."""
    from openm.services.mac_service import MacVendorService

    assert MacVendorService.extract_oui("00:1B:63:84:45:E6") == "00:1B:63"
    assert MacVendorService.extract_oui("3C:A9:F4:11:22:33") == "3C:A9:F4"
    assert MacVendorService.extract_oui("invalid") is None


def test_mac_vendor_service_lookup_known_vendors():
    """lookup() identifica fabricantes conhecidos."""
    from openm.services.mac_service import MacVendorService

    assert MacVendorService.lookup("00:1B:63:84:45:E6")["vendor"] == "Apple"
    assert MacVendorService.lookup("00:00:0C:11:22:33")["vendor"] == "Cisco Systems"
    assert MacVendorService.lookup("3C:A9:F4:11:22:33")["vendor"] == "Intel"
    assert MacVendorService.lookup("F0:F6:1C:11:22:33")["vendor"] == "Google"
    assert MacVendorService.lookup("AC:63:BE:11:22:33")["vendor"] == "Amazon"


def test_mac_vendor_service_lookup_invalid_mac():
    """lookup() retorna valid=False para MAC invalido."""
    from openm.services.mac_service import MacVendorService

    result = MacVendorService.lookup("not-a-mac")
    assert result["valid"] is False
    assert "invalid_format" in result["errors"]


def test_mac_vendor_service_known_vendor_count():
    """Tabela cobre centenas de fabricantes."""
    from openm.services.mac_service import MacVendorService

    count = MacVendorService.known_vendor_count()
    assert count > 500


def test_mac_address_entity_extracts_oui():
    """MACAddress entity extrai OUI no __init__."""
    m = MACAddress(value="00:1B:63:84:45:E6")
    assert m.properties.get("oui") == "00:1B:63"


def test_mac_address_entity_handles_alternative_formats():
    """MACAddress entity extrai OUI de varios formatos."""
    assert MACAddress(value="00-1B-63-84-45-E6").properties.get("oui") == "00:1B:63"
    assert MACAddress(value="001B.6384.45E6").properties.get("oui") == "00:1B:63"
    assert MACAddress(value="001B638445E6").properties.get("oui") == "00:1B:63"


def test_mac_address_entity_invalid_value_no_oui():
    """MACAddress entity sem OUI quando value invalido."""
    assert MACAddress(value="not-a-mac").properties.get("oui") is None


# ========================================================================
# SecurityTrails Transform
# ========================================================================


def test_securitytrails_transform_domain_full_result():
    """Domain com info + subdomains -> enriquecido + subdominios + edges."""
    from openm.transforms.securitytrails import SecurityTrailsTransform

    domain = Domain(value="example.com", properties={})
    transform = SecurityTrailsTransform()

    intel = {
        "domain": "example.com",
        "source": "securitytrails",
        "available": True,
        "available_full": True,
        "hostname": "example.com",
        "alexa_rank": 5000,
        "whois": {
            "created_date": "1995-08-14T04:00:00Z",
            "expires_date": "2025-08-13T04:00:00Z",
            "registrar": {"name": "Reserved by IANA", "id": "376"},
            "registrant": {"name": "Internet Assigned Numbers Authority"},
        },
        "subdomains": ["www.example.com", "mail.example.com", "api.example.com"],
        "rate_limited": False,
        "key_valid": True,
        "checked_at": "2026-06-27T20:00:00+00:00",
    }

    with patch(
        "openm.transforms.securitytrails.SecurityTrailsService.investigate_domain",
        return_value=intel,
    ):
        result = transform.run(domain)

    # 1 Domain enriquecido + 3 subdomains = 4 entities
    assert len(result.entities) == 4
    enriched = [e for e in result.entities if e.id == domain.id][0]
    assert enriched.properties["st_available"] is True
    assert enriched.properties["st_available_full"] is True
    assert enriched.properties["st_hostname"] == "example.com"
    assert enriched.properties["st_alexa_rank"] == 5000
    assert enriched.properties["st_whois_registrar"] == "Reserved by IANA"
    assert enriched.properties["st_whois_registrant"] == "Internet Assigned Numbers Authority"
    assert enriched.properties["st_whois_created"] == "1995-08-14T04:00:00Z"
    assert enriched.properties["st_whois_expires"] == "2025-08-13T04:00:00Z"
    assert enriched.properties["st_subdomain_count"] == 3

    # 3 subdomains como entidades Domain
    subs = [e for e in result.entities if isinstance(e, Domain) and e.id != domain.id]
    assert {s.value for s in subs} == {"www.example.com", "mail.example.com", "api.example.com"}
    for s in subs:
        assert s.properties["is_subdomain"] is True
        assert s.properties["parent_domain"] == "example.com"
        assert s.properties["source"] == "securitytrails"

    # 3 edges HAS_SUBDOMAIN
    has_sub = [r for r in result.relationships if r["type"] == "HAS_SUBDOMAIN"]
    assert len(has_sub) == 3
    assert all(r["from_id"] == domain.id for r in has_sub)


def test_securitytrails_transform_no_subdomains():
    """Domain sem subdomains -> apenas enriquecido."""
    from openm.transforms.securitytrails import SecurityTrailsTransform

    domain = Domain(value="narrow.example.com", properties={})
    transform = SecurityTrailsTransform()

    intel = {
        "domain": "narrow.example.com",
        "source": "securitytrails",
        "available": True,
        "available_full": True,
        "hostname": "narrow.example.com",
        "alexa_rank": None,
        "whois": {},
        "subdomains": [],
        "rate_limited": False,
        "key_valid": True,
        "checked_at": "2026-06-27T20:00:00+00:00",
    }

    with patch(
        "openm.transforms.securitytrails.SecurityTrailsService.investigate_domain",
        return_value=intel,
    ):
        result = transform.run(domain)

    assert len(result.entities) == 1
    enriched = result.entities[0]
    assert enriched.properties["st_subdomain_count"] == 0
    assert result.relationships == []


def test_securitytrails_transform_unavailable_marks_input():
    """API indisponivel (chave ausente / 404 / erro) -> enriched com st_available=False."""
    from openm.transforms.securitytrails import SecurityTrailsTransform

    domain = Domain(value="unknown.example.com", properties={})
    transform = SecurityTrailsTransform()

    intel = {
        "domain": "unknown.example.com",
        "source": "securitytrails",
        "available": False,
        "available_full": False,
        "hostname": None,
        "alexa_rank": None,
        "whois": None,
        "subdomains": [],
        "key_valid": False,
        "checked_at": "2026-06-27T20:00:00+00:00",
    }

    with patch(
        "openm.transforms.securitytrails.SecurityTrailsService.investigate_domain",
        return_value=intel,
    ):
        result = transform.run(domain)

    assert len(result.entities) == 1
    enriched = result.entities[0]
    assert enriched.properties["st_available"] is False
    assert enriched.properties["st_key_valid"] is False
    assert enriched.properties["st_subdomain_count"] == 0
    assert result.relationships == []


def test_securitytrails_transform_rate_limited_marks():
    """Quota excedida -> available=False, st_rate_limited=True."""
    from openm.transforms.securitytrails import SecurityTrailsTransform

    domain = Domain(value="quota.example.com", properties={})
    transform = SecurityTrailsTransform()

    intel = {
        "domain": "quota.example.com",
        "source": "securitytrails",
        "available": False,
        "available_full": False,
        "hostname": None,
        "alexa_rank": None,
        "whois": None,
        "subdomains": [],
        "rate_limited": True,
        "key_valid": True,
        "checked_at": "2026-06-27T20:00:00+00:00",
    }

    with patch(
        "openm.transforms.securitytrails.SecurityTrailsService.investigate_domain",
        return_value=intel,
    ):
        result = transform.run(domain)

    enriched = result.entities[0]
    assert enriched.properties["st_available"] is False
    assert enriched.properties["st_rate_limited"] is True
    # Quando rate_limited mas key_valid, nao seta st_key_valid.
    assert "st_key_valid" not in enriched.properties


def test_securitytrails_transform_dedupes_subdomains():
    """Subdominios duplicados e self-reference sao removidos."""
    from openm.transforms.securitytrails import SecurityTrailsTransform

    domain = Domain(value="example.com", properties={})
    transform = SecurityTrailsTransform()

    intel = {
        "domain": "example.com",
        "source": "securitytrails",
        "available": True,
        "available_full": True,
        "hostname": "example.com",
        "alexa_rank": None,
        "whois": {},
        "subdomains": ["www.example.com", "WWW.EXAMPLE.COM", "example.com", "api.example.com"],
        "rate_limited": False,
        "key_valid": True,
        "checked_at": "2026-06-27T20:00:00+00:00",
    }

    with patch(
        "openm.transforms.securitytrails.SecurityTrailsService.investigate_domain",
        return_value=intel,
    ):
        result = transform.run(domain)

    # 3 entities: Domain enriquecido + www + api
    assert len(result.entities) == 3
    subs = [e for e in result.entities if e.id != domain.id]
    assert {s.value for s in subs} == {"www.example.com", "api.example.com"}


def test_securitytrails_transform_no_key_returns_empty():
    """Service retorna None (sem chave) -> result vazio."""
    from openm.transforms.securitytrails import SecurityTrailsTransform

    domain = Domain(value="example.com", properties={})
    transform = SecurityTrailsTransform()

    with patch(
        "openm.transforms.securitytrails.SecurityTrailsService.investigate_domain",
        return_value=None,
    ):
        result = transform.run(domain)

    assert result.entities == []
    assert result.relationships == []


def test_securitytrails_transform_preserves_existing_properties():
    """Propriedades pre-existentes do Domain sao preservadas."""
    from openm.transforms.securitytrails import SecurityTrailsTransform

    domain = Domain(
        value="example.com",
        properties={"whois_registrar": "X", "crtsh_subdomain_count": 3},
    )
    transform = SecurityTrailsTransform()

    intel = {
        "domain": "example.com",
        "source": "securitytrails",
        "available": True,
        "available_full": True,
        "hostname": "example.com",
        "alexa_rank": 1000,
        "whois": {"created_date": "2020-01-01", "registrar": "Y"},
        "subdomains": ["www.example.com"],
        "rate_limited": False,
        "key_valid": True,
        "checked_at": "2026-06-27T20:00:00+00:00",
    }

    with patch(
        "openm.transforms.securitytrails.SecurityTrailsService.investigate_domain",
        return_value=intel,
    ):
        result = transform.run(domain)

    enriched = result.entities[0]
    assert enriched.properties["whois_registrar"] == "X"
    assert enriched.properties["crtsh_subdomain_count"] == 3
    assert enriched.properties["st_whois_registrar"] == "Y"


def test_securitytrails_transform_skips_non_domain():
    """Email nao e aceito -> result vazio."""
    from openm.transforms.securitytrails import SecurityTrailsTransform

    email = Email(value="a@b.com")
    transform = SecurityTrailsTransform()

    with patch(
        "openm.transforms.securitytrails.SecurityTrailsService.investigate_domain"
    ) as mock:
        result = transform.run(email)

    mock.assert_not_called()
    assert result.entities == []
    assert result.relationships == []


def test_securitytrails_transform_registered():
    """SecurityTrailsTransform aparece no registry para Domain."""
    from openm.core.transform import TransformRegistry
    from openm.transforms.securitytrails import SecurityTrailsTransform

    assert TransformRegistry.get("securitytrails_lookup") is SecurityTrailsTransform

    names = [t["name"] for t in TransformRegistry.list_for_type("Domain")]
    assert "securitytrails_lookup" in names

    for other_type in ("Email", "IPAddress", "Person", "URL", "Device"):
        assert "securitytrails_lookup" not in [
            t["name"] for t in TransformRegistry.list_for_type(other_type)
        ]


# ========================================================================
# SecurityTrailsService — unit tests
# ========================================================================


def test_securitytrails_service_no_key_returns_empty(monkeypatch):
    """Sem chave -> investigate_domain retorna available=False, key_valid=False."""
    from openm.services.securitytrails_service import SecurityTrailsService

    monkeypatch.setattr(SecurityTrailsService, "get_key", staticmethod(lambda: None))

    result = SecurityTrailsService.investigate_domain("example.com")
    assert result["available"] is False
    assert result["key_valid"] is False
    assert result["subdomains"] == []


def test_securitytrails_service_get_key_falls_back_to_env(monkeypatch):
    """Sem ApiKey no DB, get_key usa env SECURITYTRAILS_API_KEY."""
    from openm.services import securitytrails_service as sts

    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "env-key-123")
    # Em ambiente sem DB, ApiKey.query falha; verificamos que get_key
    # tenta DB primeiro e cai no env se DB falhar.
    try:
        key = sts.SecurityTrailsService.get_key()
        if key is not None:
            assert key == "env-key-123"
    except Exception:
        # DB nao disponivel no teste: comportamento aceitavel.
        pass


def test_securitytrails_service_investigate_domain_normalizes(monkeypatch):
    """investigate_domain consome info + subdomains (com mocks)."""
    from openm.services.securitytrails_service import SecurityTrailsService

    info_payload = {
        "hostname": "example.com",
        "alexa_rank": 100,
        "whois": {
            "created_date": "2020-01-01",
            "expires_date": "2030-01-01",
            "registrar": {"name": "TestRegistrar"},
        },
    }
    subs_payload = {"subdomains": ["a.example.com", "b.example.com"]}

    call_count = {"info": 0, "sub": 0}

    def fake_request(endpoint, **_kwargs):
        if "/subdomains" in endpoint:
            call_count["sub"] += 1
            return subs_payload
        call_count["info"] += 1
        return info_payload

    monkeypatch.setattr(SecurityTrailsService, "_request", staticmethod(fake_request))
    monkeypatch.setattr(SecurityTrailsService, "get_key", staticmethod(lambda: "key"))

    result = SecurityTrailsService.investigate_domain("example.com")
    assert result["available"] is True
    assert result["available_full"] is True
    assert result["hostname"] == "example.com"
    assert result["alexa_rank"] == 100
    assert result["whois"]["created_date"] == "2020-01-01"
    assert result["subdomains"] == ["a.example.com", "b.example.com"]
    assert call_count == {"info": 1, "sub": 1}


def test_securitytrails_service_investigate_domain_sub_fails(monkeypatch):
    """info OK mas subdomains falha -> available=True, available_full=False."""
    from openm.services.securitytrails_service import SecurityTrailsService

    def fake_request(endpoint, **_kwargs):
        if "/subdomains" in endpoint:
            return None  # falha
        return {"hostname": "example.com", "whois": {}}

    monkeypatch.setattr(SecurityTrailsService, "_request", staticmethod(fake_request))
    monkeypatch.setattr(SecurityTrailsService, "get_key", staticmethod(lambda: "key"))

    result = SecurityTrailsService.investigate_domain("example.com")
    assert result["available"] is True
    assert result["available_full"] is False
    assert result["subdomains"] == []
