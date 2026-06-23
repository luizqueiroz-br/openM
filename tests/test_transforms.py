from unittest.mock import patch

from openm.core.entity import Domain, Email, IPAddress
from openm.transforms.fraud_email import CheckFraudEmailTransform
from openm.transforms.resolve_ip import ResolveIPTransform


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
