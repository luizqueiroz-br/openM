from openm.core.entity import (
    BankAccount,
    Device,
    Domain,
    Email,
    ENTITY_CLASSES,
    Entity,
    IPAddress,
    Person,
    URL,
)


def test_entity_base_serialization():
    entity = Entity(value="test", properties={"foo": "bar"})
    data = entity.to_dict()
    assert data["type"] == "Entity"
    assert data["value"] == "test"
    assert data["properties"]["foo"] == "bar"
    assert "id" in data


def test_cytoscape_format():
    ip = IPAddress(value="8.8.8.8", properties={"asn": "AS15169"})
    cyto = ip.to_cytoscape()
    assert cyto["data"]["id"] == ip.id
    assert cyto["data"]["label"] == "8.8.8.8"
    assert cyto["data"]["type"] == "IPAddress"
    assert cyto["data"]["asn"] == "AS15169"


def test_all_entity_subclasses_exist():
    assert set(ENTITY_CLASSES.keys()) == {
        "IPAddress",
        "Email",
        "Domain",
        "Person",
        "BankAccount",
        "Device",
        "URL",
    }


def test_subclass_types():
    assert Domain(value="x.com").type == "Domain"
    assert Email(value="a@b.com").type == "Email"
    assert BankAccount(value="123").type == "BankAccount"
    assert Person(value="John").type == "Person"
    assert Device(value="phone-1").type == "Device"


def test_url_entity():
    """URL entity: type/value/serialization/cytoscape/registration."""
    url = URL(value="https://example.com/login", properties={"path": "/login"})

    # type e value
    assert url.type == "URL"
    assert url.value == "https://example.com/login"

    # serialização
    data = url.to_dict()
    assert data["type"] == "URL"
    assert data["value"] == "https://example.com/login"
    assert data["properties"]["path"] == "/login"
    assert "id" in data

    # cytoscape
    cyto = url.to_cytoscape()
    assert cyto["data"]["id"] == url.id
    assert cyto["data"]["label"] == "https://example.com/login"
    assert cyto["data"]["type"] == "URL"
    assert cyto["data"]["path"] == "/login"

    # registro em ENTITY_CLASSES
    assert ENTITY_CLASSES["URL"] is URL
    instance = ENTITY_CLASSES["URL"](value="https://test.com")
    assert isinstance(instance, URL)
    assert isinstance(instance, Entity)
