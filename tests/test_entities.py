from openm.core.entity import (
    BankAccount,
    Device,
    Domain,
    Email,
    ENTITY_CLASSES,
    Entity,
    IPAddress,
    Person,
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
    }


def test_subclass_types():
    assert Domain(value="x.com").type == "Domain"
    assert Email(value="a@b.com").type == "Email"
    assert BankAccount(value="123").type == "BankAccount"
    assert Person(value="John").type == "Person"
    assert Device(value="phone-1").type == "Device"
