from openm.core.entity import (
    BankAccount,
    Device,
    Domain,
    Email,
    ENTITY_CLASSES,
    Entity,
    FileHash,
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
        "FileHash",
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


def test_filehash_entity_basic():
    """FileHash entity: type/value/serialization/cytoscape/registration."""
    md5 = "d41d8cd98f00b204e9800998ecf8427e"  # 32 chars
    fh = FileHash(value=md5)

    # type e value
    assert fh.type == "FileHash"
    assert fh.value == md5

    # algoritmo inferido do length (32 → md5)
    assert fh.properties["algorithm"] == "md5"

    # serialização
    data = fh.to_dict()
    assert data["type"] == "FileHash"
    assert data["value"] == md5
    assert data["properties"]["algorithm"] == "md5"
    assert "id" in data

    # cytoscape
    cyto = fh.to_cytoscape()
    assert cyto["data"]["id"] == fh.id
    assert cyto["data"]["label"] == md5
    assert cyto["data"]["type"] == "FileHash"
    assert cyto["data"]["algorithm"] == "md5"

    # registro em ENTITY_CLASSES
    assert ENTITY_CLASSES["FileHash"] is FileHash
    instance = ENTITY_CLASSES["FileHash"](value=md5)
    assert isinstance(instance, FileHash)
    assert isinstance(instance, Entity)


def test_filehash_algorithm_inference():
    """FileHash infere algoritmo a partir do comprimento do value."""
    # MD5: 32 hex chars
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert FileHash(value=md5).properties["algorithm"] == "md5"

    # SHA1: 40 hex chars
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert FileHash(value=sha1).properties["algorithm"] == "sha1"

    # SHA256: 64 hex chars
    sha256 = (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert FileHash(value=sha256).properties["algorithm"] == "sha256"

    # Tamanho não-padrão → unknown
    assert FileHash(value="abc").properties["algorithm"] == "unknown"
    assert FileHash(value="").properties["algorithm"] == "unknown"


def test_filehash_preserves_explicit_algorithm():
    """Se properties já tiver 'algorithm', o valor explícito tem prioridade."""
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    fh = FileHash(value=md5, properties={"algorithm": "sha256-custom"})
    # setdefault não sobrescreve valor já presente
    assert fh.properties["algorithm"] == "sha256-custom"
