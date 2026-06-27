import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class Entity:
    """
    Modelo base para todas as entidades investigáveis no OpenM.

    Cada entidade vira um nó no Neo4j. Propriedades dinâmicas são
    armazenadas no dicionário `properties`, enquanto `id`, `type`
    e `value` são campos semânticos obrigatórios.
    """

    entity_type: str = "Entity"

    def __init__(
        self,
        value: str,
        properties: Optional[Dict[str, Any]] = None,
        entity_id: Optional[str] = None,
        created_by_user_id: Optional[int] = None,
    ):
        self.id = entity_id or str(uuid.uuid4())
        self.type = self.entity_type
        self.value = value
        self.properties = properties or {}
        self.created_by_user_id = created_by_user_id
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        """Representação serializável da entidade."""
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "properties": self.properties,
            "created_by_user_id": self.created_by_user_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_cytoscape(self) -> Dict[str, Any]:
        """Retorna o formato Cytoscape.js para este nó."""
        return {
            "data": {
                "id": self.id,
                "label": self.value,
                "type": self.type,
                **self.properties,
            }
        }

    def __repr__(self) -> str:
        return f"<{self.type} id={self.id} value={self.value}>"


class IPAddress(Entity):
    """Endereço IPv4 ou IPv6."""
    entity_type = "IPAddress"


class Email(Entity):
    """Endereço de e-mail."""
    entity_type = "Email"


class Domain(Entity):
    """Nome de domínio (ex: example.com)."""
    entity_type = "Domain"


class Person(Entity):
    """Pessoa de interesse em investigação."""
    entity_type = "Person"


class BankAccount(Entity):
    """Conta bancária."""
    entity_type = "BankAccount"


class Device(Entity):
    """Dispositivo (computador, celular, etc)."""
    entity_type = "Device"


class URL(Entity):
    """URL completa (scheme + host + path). Ex: https://example.com/login."""
    entity_type = "URL"


class FileHash(Entity):
    """Hash de arquivo (MD5, SHA1 ou SHA256).

    O algoritmo é inferido a partir do comprimento do value (hex string):
      - 32 chars → md5
      - 40 chars → sha1
      - 64 chars → sha256
      - outro    → unknown

    Também é gravado em ``properties["algorithm"]`` para queries Cypher
    diretas sem precisar recomputar.
    """
    entity_type = "FileHash"

    _LENGTH_TO_ALGO = {
        32: "md5",
        40: "sha1",
        64: "sha256",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        algo = self._LENGTH_TO_ALGO.get(len(self.value.strip()), "unknown")
        self.properties.setdefault("algorithm", algo)


class DnsRecord(Entity):
    """Registro DNS de uma consulta (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR).

    ``value`` é o valor principal do registro (IP, hostname, texto,
    CNAME target, etc). Metadados como ``record_type``, ``record_ttl``,
    ``record_priority`` e dados estruturados específicos ficam em
    ``properties``.
    """
    entity_type = "DnsRecord"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # value deve refletir o campo principal do registro para
        # visualizacao e merge no grafo.
        self.properties.setdefault("record_value", self.value)


# Mapeamento de tipo-string para classe, usado pela API e pelos transforms.
ENTITY_CLASSES = {
    cls.entity_type: cls
    for cls in [
        IPAddress, Email, Domain, Person, BankAccount, Device, URL, FileHash,
        DnsRecord,
    ]
}
