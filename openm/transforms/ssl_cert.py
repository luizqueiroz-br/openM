from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Device, Domain, Entity
from openm.core.transform import Transform, TransformResult
from openm.services.ssl_service import extract_san_domains, inspect_ssl


@Transform.register
class SslCertTransform(Transform):
    """
    Transform que inspeciona o certificado SSL/TLS de um domínio.

    Entrada: Domain
    Saída:
        - Domain enriquecido com metadados SSL (issuer, valid_until,
          fingerprint, signature, etc).
        - 1 Device representando o issuer (CA) com edge SSL_ISSUED_BY.
        - N Domain adicionais (cada SAN) com edge SSL_SAN.

    Sem API key (conexão TLS direta via stdlib ssl + socket).
    """

    name = "ssl_cert_inspect"
    display_name = "SSL/TLS Certificate Inspection"
    input_types = ["Domain"]
    description = (
        "Conecta via TLS no domínio e extrai metadados do certificado "
        "(issuer, validade, fingerprint, SAN list). Cria Device para "
        "o issuer (CA) e Domain para cada SAN entry."
    )
    cache_ttl_seconds = 86400  # 24h — certs mudam raramente

    def _run(self, entity: Entity) -> TransformResult:
        cert_data = inspect_ssl(entity.value)
        if not cert_data:
            # Marca o domínio como enriquecido mesmo sem cert
            checked_at = datetime.now(timezone.utc).isoformat()
            domain_entity = Domain(
                value=entity.value,
                properties={
                    "ssl_checked_at": checked_at,
                    "ssl_source": "ssl",
                    "ssl_available": False,
                },
                entity_id=entity.id,
            )
            return TransformResult(entities=[domain_entity], relationships=[])

        san_domains = extract_san_domains(cert_data)
        # Conta apenas SANs que sao subdomínios distintos (exclui o próprio
        # domain pai, que e comum em certs single-name).
        distinct_san_count = sum(
            1 for s in san_domains if s != entity.value.lower()
        )
        checked_at = datetime.now(timezone.utc).isoformat()

        # Domínio pai enriquecido
        issuer_dict = cert_data.get("issuer") or {}
        subject_dict = cert_data.get("subject") or {}

        domain_props = {
            "ssl_issuer_cn": issuer_dict.get("common") or "",
            "ssl_issuer_org": issuer_dict.get("organization") or "",
            "ssl_issuer_country": issuer_dict.get("country") or "",
            "ssl_subject_cn": subject_dict.get("common") or "",
            "ssl_valid_from": cert_data.get("valid_from") or "",
            "ssl_valid_until": cert_data.get("valid_until") or "",
            "ssl_fingerprint_sha256": cert_data.get("fingerprint_sha256") or "",
            "ssl_version": cert_data.get("version"),
            "ssl_serial_number": cert_data.get("serial_number") or "",
            "ssl_san_count": distinct_san_count,
            "ssl_checked_at": checked_at,
            "ssl_source": "ssl",
            "ssl_available": True,
        }
        domain_entity = Domain(
            value=entity.value,
            properties={**entity.properties, **domain_props},
            entity_id=entity.id,
        )
        entities: List[Entity] = [domain_entity]
        relationships: List[Dict[str, Any]] = []

        # Device para o issuer (CA)
        issuer_cn = issuer_dict.get("common") or ""
        issuer_org = issuer_dict.get("organization") or ""
        if issuer_cn or issuer_org:
            issuer_value = issuer_cn or issuer_org
            issuer_device = Device(
                value=issuer_value,
                properties={
                    "role": "certificate_authority",
                    "issuer_cn": issuer_cn,
                    "issuer_org": issuer_org,
                    "issuer_country": issuer_dict.get("country") or "",
                    "source": "ssl",
                    "checked_at": checked_at,
                },
            )
            entities.append(issuer_device)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": issuer_device.id,
                    "type": "SSL_ISSUED_BY",
                    "properties": {
                        "source": "ssl",
                        "issuer_org": issuer_org,
                        "checked_at": checked_at,
                    },
                }
            )

        # Domain para cada SAN (deduplicado)
        for san in san_domains:
            if san == entity.value.lower():
                # SAN == domínio pai (comum em certs single-name)
                continue
            san_entity = Domain(
                value=san,
                properties={
                    "source": "ssl",
                    "is_san": True,
                    "parent_domain": entity.value,
                    "discovered_at": checked_at,
                },
            )
            entities.append(san_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": san_entity.id,
                    "type": "SSL_SAN",
                    "properties": {
                        "source": "ssl",
                        "discovered_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
