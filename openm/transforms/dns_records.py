from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from openm.core.entity import DnsRecord, Domain, Entity, IPAddress
from openm.core.transform import Transform, TransformResult
from openm.services.dns_records_service import query_records, reverse_dns_ptr


@Transform.register
class DnsRecordsTransform(Transform):
    """
    Transform que consulta registros DNS de um dominio ou IP.

    Entrada: Domain ou IPAddress
    Saida:
        - Entidades DnsRecord para cada registro encontrado
          (A, AAAA, MX, NS, TXT, CNAME, SOA; para IP tambem PTR).
        - Domain enriquecido com metadados da consulta.
        - Relacionamentos HAS_DNS_RECORD do input para cada registro.

    Sem API key (consulta DNS publico via dnspython).
    """

    name = "dns_records_lookup"
    display_name = "DNS Records Lookup"
    input_types = ["Domain", "IPAddress"]
    description = (
        "Consulta registros DNS (A, AAAA, MX, NS, TXT, CNAME, SOA) de um "
        "dominio. Para IPs, faz reverse DNS (PTR) e consulta registros do "
        "hostname descoberto."
    )
    cache_ttl_seconds = 3600  # 1h — DNS records mudam com alguma frequencia

    def _run(self, entity: Entity) -> TransformResult:
        checked_at = datetime.now(timezone.utc).isoformat()

        if isinstance(entity, IPAddress):
            return self._run_ip(entity, checked_at)
        return self._run_domain(entity, checked_at)

    def _run_domain(self, entity: Entity, checked_at: str) -> TransformResult:
        canonical_domain, records = query_records(entity.value)
        return self._build_result(entity, entity.value, canonical_domain, records, checked_at)

    def _run_ip(self, entity: IPAddress, checked_at: str) -> TransformResult:
        result = reverse_dns_ptr(entity.value)
        if not result:
            return TransformResult()

        hostname, aliases, records = result

        # Cria entidade Domain para o hostname PTR (sem conflitar com reverse_dns)
        ptr_domain = Domain(
            value=hostname,
            properties={
                "resolved_from_ip": entity.value,
                "resolved_at": checked_at,
                "source": "dns_ptr",
                "is_ptr_hostname": True,
            },
        )

        dns_result = self._build_result(
            entity,
            hostname,
            hostname,
            records,
            checked_at,
            extra_entities=[ptr_domain],
            extra_relationships=[
                {
                    "from_id": entity.id,
                    "to_id": ptr_domain.id,
                    "type": "RESOLVES_TO",
                    "properties": {
                        "source": "dns_ptr",
                        "direction": "reverse",
                        "resolved_at": checked_at,
                    },
                }
            ],
        )

        # Alias adicionais do PTR
        for alias in aliases:
            if not alias or alias == hostname:
                continue
            alias_entity = Domain(
                value=alias,
                properties={
                    "resolved_from_ip": entity.value,
                    "resolved_at": checked_at,
                    "source": "dns_ptr",
                    "is_ptr_hostname": True,
                    "ptr_primary": hostname,
                },
            )
            dns_result.entities.append(alias_entity)
            dns_result.relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": alias_entity.id,
                    "type": "RESOLVES_TO",
                    "properties": {
                        "source": "dns_ptr",
                        "direction": "reverse",
                        "resolved_at": checked_at,
                    },
                }
            )

        # Adiciona registro PTR explicito
        ptr_record = DnsRecord(
            value=hostname,
            properties={
                "record_type": "PTR",
                "record_value": hostname,
                "record_ttl": None,
                "resolved_domain": entity.value,
                "canonical_domain": hostname,
                "resolved_at": checked_at,
                "source": "dns",
                "record_data": {"target": hostname},
            },
        )
        dns_result.entities.append(ptr_record)
        dns_result.relationships.append(
            {
                "from_id": entity.id,
                "to_id": ptr_record.id,
                "type": "HAS_DNS_RECORD",
                "properties": {
                    "record_type": "PTR",
                    "source": "dns",
                    "resolved_at": checked_at,
                },
            }
        )

        return dns_result

    def _build_result(
        self,
        input_entity: Entity,
        queried_domain: str,
        canonical_domain: Optional[str],
        records: List[Dict[str, Any]],
        checked_at: str,
        extra_entities: Optional[List[Entity]] = None,
        extra_relationships: Optional[List[Dict[str, Any]]] = None,
    ) -> TransformResult:
        entities: List[Entity] = list(extra_entities or [])
        relationships: List[Dict[str, Any]] = list(extra_relationships or [])

        # Enriquece o input com metadados da consulta (apenas Domain).
        if isinstance(input_entity, Domain):
            domain_props = {
                "dns_checked_at": checked_at,
                "dns_source": "dns",
                "dns_available": bool(records),
                "dns_canonical_domain": canonical_domain or queried_domain,
                "dns_record_count": len(records),
                "dns_queried_domain": queried_domain,
            }
            enriched_domain = Domain(
                value=input_entity.value,
                properties={**input_entity.properties, **domain_props},
                entity_id=input_entity.id,
            )
            entities.insert(0, enriched_domain)

        seen_values_by_type: Dict[Tuple[str, str], bool] = {}
        for rec in records:
            record_type = rec["record_type"]
            record_value = rec["record_value"]
            key = (record_type, record_value)
            if key in seen_values_by_type:
                continue
            seen_values_by_type[key] = True

            record_entity = DnsRecord(
                value=record_value,
                properties={
                    "record_type": record_type,
                    "record_value": record_value,
                    "record_ttl": rec.get("record_ttl"),
                    "resolved_domain": rec.get("resolved_domain", queried_domain),
                    "canonical_domain": rec.get("canonical_domain") or canonical_domain or queried_domain,
                    "resolved_at": checked_at,
                    "source": "dns",
                    "record_data": rec.get("record_data") or {},
                    "record_priority": rec.get("record_priority"),
                },
            )
            entities.append(record_entity)
            relationships.append(
                {
                    "from_id": input_entity.id,
                    "to_id": record_entity.id,
                    "type": "HAS_DNS_RECORD",
                    "properties": {
                        "record_type": record_type,
                        "source": "dns",
                        "resolved_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
