from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Entity, IPAddress
from openm.core.transform import Transform, TransformResult
from openm.services.dns_service import resolve_domain


@Transform.register
class ResolveIPTransform(Transform):
    """
    Transform que resolve um domínio para seus endereços IP.

    Entrada: Domain
    Saída: entidades IPAddress vinculadas por RESOLVES_TO.
    """

    name = "resolve_ip"
    display_name = "Resolve Domain to IPs"
    input_types = ["Domain"]
    description = "Resolve um domínio para seus endereços IPv4 via DNS."
    cache_ttl_seconds = 3600  # 1h — DNS A records podem mudar

    def _run(self, entity: Entity) -> TransformResult:
        ips = resolve_domain(entity.value)
        if not ips:
            return TransformResult()

        entities: List[Entity] = []
        relationships: List[Dict[str, Any]] = []
        resolved_at = datetime.now(timezone.utc).isoformat()

        for ip in ips:
            ip_entity = IPAddress(
                value=ip,
                properties={"resolved_from": entity.value, "resolved_at": resolved_at},
            )
            entities.append(ip_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": ip_entity.id,
                    "type": "RESOLVES_TO",
                    "properties": {
                        "resolved_at": resolved_at,
                        "source": "DNS",
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
