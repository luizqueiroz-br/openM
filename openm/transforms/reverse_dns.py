from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Domain, Entity, IPAddress
from openm.core.transform import Transform, TransformResult
from openm.services.dns_service import reverse_dns


@Transform.register
class ReverseDnsTransform(Transform):
    """
    Transform que resolve um IP para seu nome canônico via PTR (reverse DNS).

    Entrada: IPAddress
    Saída: entidades Domain vinculadas por RESOLVES_TO (mesmo tipo do
           resolve_ip, indicando direção DNS → IP). O domínio canônico
           é marcado com ``reverse_dns_primary=True`` para distinguir
           de resoluções forward.

    Sem API key (consulta DNS pública via socket.gethostbyaddr).
    """

    name = "reverse_dns"
    display_name = "Reverse DNS — IP to Domain (PTR)"
    input_types = ["IPAddress"]
    description = (
        "Resolve um endereço IP para seu nome canônico via registro PTR. "
        "Útil para descobrir domínios hospedados em um IP específico."
    )

    def _run(self, entity: Entity) -> TransformResult:
        result = reverse_dns(entity.value)
        if not result:
            return TransformResult()

        hostname, aliases = result
        checked_at = datetime.now(timezone.utc).isoformat()

        entities: List[Entity] = []
        relationships: List[Dict[str, Any]] = []

        # Domínio canônico
        primary = Domain(
            value=hostname,
            properties={
                "resolved_from_ip": entity.value,
                "resolved_at": checked_at,
                "reverse_dns_primary": True,
                "source": "ptr",
            },
        )
        entities.append(primary)
        relationships.append(
            {
                "from_id": entity.id,
                "to_id": primary.id,
                "type": "RESOLVES_TO",
                "properties": {
                    "source": "ptr",
                    "direction": "reverse",
                    "resolved_at": checked_at,
                },
            }
        )

        # Aliases como Domain adicionais (sem flag primary)
        for alias in aliases:
            if not alias or alias == hostname:
                continue
            alias_entity = Domain(
                value=alias,
                properties={
                    "resolved_from_ip": entity.value,
                    "resolved_at": checked_at,
                    "reverse_dns_primary": False,
                    "source": "ptr",
                },
            )
            entities.append(alias_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": alias_entity.id,
                    "type": "RESOLVES_TO",
                    "properties": {
                        "source": "ptr",
                        "direction": "reverse",
                        "resolved_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
