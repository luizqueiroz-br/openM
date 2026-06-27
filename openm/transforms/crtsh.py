from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Domain, Entity
from openm.core.transform import Transform, TransformResult
from openm.services.crtsh_service import (
    DEFAULT_MAX_RESULTS,
    extract_subdomains,
    query_crtsh,
)


@Transform.register
class CrtShTransform(Transform):
    """
    Transform que consulta Certificate Transparency logs (crt.sh) para
    descobrir subdomínios de um domínio.

    Entrada: Domain
    Saída: entidades Domain adicionais (subdomínios) vinculadas por
           HAS_SUBDOMAIN ao domínio de entrada.

    Sem API key (crt.sh é um serviço público). Limite de resultados
    configurável via env ``OPENM_CRTSH_MAX_RESULTS`` (default: 200).
    """

    name = "crtsh_lookup"
    display_name = "crt.sh — Certificate Transparency Subdomains"
    input_types = ["Domain"]
    description = (
        "Consulta logs de Certificate Transparency (crt.sh) para descobrir "
        "subdomínios de um domínio. Útil para mapear a superfície de ataque "
        "e descobrir hosts esquecidos ou não documentados."
    )
    cache_ttl_seconds = 86400  # 24h — CT logs são append-only

    def _run(self, entity: Entity) -> TransformResult:
        entries = query_crtsh(entity.value)
        checked_at = datetime.now(timezone.utc).isoformat()

        # API falhou → marca como indisponível, sem subdomains
        if entries is None:
            domain_entity = Domain(
                value=entity.value,
                properties={
                    "crtsh_subdomain_count": 0,
                    "crtsh_checked_at": checked_at,
                    "crtsh_source": "crt.sh",
                    "crtsh_available": False,
                },
                entity_id=entity.id,
            )
            return TransformResult(entities=[domain_entity], relationships=[])

        subdomains = extract_subdomains(
            entries,
            parent_domain=entity.value,
            max_results=DEFAULT_MAX_RESULTS,
        )

        # Domínio pai enriquecido (API succeeded, mesmo se sem subdomains)
        domain_props = {
            "crtsh_subdomain_count": len(subdomains),
            "crtsh_certificate_count": len(entries),
            "crtsh_checked_at": checked_at,
            "crtsh_source": "crt.sh",
            "crtsh_available": True,
        }
        domain_entity = Domain(
            value=entity.value,
            properties={**entity.properties, **domain_props},
            entity_id=entity.id,
        )
        entities: List[Entity] = [domain_entity]
        relationships: List[Dict[str, Any]] = []

        # Cada subdomínio como Domain + edge HAS_SUBDOMAIN
        for sub in subdomains:
            sub_entity = Domain(
                value=sub,
                properties={
                    "parent_domain": entity.value,
                    "source": "crt.sh",
                    "discovered_at": checked_at,
                    "is_subdomain": True,
                },
            )
            entities.append(sub_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": sub_entity.id,
                    "type": "HAS_SUBDOMAIN",
                    "properties": {
                        "source": "crt.sh",
                        "discovered_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
