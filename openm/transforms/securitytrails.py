from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Domain, Entity
from openm.core.transform import Transform, TransformResult
from openm.services.securitytrails_service import SecurityTrailsService


@Transform.register
class SecurityTrailsTransform(Transform):
    """
    Transform que consulta SecurityTrails para obter dados historicos
    e domínios associados de um Domain.

    Entrada: Domain
    Saida:
      - Domain enriquecida com st_hostname, st_alexa_rank, st_whois_*,
        st_available, st_subdomain_count, st_source='securitytrails'.
      - 1 entidade Domain por subdominio + edge HAS_SUBDOMAIN.
      - Estados: available=True/False, rate_limited=True/False,
        key_valid=True/False (graceful degradation).

    Requer chave de API (ApiKey service_name='securitytrails' ou env
    SECURITYTRAILS_API_KEY). Free tier: 50 queries/mes.

    Endpoint: GET https://api.securitytrails.com/v1/domain/{domain}
    """

    name = "securitytrails_lookup"
    display_name = "SecurityTrails — Domain History & Associated"
    input_types = ["Domain"]
    description = (
        "Consulta SecurityTrails para obter dados historicos, WHOIS, "
        "Alexa rank e subdominios de um Domain. Complementa crt.sh e "
        "WHOIS com perspectiva historica e dominios associados."
    )
    service_name = "securitytrails"
    service_display = "SecurityTrails"
    # Free tier: 50/mes. TTL alto para poupar quota.
    cache_ttl_seconds = 2592000  # 30 dias

    def _run(self, entity: Entity) -> TransformResult:
        checked_at = datetime.now(timezone.utc).isoformat()

        intel = SecurityTrailsService.investigate_domain(entity.value)

        # Enriquece o Domain de input com metadados da API.
        whois = intel.get("whois") or {}
        props: Dict[str, Any] = {
            "st_source": "securitytrails",
            "st_available": bool(intel.get("available", False)),
            "st_available_full": bool(intel.get("available_full", False)),
            "st_checked_at": checked_at,
            "st_hostname": intel.get("hostname"),
            "st_alexa_rank": intel.get("alexa_rank"),
            "st_subdomain_count": len(intel.get("subdomains") or []),
        }
        if isinstance(whois, dict):
            props["st_whois_created"] = whois.get("created_date")
            props["st_whois_expires"] = whois.get("expires_date")
            registrar = whois.get("registrar")
            registrant = whois.get("registrant")
            props["st_whois_registrar"] = (
                registrar.get("name")
                if isinstance(registrar, dict)
                else registrar
            )
            props["st_whois_registrant"] = (
                registrant.get("name")
                if isinstance(registrant, dict)
                else registrant
            )
        if intel.get("rate_limited"):
            props["st_rate_limited"] = True
        if intel.get("key_valid") is False:
            props["st_key_valid"] = False

        enriched = Domain(
            value=entity.value,
            properties={**entity.properties, **props},
            entity_id=entity.id,
        )

        entities: List[Entity] = [enriched]
        relationships: List[Dict[str, Any]] = []

        # Cria entidades Domain para subdominios + edges HAS_SUBDOMAIN.
        seen: set = set()
        for sub in intel.get("subdomains") or []:
            if not isinstance(sub, str) or not sub:
                continue
            sub_lower = sub.strip().lower()
            if not sub_lower or sub_lower == entity.value.lower() or sub_lower in seen:
                continue
            seen.add(sub_lower)
            sub_entity = Domain(
                value=sub_lower,
                properties={
                    "source": "securitytrails",
                    "is_subdomain": True,
                    "parent_domain": entity.value,
                    "discovered_at": checked_at,
                },
            )
            entities.append(sub_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": sub_entity.id,
                    "type": "HAS_SUBDOMAIN",
                    "properties": {
                        "source": "securitytrails",
                        "discovered_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
