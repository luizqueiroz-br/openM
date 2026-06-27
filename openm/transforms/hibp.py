from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from openm.core.entity import Breach, Domain, Email, Entity
from openm.core.transform import Transform, TransformResult
from openm.services.hibp_service import HibpService


@Transform.register
class HibpTransform(Transform):
    """
    Transform que consulta Have I Been Pwned para verificar vazamentos
    de um email ou dominio.

    Entrada: Email ou Domain
    Saida:
      - Email/Domain enriquecido com hibp_breach_count,
        hibp_available, hibp_checked_at.
      - Entidades Breach para cada vazamento encontrado.
      - Edges EXPOSED_IN do Email/Domain para cada Breach.

    Requer chave HIBP (ApiKey service_name='hibp' ou env HIBP_API_KEY).
    """

    name = "hibp_breach_lookup"
    display_name = "Have I Been Pwned — Breach Lookup"
    input_types = ["Email", "Domain"]
    description = (
        "Consulta Have I Been Pwned para descobrir vazamentos de dados "
        "associados a um email ou dominio. Cria entidades Breach e "
        "vincula a entidade de entrada."
    )
    service_name = "hibp"
    service_display = "Have I Been Pwned"
    cache_ttl_seconds = 21600  # 6h — API paga, balancear freshness

    def _run(self, entity: Entity) -> TransformResult:
        checked_at = datetime.now(timezone.utc).isoformat()

        if entity.type == "Email":
            return self._run_email(entity, checked_at)
        return self._run_domain(entity, checked_at)

    def _run_email(self, entity: Entity, checked_at: str) -> TransformResult:
        intel = HibpService.investigate_email(entity.value)
        breaches = intel.get("breaches") or []

        email_props: Dict[str, Any] = {
            "hibp_source": intel.get("source", "hibp"),
            "hibp_available": bool(intel.get("available", False)),
            "hibp_breach_count": len(breaches),
            "hibp_checked_at": checked_at,
        }
        enriched = Email(
            value=entity.value,
            properties={**entity.properties, **email_props},
            entity_id=entity.id,
        )
        entities: List[Entity] = [enriched]
        relationships: List[Dict[str, Any]] = []

        for breach_data in breaches:
            breach_entity = self._build_breach(breach_data, checked_at)
            if not breach_entity:
                continue
            entities.append(breach_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": breach_entity.id,
                    "type": "EXPOSED_IN",
                    "properties": {
                        "source": "hibp",
                        "breach_name": breach_entity.value,
                        "checked_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)

    def _run_domain(self, entity: Entity, checked_at: str) -> TransformResult:
        intel = HibpService.investigate_domain(entity.value)
        exposed = intel.get("exposed_emails") or []
        available = bool(intel.get("available", False))

        domain_props: Dict[str, Any] = {
            "hibp_source": intel.get("source", "hibp"),
            "hibp_available": available,
            "hibp_exposed_email_count": len(exposed),
            "hibp_checked_at": checked_at,
        }
        enriched = Domain(
            value=entity.value,
            properties={**entity.properties, **domain_props},
            entity_id=entity.id,
        )
        entities: List[Entity] = [enriched]
        relationships: List[Dict[str, Any]] = []

        # Endpoint pago; se nao disponivel, apenas marca o dominio.
        if not available:
            return TransformResult(entities=entities, relationships=relationships)

        # Para cada email exposto, cria Email + Breach + edges.
        seen_breach_names: set = set()
        for item in exposed:
            email_value = item.get("email")
            if not email_value:
                continue
            email_entity = Email(
                value=email_value,
                properties={
                    "source": "hibp",
                    "exposed_in_domain": entity.value,
                    "discovered_at": checked_at,
                },
            )
            entities.append(email_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": email_entity.id,
                    "type": "HAS_EXPOSED_EMAIL",
                    "properties": {
                        "source": "hibp",
                        "discovered_at": checked_at,
                    },
                }
            )

            for breach_data in item.get("breaches") or []:
                breach_name = breach_data.get("Name", "")
                if not breach_name or breach_name in seen_breach_names:
                    continue
                seen_breach_names.add(breach_name)
                breach_entity = self._build_breach(
                    HibpService._normalize_breach(breach_data),
                    checked_at,
                )
                if not breach_entity:
                    continue
                entities.append(breach_entity)
                relationships.append(
                    {
                        "from_id": email_entity.id,
                        "to_id": breach_entity.id,
                        "type": "EXPOSED_IN",
                        "properties": {
                            "source": "hibp",
                            "breach_name": breach_name,
                            "checked_at": checked_at,
                        },
                    }
                )

        return TransformResult(entities=entities, relationships=relationships)

    @staticmethod
    def _build_breach(breach_data: Dict[str, Any], checked_at: str) -> Optional[Breach]:
        name = breach_data.get("name") or breach_data.get("Name", "")
        if not name:
            return None
        return Breach(
            value=name,
            properties={
                "title": breach_data.get("title", ""),
                "domain": breach_data.get("domain", ""),
                "breach_date": breach_data.get("breach_date", ""),
                "added_date": breach_data.get("added_date", ""),
                "modified_date": breach_data.get("modified_date", ""),
                "pwn_count": breach_data.get("pwn_count", 0),
                "description": breach_data.get("description", ""),
                "data_classes": breach_data.get("data_classes", []),
                "is_verified": bool(breach_data.get("is_verified", False)),
                "is_fabricated": bool(breach_data.get("is_fabricated", False)),
                "is_sensitive": bool(breach_data.get("is_sensitive", False)),
                "is_retired": bool(breach_data.get("is_retired", False)),
                "is_spam_list": bool(breach_data.get("is_spam_list", False)),
                "logo_path": breach_data.get("logo_path", ""),
                "source": "hibp",
                "checked_at": checked_at,
            },
        )
