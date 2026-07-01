"""
HunterDomainTransform: Domain → Person + Email entities.

Usa Hunter.io /v2/domain-search para descobrir emails de pessoas
associadas ao domínio, cria nós Person e Email no grafo, e edges:

- ASSOCIATED_WITH (Domain → Person)  — pessoa encontrada para o domínio
- WORKS_AT        (Person → Domain)  — pessoa trabalha no domínio
- USES_EMAIL      (Person → Email)   — email pertence à pessoa

Quando quota excedida, GDPR bloqueado, ou sem dados, anota a entidade
Domain com flags mas não cria Person/Email (mantém grafo limpo).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Domain, Email, Entity, Person
from openm.core.transform import Transform, TransformResult
from openm.services.hunter_service import HunterService


@Transform.register
class HunterDomainTransform(Transform):
    """Domain → Person + Email entities via Hunter.io domain-search."""

    name = "hunter_domain_search"
    display_name = "Hunter.io — Domain → People & Emails"
    input_types = ["Domain"]
    description = (
        "Consulta Hunter.io para descobrir emails e pessoas associadas ao "
        "domínio. Cria nós Person e Email com edges ASSOCIATED_WITH, "
        "WORKS_AT e USES_EMAIL."
    )
    service_name = "hunter"
    # Label neutro: a mesma key Hunter serve para AMBOS os endpoints
    # (domain-search e email-verifier). Por causa da deduplicacao
    # em TransformRegistry.list_services(), apenas o display_name
    # do primeiro transform com service_name="hunter" aparece no
    # dropdown — por isso usamos um label unificado aqui.
    service_display = "Hunter.io"
    cache_ttl_seconds = 21600  # 6h — API paga, queremos freshness vs quota
    # Issue #81: chain. Cada email descoberto pelo Hunter domain-search
    # pode ser verificado (deliverability/breach) pelo
    # hunter_email_verifier.
    downstream_transforms = ["hunter_email_verifier"]

    def _run(self, entity: Entity) -> TransformResult:
        data = HunterService.investigate_domain(entity.value)
        checked_at = datetime.now(timezone.utc).isoformat()

        # Domínio enriquecido é criado SEMPRE — mesmo em caso de quota/gdpr
        # — para que o investigador veja que o enriquecimento foi tentado.
        domain_props = {
            "hunter_organization": data.get("organization") or "",
            "hunter_pattern": data.get("pattern") or "",
            "hunter_accept_all": data.get("accept_all"),
            "hunter_linked_domains": data.get("linked_domains", []),
            "hunter_checked_at": checked_at,
            "hunter_quota_exceeded": data.get("quota_exceeded", False),
            "hunter_gdpr_blocked": data.get("gdpr_blocked", False),
            "hunter_available": data.get("available", False),
            "hunter_cache_hit": data.get("cache_hit", False),
        }
        domain_entity = Domain(
            value=entity.value,
            properties={**entity.properties, **domain_props},
            entity_id=entity.id,
        )
        entities: List[Entity] = [domain_entity]
        relationships: List[Dict[str, Any]] = []

        # Sem quota/gdpr ou dados disponíveis → não cria Person/Email
        if (
            data.get("quota_exceeded")
            or data.get("gdpr_blocked")
            or not data.get("available")
        ):
            return TransformResult(entities=entities, relationships=relationships)

        seen_emails: set = set()
        for person_data in data.get("people", []):
            email_value = person_data.get("email")
            if not email_value or email_value in seen_emails:
                continue
            seen_emails.add(email_value)

            first = person_data.get("first_name") or ""
            last = person_data.get("last_name") or ""
            person_value = (
                f"{first} {last}".strip()
                or email_value.split("@", 1)[0]
                or "unknown"
            )
            person = Person(
                value=person_value,
                properties={
                    "first_name": first,
                    "last_name": last,
                    "position": person_data.get("position") or "",
                    "seniority": person_data.get("seniority") or "",
                    "department": person_data.get("department") or "",
                    "linkedin": person_data.get("linkedin") or "",
                    "twitter": person_data.get("twitter") or "",
                    "confidence": int(person_data.get("confidence") or 0),
                    "source": "hunter",
                    "checked_at": checked_at,
                },
            )
            entities.append(person)

            # Domain → Person (pessoa encontrada para o domínio)
            relationships.append({
                "from_id": entity.id,
                "to_id": person.id,
                "type": "ASSOCIATED_WITH",
                "properties": {
                    "source": "hunter",
                    "confidence": int(person_data.get("confidence") or 0),
                    "checked_at": checked_at,
                },
            })

            # Person → Domain (a pessoa trabalha no domínio)
            relationships.append({
                "from_id": person.id,
                "to_id": entity.id,
                "type": "WORKS_AT",
                "properties": {
                    "organization": data.get("organization") or "",
                    "source": "hunter",
                    "checked_at": checked_at,
                },
            })

            # Email node
            verification = person_data.get("verification") or {}
            email = Email(
                value=email_value,
                properties={
                    "type": person_data.get("email_type") or "personal",
                    "confidence": int(person_data.get("confidence") or 0),
                    "verification_status": (
                        verification.get("status") if isinstance(verification, dict) else ""
                    ) or "",
                    "source": "hunter",
                    "checked_at": checked_at,
                },
            )
            entities.append(email)

            # Person → Email
            relationships.append({
                "from_id": person.id,
                "to_id": email.id,
                "type": "USES_EMAIL",
                "properties": {
                    "source": "hunter",
                    "checked_at": checked_at,
                },
            })

        return TransformResult(entities=entities, relationships=relationships)
