from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from openm.core.entity import Domain, Entity, Person
from openm.core.transform import Transform, TransformResult
from openm.services.whois_service import WhoisService


def _clean_value(value: Optional[str]) -> Optional[str]:
    """
    Sanitize a WHOIS value, returning None for garbage data.

    Filters out:
    - None/empty strings
    - Lines starting with '%' (WHOIS comments)
    - WHOIS protocol metadata lines
    """
    if not value:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if stripped.startswith("%"):
        return None
    if stripped.lower().startswith("this query returned"):
        return None
    return stripped


@Transform.register
class WhoisTransform(Transform):
    """
    Transform que consulta WHOIS para um domínio.

    Entrada: Domain
    Saída: anotações na entidade Domain (registrar, datas, nameservers)
           + novos nós Person (admin-c, tech-c, registrant)
           + edges REGISTERED_BY, ADMIN_CONTACT, TECH_CONTACT
    """

    name = "whois_lookup"
    display_name = "WHOIS Lookup — Domain Metadata"
    input_types = ["Domain"]
    description = (
        "Consulta WHOIS (porta 43) para obter registrar, datas de criação/expiração, "
        "nameservers e contatos (registrant, admin, tech) de um domínio."
    )

    def _run(self, entity: Entity) -> TransformResult:
        whois_data = WhoisService.investigate_domain(entity.value)

        entities: List[Entity] = []
        relationships: List[Dict[str, Any]] = []
        checked_at = datetime.now(timezone.utc).isoformat()

        # Annotate the Domain entity with WHOIS metadata
        domain_props = {
            "whois_registrar": whois_data.get("registrar", ""),
            "whois_creation_date": whois_data.get("creation_date", ""),
            "whois_expiry_date": whois_data.get("expiry_date", ""),
            "whois_updated_date": whois_data.get("updated_date", ""),
            "whois_nameservers": whois_data.get("nameservers", []),
            "whois_status": whois_data.get("status", []),
            "whois_dnssec": whois_data.get("dnssec", ""),
            "whois_source": whois_data.get("source", "whois"),
            "whois_checked_at": checked_at,
        }
        # Create a Domain entity with enriched properties (same id as input)
        domain_entity = Domain(
            value=entity.value,
            properties={**entity.properties, **domain_props},
            entity_id=entity.id,
        )
        entities.append(domain_entity)

        # Registrant as Person
        registrant_name = _clean_value(whois_data.get("registrant_name"))
        registrant_org = _clean_value(whois_data.get("registrant_org"))
        registrant_email = _clean_value(whois_data.get("registrant_email"))
        registrant_country = _clean_value(whois_data.get("registrant_country"))

        if registrant_name or registrant_org or registrant_email:
            # Prefer name, then org, then email as the Person value
            registrant_value = registrant_name or registrant_org or registrant_email or f"registrant@{entity.value}"
            registrant = Person(
                value=registrant_value,
                properties={
                    "role": "registrant",
                    "email": registrant_email or "",
                    "organization": registrant_org or "",
                    "country": registrant_country or "",
                    "source": whois_data.get("source", "whois"),
                    "checked_at": checked_at,
                },
            )
            entities.append(registrant)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": registrant.id,
                    "type": "REGISTERED_BY",
                    "properties": {
                        "role": "registrant",
                        "source": whois_data.get("source", "whois"),
                        "checked_at": checked_at,
                    },
                }
            )

        # Admin contact as Person
        admin_name = _clean_value(whois_data.get("admin_name"))
        admin_email = _clean_value(whois_data.get("admin_email"))
        admin_org = _clean_value(whois_data.get("admin_org"))
        if admin_name or admin_email:
            admin_value = admin_name or admin_email or f"admin@{entity.value}"
            admin = Person(
                value=admin_value,
                properties={
                    "role": "admin_contact",
                    "email": admin_email or "",
                    "organization": admin_org or "",
                    "source": whois_data.get("source", "whois"),
                    "checked_at": checked_at,
                },
            )
            entities.append(admin)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": admin.id,
                    "type": "ADMIN_CONTACT",
                    "properties": {
                        "role": "admin",
                        "source": whois_data.get("source", "whois"),
                        "checked_at": checked_at,
                    },
                }
            )

        # Tech contact as Person
        tech_name = _clean_value(whois_data.get("tech_name"))
        tech_email = _clean_value(whois_data.get("tech_email"))
        tech_org = _clean_value(whois_data.get("tech_org"))
        if tech_name or tech_email:
            tech_value = tech_name or tech_email or f"tech@{entity.value}"
            tech = Person(
                value=tech_value,
                properties={
                    "role": "tech_contact",
                    "email": tech_email or "",
                    "organization": tech_org or "",
                    "source": whois_data.get("source", "whois"),
                    "checked_at": checked_at,
                },
            )
            entities.append(tech)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": tech.id,
                    "type": "TECH_CONTACT",
                    "properties": {
                        "role": "tech",
                        "source": whois_data.get("source", "whois"),
                        "checked_at": checked_at,
                    },
                }
            )

        # Registrar as Person (if different from registrant)
        registrar = _clean_value(whois_data.get("registrar"))
        if registrar and registrar != registrant_name and registrar != registrant_org:
            registrar_entity = Person(
                value=registrar,
                properties={
                    "role": "registrar",
                    "source": whois_data.get("source", "whois"),
                    "checked_at": checked_at,
                },
            )
            entities.append(registrar_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": registrar_entity.id,
                    "type": "REGISTERED_BY",
                    "properties": {
                        "role": "registrar",
                        "source": whois_data.get("source", "whois"),
                        "checked_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
