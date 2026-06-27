from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from openm.core.entity import Domain, Email, Entity, Person
from openm.core.transform import Transform, TransformResult
from openm.services.hunter_service import HunterService


@Transform.register
class PersonToDomainTransform(Transform):
    """
    Transform que descobre dominios associados a uma Person.

    Entrada: Person
    Saida:
      - Person enriquecida com person_domain_source (email | heuristic
        | hunter), person_associated_domains (lista).
      - Uma entidade Domain por dominio descoberto + edge
        ASSOCIATED_WITH (Person -> Domain).
      - Opcionalmente: entidades Email adicionais (linked emails do
        Hunter) + edges BELONGS_TO (Email -> Domain).

    Estrategia:
      1. Se Person.properties.email estiver presente, extrai dominio
         do email (sem API key, parsing local).
      2. Se Person.properties.organization estiver presente, tenta
         resolver dominio heuristico da org (orgname.com,
         orgname.co, etc.) e usa Hunter.io domain-search para validar.
      3. Quando Hunter esta disponivel, enriquece com linked_domains.

    Hunter (opcional): requer chave Hunter (ApiKey service_name='hunter'
    ou env HUNTER_API_KEY). Sem chave, o transform ainda funciona
    apenas com o parsing local de email.
    """

    name = "person_domain_discovery"
    display_name = "Person → Domain Discovery"
    input_types = ["Person"]
    description = (
        "Descobre dominios associados a uma Person via parsing de "
        "email e Hunter.io (quando disponivel). Cria entidades Domain "
        "vinculadas por ASSOCIATED_WITH."
    )
    service_name = "hunter"
    service_display = "Hunter.io"
    cache_ttl_seconds = 86400  # 24h — dados mudam pouco

    def _run(self, entity: Entity) -> TransformResult:
        if not isinstance(entity, Person):
            return TransformResult()

        checked_at = datetime.now(timezone.utc).isoformat()
        props = entity.properties or {}

        domains: Dict[str, Dict[str, Any]] = {}
        emails: Dict[str, Email] = {}

        # 1. Extrai dominio do email se presente.
        email = props.get("email")
        if email:
            domain_value = _extract_domain_from_email(email)
            if domain_value:
                domains[domain_value] = {
                    "source": "email_parse",
                    "discovered_via": "person_email",
                    "raw_email": email,
                }
                emails[email.lower()] = Email(
                    value=email.lower(),
                    properties={
                        "source": "person_property",
                        "extracted_from_person": entity.value,
                        "discovered_at": checked_at,
                    },
                )

        # 2. Se tem organizacao, tenta resolver via Hunter (se disponivel).
        organization = props.get("organization")
        hunter_intel: Optional[Dict[str, Any]] = None
        if organization:
            hunter_intel = HunterService.investigate_domain(
                _guess_domain_from_org(organization)
            )
            if hunter_intel and hunter_intel.get("available"):
                # Dominio confirmado pelo Hunter
                hunter_domain = (
                    hunter_intel.get("domain")
                    or _guess_domain_from_org(organization)
                )
                existing = domains.get(hunter_domain)
                if existing is None:
                    domains[hunter_domain] = {
                        "source": "hunter_domain_search",
                        "discovered_via": "person_organization",
                        "hunter_pattern": hunter_intel.get("pattern"),
                        "hunter_organization": hunter_intel.get("organization"),
                    }
                else:
                    existing["hunter_verified"] = True

                # Linked domains adicionais do Hunter
                for linked in hunter_intel.get("linked_domains") or []:
                    if not isinstance(linked, str):
                        continue
                    linked_lower = linked.lower().strip()
                    if not linked_lower or linked_lower in domains:
                        continue
                    domains[linked_lower] = {
                        "source": "hunter_linked_domain",
                        "discovered_via": "hunter",
                        "parent_domain": hunter_domain,
                    }

                # Pessoas adicionais encontradas (cria Email entities)
                for person in hunter_intel.get("people") or []:
                    person_email = person.get("email")
                    if person_email and isinstance(person_email, str):
                        person_email_lower = person_email.lower().strip()
                        if person_email_lower and person_email_lower not in emails:
                            emails[person_email_lower] = Email(
                                value=person_email_lower,
                                properties={
                                    "source": "hunter",
                                    "extracted_from_person": entity.value,
                                    "discovered_at": checked_at,
                                },
                            )

        # 3. Enriquece a Person com resumo dos dominios descobertos.
        associated_domains_list = sorted(domains.keys())
        person_props: Dict[str, Any] = {
            "person_domain_source": _primary_source(domains),
            "person_associated_domains": associated_domains_list,
            "person_domain_discovery_checked_at": checked_at,
            "person_domain_hunter_available": bool(
                hunter_intel and hunter_intel.get("available")
            ),
        }
        if hunter_intel is not None:
            if hunter_intel.get("available"):
                person_props["person_domain_hunter_pattern"] = hunter_intel.get("pattern")
            elif hunter_intel.get("quota_exceeded"):
                person_props["person_domain_hunter_quota_exceeded"] = True

        enriched = Person(
            value=entity.value,
            properties={**entity.properties, **person_props},
            entity_id=entity.id,
        )

        entities: List[Entity] = [enriched]
        relationships: List[Dict[str, Any]] = []

        # Cria Domain entities e edges Person -> Domain
        for domain_value, domain_meta in domains.items():
            domain_entity = Domain(
                value=domain_value,
                properties={
                    "source": domain_meta.get("source", "unknown"),
                    "discovered_via": domain_meta.get("discovered_via", "person"),
                    "discovered_at": checked_at,
                    **(
                        {"hunter_verified": True}
                        if domain_meta.get("hunter_verified")
                        else {}
                    ),
                },
            )
            entities.append(domain_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": domain_entity.id,
                    "type": "ASSOCIATED_WITH",
                    "properties": {
                        "source": domain_meta.get("source", "person_discovery"),
                        "via": domain_meta.get("discovered_via", "person"),
                        "discovered_at": checked_at,
                    },
                }
            )

        # Cria Email entities extras (Hunter) e edges Email -> Domain
        for email_entity in emails.values():
            entities.append(email_entity)
            email_domain = _extract_domain_from_email(email_entity.value)
            if email_domain and email_domain in domains:
                # Encontra o id do Domain entity correspondente
                domain_entity = next(
                    (e for e in entities if isinstance(e, Domain) and e.value == email_domain),
                    None,
                )
                if domain_entity is not None:
                    relationships.append(
                        {
                            "from_id": email_entity.id,
                            "to_id": domain_entity.id,
                            "type": "BELONGS_TO",
                            "properties": {
                                "source": "hunter",
                                "discovered_at": checked_at,
                            },
                        }
                    )

        return TransformResult(entities=entities, relationships=relationships)


def _extract_domain_from_email(email: str) -> str:
    """Extrai dominio de um endereco de email (parsing local)."""
    if not email or not isinstance(email, str):
        return ""
    candidate = email.strip().lower()
    if "@" not in candidate:
        return ""
    local, _, domain = candidate.partition("@")
    if not local or not domain:
        return ""
    # Rejeita multiplos @ (apos partition, rest nao deveria ter @).
    if "@" in domain:
        return ""
    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        return ""
    return domain


def _guess_domain_from_org(organization: str) -> str:
    """
    Heuristica simples: normaliza nome da organizacao e adiciona .com.

    Ex: "Acme Inc." -> "acme.com", "Acme Corp" -> "acme.com".
    E uma aproximacao; Hunter confirma ou descarta depois.
    """
    if not organization or not isinstance(organization, str):
        return ""
    cleaned = organization.strip().lower()
    # Remove sufixos comuns
    for suffix in (" inc.", " inc", " corp.", " corp", " ltd.", " ltd",
                   " llc", " s.a.", " sa", " s.r.l.", " gmbh"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)].strip()
    # Pega primeira palavra alfabetica como slug
    tokens = [t for t in cleaned.split() if t.isalpha()]
    if not tokens:
        return ""
    return f"{tokens[0]}.com"


def _primary_source(domains: Dict[str, Dict[str, Any]]) -> str:
    """Retorna a fonte principal (hunter tem prioridade se presente)."""
    sources = {meta.get("source") for meta in domains.values()}
    if "hunter_domain_search" in sources:
        return "hunter"
    if "hunter_linked_domain" in sources:
        return "hunter"
    if "email_parse" in sources:
        return "email"
    return "none"
