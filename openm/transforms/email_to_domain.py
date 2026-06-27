from datetime import datetime, timezone
from typing import Any, Dict

from openm.core.entity import Domain, Entity
from openm.core.transform import Transform, TransformResult


@Transform.register
class EmailToDomainTransform(Transform):
    """
    Transform que extrai o domínio de um endereço de email.

    Entrada: Email
    Saída: 1 entidade Domain (a parte após o @) + edge BELONGS_TO do
           email para o domínio.

    Sem API key (parsing local de string). Útil para pivotar de um
    email descoberto (via Hunter, HIBP, etc.) para o domínio
    correspondente e enriquecer a partir dele.
    """

    name = "email_to_domain"
    display_name = "Email → Domain Extraction"
    input_types = ["Email"]
    description = (
        "Extrai o domínio de um endereço de email e cria um nó Domain "
        "vinculado por BELONGS_TO. Útil para pivotar de email para "
        "domínio e enriquecer a partir dele."
    )

    def _run(self, entity: Entity) -> TransformResult:
        domain_value = _extract_domain(entity.value)
        if not domain_value:
            return TransformResult()

        checked_at = datetime.now(timezone.utc).isoformat()

        domain_entity = Domain(
            value=domain_value,
            properties={
                "extracted_from_email": entity.value,
                "source": "email_parse",
                "discovered_at": checked_at,
            },
        )

        relationship: Dict[str, Any] = {
            "from_id": entity.id,
            "to_id": domain_entity.id,
            "type": "BELONGS_TO",
            "properties": {
                "source": "email_parse",
                "discovered_at": checked_at,
            },
        }

        return TransformResult(entities=[domain_entity], relationships=[relationship])


def _extract_domain(email: str) -> str:
    """
    Extrai a parte do domínio de um endereço de email.

    Validação básica: deve conter exatamente um '@' com parte local
    não-vazia antes e parte de domínio não-vazia depois.

    Args:
        email: endereço de email.

    Returns:
        String do domínio (lowercased, sem espaços), ou string vazia
        se o email for inválido.
    """
    if not email or not isinstance(email, str):
        return ""

    candidate = email.strip().lower()
    if "@" not in candidate:
        return ""

    local, _, domain = candidate.partition("@")
    if not local or not domain:
        return ""

    # Rejeitar múltiplos @ (após partition, rest não deveria ter @,
    # mas por segurança)
    if "@" in domain:
        return ""

    # Domínio deve ter pelo menos um ponto e não começar/terminar com ponto
    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        return ""

    return domain
