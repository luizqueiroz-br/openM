"""
HunterEmailTransform: Email → validation + sources (annotation only).

Anota a entidade Email com o status de validação do Hunter.io e
referências às fontes públicas onde o email aparece. NÃO cria
entidades novas (sources são referências textuais a URLs externas).
"""

from datetime import datetime, timezone
from typing import Any, List

from openm.core.entity import Email, Entity
from openm.core.transform import Transform, TransformResult
from openm.services.hunter_service import HunterService


@Transform.register
class HunterEmailTransform(Transform):
    """Email → validation annotation via Hunter.io email-verifier."""

    name = "hunter_email_verifier"
    display_name = "Hunter.io — Email Verifier"
    input_types = ["Email"]
    description = (
        "Consulta Hunter.io para validar um endereço de email e listar "
        "fontes públicas onde o email aparece."
    )
    service_name = "hunter"
    # Mesmo service_name do HunterDomainTransform (a key Hunter e
    # unica e serve para os 2 endpoints). service_display nao aparece
    # no dropdown por causa da deduplicacao, mas mantemos um label
    # explicito para consistencia caso o registry evolua.
    service_display = "Hunter.io"
    cache_ttl_seconds = 21600  # 6h — API paga, queremos freshness vs quota

    def _run(self, entity: Entity) -> TransformResult:
        data = HunterService.investigate_email(entity.value)
        checked_at = datetime.now(timezone.utc).isoformat()

        sources: List[Any] = data.get("sources") or []
        email_props = {
            "hunter_status": data.get("status") or "unknown",
            "hunter_score": data.get("score"),
            "hunter_deliverable": data.get("deliverable"),
            "hunter_mx_records": data.get("mx_records"),
            "hunter_smtp_server": data.get("smtp_server"),
            "hunter_smtp_check": data.get("smtp_check"),
            "hunter_accept_all": data.get("accept_all"),
            "hunter_disposable": data.get("disposable"),
            "hunter_webmail": data.get("webmail"),
            "hunter_block": data.get("block"),
            "hunter_sources_count": len(sources),
            "hunter_sources": sources[:5],  # top 5 para não inflar o nó
            "hunter_checked_at": checked_at,
            "hunter_quota_exceeded": data.get("quota_exceeded", False),
            "hunter_gdpr_blocked": data.get("gdpr_blocked", False),
            "hunter_available": data.get("available", False),
            "hunter_cache_hit": data.get("cache_hit", False),
        }
        email_entity = Email(
            value=entity.value,
            properties={**entity.properties, **email_props},
            entity_id=entity.id,
        )
        return TransformResult(entities=[email_entity], relationships=[])
