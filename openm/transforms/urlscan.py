from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Domain, Entity, IPAddress
from openm.core.transform import Transform, TransformResult
from openm.services.urlscan_service import UrlscanService


@Transform.register
class UrlscanTransform(Transform):
    """
    Transform que consulta URLScan.io para analise comportamental de
    um dominio, IP ou URL.

    Entrada: Domain, IPAddress ou URL
    Saida:
      - Entidade de entrada enriquecida com urlscan_screenshot_url,
        urlscan_malicious, urlscan_score, urlscan_technologies,
        urlscan_page_status, etc.
      - Para cada dominio contactado: entidade Domain + edge CONTACTS.
      - Para cada IP contactado: entidade IPAddress + edge CONNECTS_TO.

    Requer chave de API (ApiKey service_name='urlscan' ou env
    URLSCAN_API_KEY). O scan no URLScan e assincrono; o service
    implementa polling com timeout.
    """

    name = "urlscan_lookup"
    display_name = "URLScan.io — URL/Domain Scan"
    input_types = ["Domain", "IPAddress", "URL"]
    description = (
        "Consulta URLScan.io para obter screenshot, tecnologias "
        "detectadas, dominios contactados, IPs de origem e veredito "
        "geral de seguranca de uma URL."
    )
    service_name = "urlscan"
    service_display = "URLScan.io"
    # Scans sao async e o servico faz polling; mantemos TTL conservador
    # porque o resultado nao muda apos publicado.
    cache_ttl_seconds = 21600  # 6h

    def _run(self, entity: Entity) -> TransformResult:
        checked_at = datetime.now(timezone.utc).isoformat()

        target = self._target_from(entity)
        if not target:
            return TransformResult()

        intel = UrlscanService.submit_scan(target)
        if intel is None:
            return TransformResult()

        return self._build_result(entity, intel, checked_at)

    @staticmethod
    def _target_from(entity: Entity) -> str:
        """Extrai target do tipo de entidade."""
        if entity.type == "URL":
            return entity.value
        if entity.type == "Domain":
            return entity.value
        if entity.type == "IPAddress":
            return entity.value
        return ""

    @classmethod
    def _build_result(
        cls,
        entity: Entity,
        intel: Dict[str, Any],
        checked_at: str,
    ) -> TransformResult:
        entities: List[Entity] = []
        relationships: List[Dict[str, Any]] = []

        available = bool(intel.get("available", False))
        properties: Dict[str, Any] = {
            "urlscan_source": "urlscan",
            "urlscan_available": available,
            "urlscan_checked_at": checked_at,
            "urlscan_uuid": intel.get("uuid"),
            "urlscan_result_url": intel.get("result_url"),
        }

        if available:
            properties.update({
                "urlscan_screenshot_url": intel.get("screenshot_url"),
                "urlscan_page_url": intel.get("page_url"),
                "urlscan_page_domain": intel.get("page_domain"),
                "urlscan_page_status": intel.get("page_status"),
                "urlscan_page_title": intel.get("page_title"),
                "urlscan_malicious": bool(intel.get("malicious")),
                "urlscan_score": intel.get("score"),
                "urlscan_technologies": intel.get("technologies") or [],
                "urlscan_stats": intel.get("stats") or {},
            })
        elif intel.get("rate_limited"):
            properties["urlscan_rate_limited"] = True
        elif intel.get("key_valid") is False:
            properties["urlscan_key_valid"] = False
        elif intel.get("pending"):
            properties["urlscan_pending"] = True

        # Enriquece a entidade de entrada (preserva id original).
        enriched = cls._build_enriched(entity, properties)
        entities.append(enriched)

        # Dominios contactados (CONTACTS).
        seen_domains: set = set()
        for d in intel.get("domains") or []:
            if not isinstance(d, str) or not d or d == enriched.value:
                continue
            if d.lower() == (intel.get("page_domain") or "").lower():
                continue
            if d in seen_domains:
                continue
            seen_domains.add(d)
            contact_domain = Domain(
                value=d.lower(),
                properties={
                    "source": "urlscan",
                    "is_contacted": True,
                    "discovered_at": checked_at,
                },
            )
            entities.append(contact_domain)
            relationships.append(
                {
                    "from_id": enriched.id,
                    "to_id": contact_domain.id,
                    "type": "CONTACTS",
                    "properties": {
                        "source": "urlscan",
                        "discovered_at": checked_at,
                    },
                }
            )

        # IPs contactados (CONNECTS_TO).
        seen_ips: set = set()
        for ip in intel.get("ips") or []:
            if not isinstance(ip, str) or not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)
            contact_ip = IPAddress(
                value=ip,
                properties={
                    "source": "urlscan",
                    "is_contacted": True,
                    "discovered_at": checked_at,
                },
            )
            entities.append(contact_ip)
            relationships.append(
                {
                    "from_id": enriched.id,
                    "to_id": contact_ip.id,
                    "type": "CONNECTS_TO",
                    "properties": {
                        "source": "urlscan",
                        "discovered_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)

    @staticmethod
    def _build_enriched(entity: Entity, properties: Dict[str, Any]) -> Entity:
        """Constroi a entidade enriquecida preservando o id original."""
        entity_class = type(entity)
        return entity_class(
            value=entity.value,
            properties={**entity.properties, **properties},
            entity_id=entity.id,
        )
