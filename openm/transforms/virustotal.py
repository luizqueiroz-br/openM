from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Device, Domain, Entity, IPAddress
from openm.core.transform import Transform, TransformResult
from openm.services.virustotal_service import VirusTotalService


@Transform.register
class VirusTotalTransform(Transform):
    """
    Transform que consulta VirusTotal v3 para reputação e engines que
    marcaram um domínio ou IP como malicious/suspicious.

    Entrada: Domain ou IPAddress
    Saída:
      - Mesma entidade (Domain/IPAddress) enriquecida com
        virustotal_reputation, virustotal_malicious_count,
        virustotal_suspicious_count, virustotal_harmless_count,
        virustotal_undetected_count, virustotal_flagged,
        virustotal_checked_at, virustotal_source.
      - Para cada engine flagged (malicious ou suspicious), uma entidade
        Device com role="antivirus_engine" + edge FLAGGED_BY da entidade
        enriquecida para o Device.
    """

    name = "virustotal_lookup"
    display_name = "VirusTotal Lookup — Reputation"
    input_types = ["Domain", "IPAddress"]
    description = (
        "Consulta VirusTotal v3 para obter reputação, contadores de "
        "análise (malicious/suspicious/harmless/undetected) e engines "
        "que marcaram como malicious ou suspicious."
    )
    service_name = "virustotal"
    service_display = "VirusTotal"
    cache_ttl_seconds = 21600  # 6h — API paga, queremos freshness vs quota

    def _run(self, entity: Entity) -> TransformResult:
        intel = VirusTotalService.investigate_entity(
            entity.type, entity.value
        )

        entities: List[Entity] = []
        relationships: List[Dict[str, Any]] = []
        checked_at = datetime.now(timezone.utc).isoformat()

        stats = intel.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        reputation = intel.get("reputation")

        # Cria entidade enriquecida mesmo quando VT não retornou dados — assim
        # o investigador vê no grafo que o enriquecimento foi tentado (e
        # falhou ou não encontrou dados) em vez de assumir que não rodamos.
        vt_props: Dict[str, Any] = {
            "virustotal_source": intel.get("source", "virustotal"),
            "virustotal_available": bool(intel.get("available", False)),
            "virustotal_reputation": reputation,
            "virustotal_malicious_count": malicious,
            "virustotal_suspicious_count": suspicious,
            "virustotal_harmless_count": harmless,
            "virustotal_undetected_count": undetected,
            "virustotal_flagged": bool(
                intel.get("available", False)
                and (malicious > 0 or suspicious > 0)
            ),
            "virustotal_checked_at": checked_at,
        }

        # Cria entidade enriquecida preservando id original (padrão Whois)
        if entity.type == "Domain":
            enriched = Domain(
                value=entity.value,
                properties={**entity.properties, **vt_props},
                entity_id=entity.id,
            )
        else:
            enriched = IPAddress(
                value=entity.value,
                properties={**entity.properties, **vt_props},
                entity_id=entity.id,
            )
        entities.append(enriched)

        # Cria Devices para cada engine flagged + edges FLAGGED_BY.
        # Só faz sentido quando VT retornou dados (available=True).
        for engine_info in intel.get("flagged_by") or []:
            engine_name = engine_info.get("engine")
            if not engine_name:
                continue
            device = Device(
                value=engine_name,
                properties={
                    "role": "antivirus_engine",
                    "category": engine_info.get("category", ""),
                    "result": engine_info.get("result", ""),
                    "source": intel.get("source", "virustotal"),
                    "checked_at": checked_at,
                },
            )
            entities.append(device)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": device.id,
                    "type": "FLAGGED_BY",
                    "properties": {
                        "category": engine_info.get("category", ""),
                        "result": engine_info.get("result", ""),
                        "source": intel.get("source", "virustotal"),
                        "checked_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
