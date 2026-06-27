from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from openm.core.entity import Device, Entity, IPAddress
from openm.core.transform import Transform, TransformResult
from openm.services.abuseipdb_service import AbuseIPDBService


@Transform.register
class AbuseIpdbTransform(Transform):
    """
    Transform que consulta AbuseIPDB para reputacao de um IP.

    Entrada: IPAddress ou Domain
    Saida:
      - IPAddress enriquecido com abuseipdb_abuse_confidence_score,
        abuseipdb_total_reports, abuseipdb_country_code, etc.
      - Se entrada for Domain, resolve para IP e cria IPAddress com
        edge RESOLVES_TO.
      - Se abuse_confidence_score >= 50, cria Device de threat intel
        com edge REPORTED_AS_ABUSIVE.
    """

    name = "abuseipdb_lookup"
    display_name = "AbuseIPDB Lookup — IP Reputation"
    input_types = ["IPAddress", "Domain"]
    description = (
        "Consulta AbuseIPDB para obter abuse confidence score, total "
        "de reports, ISP, codigo do pais e ultima denuncia de um IP."
    )
    service_name = "abuseipdb"
    service_display = "AbuseIPDB"
    cache_ttl_seconds = 21600  # 6h — free tier de 1k/dia, balancear freshness

    def _run(self, entity: Entity) -> TransformResult:
        service = AbuseIPDBService()
        checked_at = datetime.now(timezone.utc).isoformat()

        if entity.type == "Domain":
            # AbuseIPDB trabalha com IP; resolve o dominio primeiro
            ip = self._resolve_domain(entity.value)
            if not ip:
                return TransformResult()
            # Cria IPAddress resultante
            ip_entity = IPAddress(
                value=ip,
                properties={
                    "resolved_from": entity.value,
                    "source": "abuseipdb",
                    "checked_at": checked_at,
                },
            )
            target_id = ip_entity.id
            input_id = entity.id
            entities: List[Entity] = [ip_entity]
            relationships: List[Dict[str, Any]] = [
                {
                    "from_id": entity.id,
                    "to_id": ip_entity.id,
                    "type": "RESOLVES_TO",
                    "properties": {
                        "source": "abuseipdb_dns_resolution",
                        "checked_at": checked_at,
                    },
                }
            ]
        else:
            ip = entity.value
            target_id = entity.id
            input_id = entity.id
            entities = []
            relationships = []

        intel = service.investigate_ip(ip)

        score = intel.get("abuse_confidence_score")
        total_reports = intel.get("total_reports")
        country_code = intel.get("country_code")
        isp = intel.get("isp")
        usage_type = intel.get("usage_type")
        last_reported = intel.get("last_reported_at")
        is_whitelisted = intel.get("is_whitelisted")

        ip_props: Dict[str, Any] = {
            "abuseipdb_source": intel.get("source", "abuseipdb"),
            "abuseipdb_available": bool(intel.get("available", False)),
            "abuseipdb_abuse_confidence_score": score,
            "abuseipdb_total_reports": total_reports,
            "abuseipdb_country_code": country_code,
            "abuseipdb_isp": isp,
            "abuseipdb_usage_type": usage_type,
            "abuseipdb_domain": intel.get("domain"),
            "abuseipdb_num_distinct_users": intel.get("num_distinct_users"),
            "abuseipdb_last_reported_at": last_reported,
            "abuseipdb_is_public": intel.get("is_public"),
            "abuseipdb_is_whitelisted": is_whitelisted,
            "abuseipdb_checked_at": checked_at,
        }

        # Enriquece o IP (novo ou o proprio input)
        target_ip_entity = next(
            (e for e in entities if isinstance(e, IPAddress)), None
        ) or IPAddress(value=ip, properties={}, entity_id=input_id)
        target_ip_entity.properties = {
            **target_ip_entity.properties,
            **ip_props,
        }
        # Se veio do input, garante que o id original seja preservado
        if not any(e.id == target_id for e in entities):
            target_ip_entity.id = input_id
        if target_ip_entity not in entities:
            entities.append(target_ip_entity)

        # Device de threat intel quando score alto (malicioso/suspeito)
        if score is not None and score >= 50:
            threat_device = Device(
                value=f"abuseipdb:{ip}",
                properties={
                    "role": "threat_intel_source",
                    "source": "abuseipdb",
                    "abuse_confidence_score": score,
                    "total_reports": total_reports,
                    "country_code": country_code,
                    "isp": isp,
                    "last_reported_at": last_reported,
                    "checked_at": checked_at,
                },
            )
            entities.append(threat_device)
            relationships.append(
                {
                    "from_id": target_ip_entity.id,
                    "to_id": threat_device.id,
                    "type": "REPORTED_AS_ABUSIVE",
                    "properties": {
                        "abuse_confidence_score": score,
                        "total_reports": total_reports,
                        "source": "abuseipdb",
                        "checked_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)

    @staticmethod
    def _resolve_domain(domain: str) -> Optional[str]:
        """Resolve dominio para IPv4 usando DNS local."""
        import logging
        import socket

        try:
            return socket.gethostbyname(domain)
        except OSError:
            logging.getLogger(__name__).warning("Nao foi possivel resolver %s", domain)
            return None
