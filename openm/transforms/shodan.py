from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Device, Entity, IPAddress
from openm.core.transform import Transform, TransformResult
from openm.services.shodan_service import ShodanService


@Transform.register
class ShodanTransform(Transform):
    """
    Transform que consulta Shodan para descobrir serviços expostos
    de um domínio ou endereço IP.

    Entrada: Domain ou IPAddress
    Saída: entidades IPAddress e Device com portas/serviços,
           vinculadas por EXPOSES ou RUNS.
    """

    name = "shodan_lookup"
    display_name = "Shodan Lookup — Services Exposed"
    input_types = ["Domain", "IPAddress"]
    description = (
        "Consulta Shodan para descobrir portas abertas, serviços, "
        "banners e localização geográfica de um host."
    )

    def run(self, entity: Entity) -> TransformResult:
        if entity.type not in self.input_types:
            return TransformResult()

        service = ShodanService()
        checked_at = datetime.now(timezone.utc).isoformat()

        # Resolve IP se entrada for Domain
        if entity.type == "Domain":
            ip = service.resolve_domain(entity.value)
            if not ip:
                return TransformResult()
        else:
            ip = entity.value

        # Consulta Shodan
        intel = service.investigate_host(ip)

        entities: List[Entity] = []
        relationships: List[Dict[str, Any]] = []

        # IP do alvo (se for Domain, cria IP novo; se for IP, reutiliza)
        if entity.type == "Domain":
            ip_entity = IPAddress(
                value=ip,
                properties={
                    "resolved_from": entity.value,
                    "source": intel.get("source", "shodan"),
                    "checked_at": checked_at,
                },
            )
            entities.append(ip_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": ip_entity.id,
                    "type": "RESOLVES_TO",
                    "properties": {
                        "source": "shodan",
                        "checked_at": checked_at,
                    },
                }
            )
            target_ip_id = ip_entity.id
        else:
            target_ip_id = entity.id

        # Portas/serviços como entidades Device (cada serviço exposto)
        seen_ports: set = set()
        for svc in intel.get("services", []):
            port = svc.get("port")
            if not port or port in seen_ports:
                continue
            seen_ports.add(port)

            device = Device(
                value=f"{ip}:{port}",
                properties={
                    "port": port,
                    "transport": svc.get("transport", "tcp"),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "banner_preview": svc.get("banner", "")[:100],
                    "cpe": svc.get("cpe", []),
                    "source": intel.get("source", "shodan"),
                    "checked_at": checked_at,
                },
            )
            entities.append(device)
            relationships.append(
                {
                    "from_id": target_ip_id,
                    "to_id": device.id,
                    "type": "EXPOSES",
                    "properties": {
                        "port": port,
                        "product": svc.get("product", ""),
                        "checked_at": checked_at,
                        "provenance": "shodan",
                    },
                }
            )

        # Metadados do host como propriedades extras no relacionamento
        # (não cria entidade extra, mas enriquece o grafo)
        location = intel.get("location", {})
        org = intel.get("organization", "")
        if location.get("country") or org:
            # Cria um 'Device' representando o host em si (meta)
            host_meta = Device(
                value=ip,
                properties={
                    "role": "host_metadata",
                    "country": location.get("country", ""),
                    "city": location.get("city", ""),
                    "latitude": location.get("latitude"),
                    "longitude": location.get("longitude"),
                    "organization": org,
                    "os": intel.get("os", ""),
                    "tags": intel.get("tags", []),
                    "source": intel.get("source", "shodan"),
                    "checked_at": checked_at,
                },
            )
            entities.append(host_meta)
            relationships.append(
                {
                    "from_id": target_ip_id,
                    "to_id": host_meta.id,
                    "type": "RUNS",
                    "properties": {
                        "provenance": "shodan",
                        "checked_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
