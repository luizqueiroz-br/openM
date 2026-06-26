from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Device, Entity, IPAddress
from openm.core.transform import Transform, TransformResult
from openm.services.threat_intel_service import ThreatIntelService


@Transform.register
class CheckFraudEmailTransform(Transform):
    """
    Transform de inteligência de fraude para e-mails.

    Entrada: Email
    Saída: entidades IPAddress e Device vinculadas por SUSPICIOUS_LOGIN
    ou ASSOCIATED_WITH, com base em APIs de threat intel ou simulação.
    """

    name = "check_fraud_email"
    display_name = "Check Fraud Indicators for Email"
    input_types = ["Email"]
    description = (
        "Consulta fontes de threat intel e retorna IPs/dispositivos "
        "associados a acessos suspeitos do e-mail."
    )
    service_name = "emailrep"
    service_display = "EmailRep.io"

    def run(self, entity: Entity) -> TransformResult:
        if entity.type != "Email":
            return TransformResult()

        intel = ThreatIntelService.investigate_email(entity.value)

        entities: List[Entity] = []
        relationships: List[Dict[str, Any]] = []
        checked_at = datetime.now(timezone.utc).isoformat()

        # IPs associados
        seen_ips = set()
        for item in intel.get("associated_ips", []):
            ip = item.get("ip")
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)
            ip_entity = IPAddress(
                value=ip,
                properties={
                    "context": item.get("context", "unknown"),
                    "confidence": item.get("confidence", "low"),
                    "source": "threat_intel",
                    "checked_at": checked_at,
                },
            )
            entities.append(ip_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": ip_entity.id,
                    "type": "SUSPICIOUS_LOGIN",
                    "properties": {
                        "context": item.get("context", "unknown"),
                        "checked_at": checked_at,
                        "risk_score": intel.get("risk_score", 0),
                    },
                }
            )

        # Dispositivos associados
        seen_devices = set()
        for item in intel.get("associated_devices", []):
            device = item.get("device")
            if not device or device in seen_devices:
                continue
            seen_devices.add(device)
            device_entity = Device(
                value=device,
                properties={
                    "context": item.get("context", "unknown"),
                    "source": "threat_intel",
                    "checked_at": checked_at,
                },
            )
            entities.append(device_entity)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": device_entity.id,
                    "type": "ASSOCIATED_WITH",
                    "properties": {
                        "context": item.get("context", "unknown"),
                        "checked_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
