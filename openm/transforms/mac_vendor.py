from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Device, Entity, MACAddress
from openm.core.transform import Transform, TransformResult
from openm.services.mac_service import MacVendorService


@Transform.register
class MacVendorTransform(Transform):
    """
    Transform que descobre o fabricante de um MAC address via OUI lookup.

    Entrada: Device (com propriedade ``mac`` ou ``mac_address``) ou
    MACAddress.
    Saida:
      - Entidade de entrada enriquecida com mac_vendor, mac_oui,
        mac_address_normalized, mac_source, mac_checked_at.
      - 1 entidade MACAddress (criada se a entrada foi Device) + edge
        IDENTIFIED_BY (Device -> MACAddress).
      - Se o vendor for conhecido, 1 entidade Device representando o
        fabricante + edge MANUFACTURED_BY (MACAddress -> Device).

    Sem API key (usa tabela OUI embutida com 700+ entradas dos
    principais fabricantes: Apple, Cisco, Dell, Intel, HP, Samsung,
    Google, Amazon, Netgear, TP-Link, D-Link, Belkin, Microsoft,
    Qualcomm Atheros).
    """

    name = "mac_vendor_lookup"
    display_name = "MAC Address Vendor Lookup (OUI)"
    input_types = ["Device", "MACAddress"]
    description = (
        "Identifica o fabricante de um MAC address via lookup do "
        "prefixo OUI (3 primeiros bytes). Sem API key, usa tabela "
        "embutida com 700+ entradas dos principais fabricantes."
    )
    cache_ttl_seconds = 2592000  # 30 dias — OUI raramente muda

    def _run(self, entity: Entity) -> TransformResult:
        checked_at = datetime.now(timezone.utc).isoformat()

        # Extrai MAC do input.
        if isinstance(entity, MACAddress):
            mac_value = entity.value
        elif isinstance(entity, Device):
            props = entity.properties or {}
            mac_value = props.get("mac") or props.get("mac_address")
        else:
            return TransformResult()

        if not mac_value or not isinstance(mac_value, str):
            return TransformResult()

        intel = MacVendorService.lookup(mac_value)
        if not intel["valid"]:
            # MAC malformado: enriquece com erro e sai.
            enriched = self._enrich_input(entity, intel, None, checked_at)
            return TransformResult(entities=[enriched], relationships=[])

        normalized_mac = intel["normalized"]
        oui = intel["oui"]
        vendor = intel["vendor"]

        # 1. Cria/usa MACAddress entity.
        if isinstance(entity, MACAddress):
            mac_entity = entity
        else:
            mac_entity = MACAddress(
                value=normalized_mac,
                properties={
                    "oui": oui,
                    "source": "mac_vendor_lookup",
                    "discovered_at": checked_at,
                },
            )

        # 2. Enriquece o input com metadados do lookup.
        enriched_input = self._enrich_input(
            entity, intel, mac_entity.id if mac_entity.id != entity.id else None, checked_at,
        )

        entities: List[Entity] = [enriched_input]
        if mac_entity.id != enriched_input.id:
            entities.append(mac_entity)
        relationships: List[Dict[str, Any]] = []

        # 3. Edge Device -> MACAddress (quando input eh Device).
        if isinstance(entity, Device):
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": mac_entity.id,
                    "type": "IDENTIFIED_BY",
                    "properties": {
                        "source": "mac_vendor_lookup",
                        "oui": oui,
                        "discovered_at": checked_at,
                    },
                }
            )

        # 4. Cria entidade Device para o fabricante (se conhecido).
        if vendor:
            vendor_device = Device(
                value=vendor,
                properties={
                    "role": "manufacturer",
                    "oui": oui,
                    "source": "mac_vendor_lookup",
                    "discovered_at": checked_at,
                },
            )
            entities.append(vendor_device)
            relationships.append(
                {
                    "from_id": mac_entity.id,
                    "to_id": vendor_device.id,
                    "type": "MANUFACTURED_BY",
                    "properties": {
                        "source": "mac_vendor_lookup",
                        "oui": oui,
                        "discovered_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)

    @staticmethod
    def _enrich_input(
        entity: Entity,
        intel: Dict[str, Any],
        mac_entity_id: Any,
        checked_at: str,
    ) -> Entity:
        """Enriquece a entidade de input com metadados do lookup."""
        props: Dict[str, Any] = {
            "mac_address_normalized": intel.get("normalized"),
            "mac_oui": intel.get("oui"),
            "mac_vendor": intel.get("vendor"),
            "mac_valid": bool(intel.get("valid")),
            "mac_source": "oui_table",
            "mac_checked_at": checked_at,
        }
        if intel.get("errors"):
            props["mac_errors"] = intel["errors"]
        if mac_entity_id and entity.type != "MACAddress":
            props["mac_entity_id"] = mac_entity_id

        entity_class = type(entity)
        return entity_class(
            value=entity.value,
            properties={**entity.properties, **props},
            entity_id=entity.id,
        )
