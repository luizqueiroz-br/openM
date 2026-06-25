from datetime import datetime, timezone
from typing import Any, Dict, List

from openm.core.entity import Device, Entity, IPAddress
from openm.core.transform import Transform, TransformResult
from openm.services.geoip_service import GeoIPService


@Transform.register
class GeoIPTransform(Transform):
    """
    Transform que consulta geolocalização para um endereço IP.

    Entrada: IPAddress
    Saída: anotações na entidade IPAddress (país, cidade, ASN, org)
           + edge LOCATED_IN (para um nó Device representando a localização)
           + edge ASN (para um nó Device representando a organização/ASN)
    """

    name = "geoip_lookup"
    display_name = "GeoIP Lookup — IP Geolocation"
    input_types = ["IPAddress"]
    description = (
        "Consulta MaxMind GeoLite2 (offline) para obter país, cidade, "
        "coordenadas e organização de um endereço IP."
    )

    def run(self, entity: Entity) -> TransformResult:
        if entity.type != "IPAddress":
            return TransformResult()

        geo_data = GeoIPService.investigate_ip(entity.value)

        entities: List[Entity] = []
        relationships: List[Dict[str, Any]] = []
        checked_at = datetime.now(timezone.utc).isoformat()

        # Annotate the IPAddress entity with GeoIP metadata
        ip_props = {
            "geo_country": geo_data.get("country", ""),
            "geo_country_name": geo_data.get("country_name", ""),
            "geo_city": geo_data.get("city", ""),
            "geo_postal_code": geo_data.get("postal_code", ""),
            "geo_latitude": geo_data.get("latitude"),
            "geo_longitude": geo_data.get("longitude"),
            "geo_accuracy_radius": geo_data.get("accuracy_radius"),
            "geo_timezone": geo_data.get("timezone", ""),
            "geo_continent": geo_data.get("continent", ""),
            "geo_subdivision": geo_data.get("subdivision", ""),
            "geo_source": geo_data.get("source", "geoip"),
            "geo_checked_at": checked_at,
        }
        ip_entity = IPAddress(
            value=entity.value,
            properties={**entity.properties, **ip_props},
            entity_id=entity.id,
        )
        entities.append(ip_entity)

        # Location as Device node
        country = geo_data.get("country_name", "") or geo_data.get("country", "")
        city = geo_data.get("city", "")
        location_label = f"{city}, {country}" if city and country else (country or entity.value)

        if country or city:
            location_device = Device(
                value=location_label,
                properties={
                    "role": "geo_location",
                    "country": geo_data.get("country", ""),
                    "country_name": geo_data.get("country_name", ""),
                    "city": geo_data.get("city", ""),
                    "postal_code": geo_data.get("postal_code", ""),
                    "latitude": geo_data.get("latitude"),
                    "longitude": geo_data.get("longitude"),
                    "accuracy_radius": geo_data.get("accuracy_radius"),
                    "timezone": geo_data.get("timezone", ""),
                    "continent": geo_data.get("continent", ""),
                    "subdivision": geo_data.get("subdivision", ""),
                    "source": geo_data.get("source", "geoip"),
                    "checked_at": checked_at,
                },
            )
            entities.append(location_device)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": location_device.id,
                    "type": "LOCATED_IN",
                    "properties": {
                        "country": geo_data.get("country", ""),
                        "city": geo_data.get("city", ""),
                        "source": geo_data.get("source", "geoip"),
                        "checked_at": checked_at,
                    },
                }
            )

        # Organization/ASN as Device node
        org = geo_data.get("organization", "")
        if org:
            org_device = Device(
                value=org,
                properties={
                    "role": "organization",
                    "organization": org,
                    "source": geo_data.get("source", "geoip"),
                    "checked_at": checked_at,
                },
            )
            entities.append(org_device)
            relationships.append(
                {
                    "from_id": entity.id,
                    "to_id": org_device.id,
                    "type": "ASN",
                    "properties": {
                        "organization": org,
                        "source": geo_data.get("source", "geoip"),
                        "checked_at": checked_at,
                    },
                }
            )

        return TransformResult(entities=entities, relationships=relationships)
