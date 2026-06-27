"""
Servico de geolocalizacao de IP (issue #85).

Implementacoes disponiveis:
- ``MaxMindGeoIPService`` — backend real MaxMind GeoLite2 (.mmdb local).
- ``SimulatedGeoIPService`` — fallback deterministico por faixa de IP
  (usado em dev/demo e em producao quando o banco nao esta disponivel).

A escolha entre as duas e feita em runtime por ``get_geoip_service()``
(baseada em ``OPENM_GEOIP_MODE`` ou na disponibilidade do banco .mmdb).

Backwards-compat: ``GeoIPService`` e alias para ``MaxMindGeoIPService``,
entao chamadas legacy (``GeoIPService.investigate_ip``, ``GeoIPService.lookup``)
continuam funcionando como classmethods.
"""
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "/usr/share/GeoIP/GeoLite2-City.mmdb")

try:
    import maxminddb

    _HAS_MAXMIND = True
except ImportError:
    _HAS_MAXMIND = False
    logger.info("maxminddb not installed; GeoIP real backend unavailable")


_SIMULATED_LOCATIONS = {
    # RFC 1918 (mantidos por compatibilidade com testes antigos).
    (10,): ("US", "United States", "New York", 40.7128, -74.0060, "Private Network"),
    (172,): ("US", "United States", "Chicago", 41.8781, -87.6298, "Private Network"),
    (192,): ("US", "United States", "San Francisco", 37.7749, -122.4194, "Private Network"),
    # Faixas publicas comuns.
    (1,): ("US", "United States", "Los Angeles", 34.0522, -118.2437, "Cloudflare Inc."),
    (8,): ("US", "United States", "San Jose", 37.3382, -121.8863, "Google LLC"),
    (13,): ("US", "United States", "Seattle", 47.6062, -122.3321, "Amazon Web Services"),
    (17,): ("US", "United States", "Cupertino", 37.3230, -122.0322, "Apple Inc."),
    (20,): ("US", "United States", "Redmond", 47.6740, -122.1215, "Microsoft Corporation"),
    (31,): ("GB", "United Kingdom", "London", 51.5074, -0.1278, "British Telecom"),
    (35,): ("US", "United States", "Mountain View", 37.4220, -122.0841, "Google LLC"),
    (40,): ("US", "United States", "Dallas", 32.7767, -96.7970, "AT&T Services"),
    (45,): ("CA", "Canada", "Toronto", 43.6532, -79.3832, "Rogers Communications"),
    (50,): ("US", "United States", "Ashburn", 39.0438, -77.4874, "Amazon Web Services"),
    (52,): ("US", "United States", "Austin", 30.2672, -97.7431, "Amazon Web Services"),
    (54,): ("US", "United States", "Portland", 45.5152, -122.6784, "Amazon Web Services"),
    (60,): ("JP", "Japan", "Tokyo", 35.6762, 139.6503, "NTT Communications"),
    (64,): ("US", "United States", "Denver", 39.7392, -104.9903, "Level 3 Communications"),
    (66,): ("US", "United States", "Phoenix", 33.4484, -112.0740, "Cox Communications"),
    (69,): ("US", "United States", "Boston", 42.3601, -71.0589, "Comcast Cable"),
    (72,): ("US", "United States", "Miami", 25.7617, -80.1918, "Comcast Cable"),
    (74,): ("US", "United States", "Atlanta", 33.7490, -84.3880, "Comcast Cable"),
    (76,): ("US", "United States", "Philadelphia", 39.9526, -75.1652, "Comcast Cable"),
    (77,): ("DE", "Germany", "Frankfurt", 50.1109, 8.6821, "Deutsche Telekom"),
    (78,): ("FR", "France", "Paris", 48.8566, 2.3522, "Orange S.A."),
    (80,): ("NL", "Netherlands", "Amsterdam", 52.3676, 4.9041, "KPN B.V."),
    (81,): ("IT", "Italy", "Milan", 45.4642, 9.1900, "Telecom Italia"),
    (82,): ("ES", "Spain", "Madrid", 40.4168, -3.7038, "Telefonica"),
    (83,): ("SE", "Sweden", "Stockholm", 59.3293, 18.0686, "Telia Company"),
    (84,): ("CH", "Switzerland", "Zurich", 47.3769, 8.5417, "Swisscom"),
    (85,): ("RU", "Russia", "Moscow", 55.7558, 37.6173, "Rostelecom"),
    (87,): ("PL", "Poland", "Warsaw", 52.2297, 21.0122, "Orange Polska"),
    (88,): ("TR", "Turkey", "Istanbul", 41.0082, 28.9784, "Turk Telekom"),
    (89,): ("RO", "Romania", "Bucharest", 44.4268, 26.1025, "RCS & RDS"),
    (90,): ("BR", "Brazil", "Sao Paulo", -23.5505, -46.6333, "Vivo"),
    (91,): ("IN", "India", "Mumbai", 19.0760, 72.8777, "Reliance Jio"),
    (92,): ("CN", "China", "Beijing", 39.9042, 116.4074, "China Telecom"),
    (93,): ("AU", "Australia", "Sydney", -33.8688, 151.2093, "Telstra"),
    (94,): ("KR", "South Korea", "Seoul", 37.5665, 126.9780, "KT Corporation"),
    (95,): ("SG", "Singapore", "Singapore", 1.3521, 103.8198, "Singtel"),
    (96,): ("HK", "Hong Kong", "Hong Kong", 22.3193, 114.1694, "PCCW"),
    (97,): ("ZA", "South Africa", "Johannesburg", -26.2041, 28.0473, "Vodacom"),
    (98,): ("MX", "Mexico", "Mexico City", 19.4326, -99.1332, "Telmex"),
    (99,): ("AR", "Argentina", "Buenos Aires", -34.6037, -58.3816, "Telecom Argentina"),
}


class MaxMindGeoIPService:
    """
    Implementacao real usando MaxMind GeoLite2 (.mmdb local).

    Mantem a API classmethod historica para preservar compatibilidade
    com ``transforms/geoip.py`` e testes existentes.
    """

    source_label = "maxmind_geolite2"

    # Estado lazy compartilhado por todas as chamadas (uma unica abertura
    # do arquivo .mmdb por processo).
    _reader: Optional[Any] = None
    _reader_loaded: bool = False

    @classmethod
    def _get_reader(cls):
        """Lazy-load the MaxMind database reader."""
        if cls._reader_loaded:
            return cls._reader

        cls._reader_loaded = True

        if not _HAS_MAXMIND:
            logger.debug("maxminddb not available; using simulated GeoIP")
            return None

        db_path = GEOIP_DB_PATH
        if not os.path.isfile(db_path):
            alt_paths = [
                "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
                "/var/lib/GeoIP/GeoLite2-City.mmdb",
                os.path.expanduser("~/.geoip/GeoLite2-City.mmdb"),
                os.path.join(
                    os.path.dirname(__file__), "..", "..", "data", "GeoLite2-City.mmdb"
                ),
            ]
            for alt in alt_paths:
                if os.path.isfile(alt):
                    db_path = alt
                    break
            else:
                logger.info(
                    "GeoLite2 database not found at %s; using simulated GeoIP",
                    GEOIP_DB_PATH,
                )
                return None

        try:
            cls._reader = maxminddb.open_database(db_path)
            logger.info("GeoLite2 database loaded from %s", db_path)
            return cls._reader
        except Exception as exc:
            logger.warning("Failed to open GeoLite2 database: %s", exc)
            return None

    @classmethod
    def lookup(cls, ip: str) -> Optional[Dict[str, Any]]:
        """Look up geolocation data for an IP address."""
        reader = cls._get_reader()
        if reader is None:
            return None

        try:
            result = reader.get(ip)
            if result is None:
                return None

            country = result.get("country", {}) or {}
            city = result.get("city", {}) or {}
            location = result.get("location", {}) or {}
            subdivisions = result.get("subdivisions", []) or []

            return {
                "ip": ip,
                "country": country.get("iso_code", ""),
                "country_name": (country.get("names") or {}).get("en", ""),
                "city": (city.get("names") or {}).get("en", ""),
                "postal_code": (result.get("postal") or {}).get("code", ""),
                "latitude": location.get("latitude"),
                "longitude": location.get("longitude"),
                "accuracy_radius": location.get("accuracy_radius"),
                "timezone": location.get("time_zone", ""),
                "continent": (result.get("continent") or {}).get("names", {}).get("en", ""),
                "subdivision": (
                    (subdivisions[0].get("names") or {}).get("en", "")
                    if subdivisions
                    else ""
                ),
                "source": cls.source_label,
                "simulated": False,
            }
        except Exception as exc:
            logger.warning("GeoIP lookup failed for %s: %s", ip, exc)
            return None

    @classmethod
    def investigate_ip(cls, ip: str) -> Dict[str, Any]:
        """
        Orquestra consulta GeoIP via MaxMind.

        Em caso de erro no banco, delega para ``SimulatedGeoIPService`` para
        manter o transform funcionando. O resultado tera
        ``simulated=True`` explicito.
        """
        result = cls.lookup(ip)
        if result is not None:
            return result

        logger.debug("GeoIP MaxMind indisponivel para %s; usando SimulatedGeoIPService", ip)
        return SimulatedGeoIPService.investigate_ip(ip)


class SimulatedGeoIPService:
    """Implementacao simulada deterministica por faixa de IP."""

    source_label = "geoip_simulated"

    @staticmethod
    def investigate_ip(ip: str) -> Dict[str, Any]:
        first_octet = 0
        ip_parts = ip.split(".")
        if len(ip_parts) == 4:
            try:
                first_octet = int(ip_parts[0])
            except ValueError:
                first_octet = 0

        for (start,), (country, country_name, city, lat, lon, org) in _SIMULATED_LOCATIONS.items():
            if first_octet == start:
                return {
                    "ip": ip,
                    "country": country,
                    "country_name": country_name,
                    "city": city,
                    "postal_code": "",
                    "latitude": lat,
                    "longitude": lon,
                    "accuracy_radius": 50,
                    "timezone": "",
                    "continent": "",
                    "subdivision": "",
                    "organization": org,
                    "source": SimulatedGeoIPService.source_label,
                    "simulated": True,
                }

        return {
            "ip": ip,
            "country": "US",
            "country_name": "United States",
            "city": "Unknown",
            "postal_code": "",
            "latitude": 37.7510,
            "longitude": -97.8220,
            "accuracy_radius": 1000,
            "timezone": "",
            "continent": "North America",
            "subdivision": "",
            "organization": "Unknown ISP",
            "source": SimulatedGeoIPService.source_label,
            "simulated": True,
        }

    @staticmethod
    def lookup(ip: str) -> Optional[Dict[str, Any]]:
        """Lookup low-level do backend simulado. Retorna o mesmo dict de
        ``investigate_ip`` (sem ``simulated`` extra)."""
        result = SimulatedGeoIPService.investigate_ip(ip)
        return {
            k: v for k, v in result.items() if k in {
                "ip", "country", "country_name", "city", "postal_code",
                "latitude", "longitude", "accuracy_radius", "timezone",
                "continent", "subdivision", "source",
            }
        }


# Backwards-compat: alias para a implementacao real. Permite que
# ``GeoIPService.investigate_ip(...)`` e ``GeoIPService.lookup(...)``
# continuem funcionando como classmethods para todos os consumidores
# existentes (transforms/geoip.py, testes, health-check).
GeoIPService = MaxMindGeoIPService


def _resolve_geoip_mode() -> str:
    """Resolve modo via env var, default: real se backend disponivel."""
    forced = os.environ.get("OPENM_GEOIP_MODE", "").lower()
    if forced in ("real", "simulated"):
        return forced
    if not _HAS_MAXMIND:
        return "simulated"
    candidate_paths = [
        GEOIP_DB_PATH,
        "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
        "/var/lib/GeoIP/GeoLite2-City.mmdb",
        os.path.expanduser("~/.geoip/GeoLite2-City.mmdb"),
        os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "GeoLite2-City.mmdb"
        ),
    ]
    return "real" if any(os.path.isfile(p) for p in candidate_paths) else "simulated"


def get_geoip_service():
    """
    Factory: retorna a implementacao adequada de GeoIP.

    Decisao:
      - ``OPENM_GEOIP_MODE=real`` → sempre MaxMindGeoIPService.
      - ``OPENM_GEOIP_MODE=simulated`` → sempre SimulatedGeoIPService.
      - Caso contrario: real se backend MaxMind disponivel, senao simulated.

    Returns:
        ``MaxMindGeoIPService`` ou ``SimulatedGeoIPService``.
    """
    mode = _resolve_geoip_mode()
    if mode == "simulated":
        logger.debug("GeoIP factory: usando SimulatedGeoIPService")
        return SimulatedGeoIPService()
    return MaxMindGeoIPService()
