import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Path to GeoLite2 database (configurable via env var)
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "/usr/share/GeoIP/GeoLite2-City.mmdb")

# Try to import maxminddb; if not available, use fallback
try:
    import maxminddb

    _HAS_MAXMIND = True
except ImportError:
    _HAS_MAXMIND = False
    logger.info("maxminddb not installed; GeoIP will use simulated data")


class GeoIPService:
    """
    Serviço de geolocalização de IP usando MaxMind GeoLite2 (offline).

    Se o banco .mmdb não estiver disponível ou a lib maxminddb
    não estiver instalada, usa simulação controlada.
    """

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
            # Try alternative paths
            alt_paths = [
                "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
                "/var/lib/GeoIP/GeoLite2-City.mmdb",
                os.path.expanduser("~/.geoip/GeoLite2-City.mmdb"),
                os.path.join(os.path.dirname(__file__), "..", "..", "data", "GeoLite2-City.mmdb"),
            ]
            for alt in alt_paths:
                if os.path.isfile(alt):
                    db_path = alt
                    break
            else:
                logger.info("GeoLite2 database not found at %s; using simulated GeoIP", GEOIP_DB_PATH)
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
        """
        Look up geolocation data for an IP address.

        Args:
            ip: IPv4 or IPv6 address.

        Returns:
            Dict with country, city, location, ASN, or None.
        """
        reader = cls._get_reader()
        if reader is None:
            return None

        try:
            result = reader.get(ip)
            if result is None:
                return None

            # Normalize the response
            country = result.get("country", {})
            city = result.get("city", {})
            location = result.get("location", {})
            subdivisions = result.get("subdivisions", [])

            return {
                "ip": ip,
                "country": country.get("iso_code", ""),
                "country_name": country.get("names", {}).get("en", ""),
                "city": city.get("names", {}).get("en", ""),
                "postal_code": result.get("postal", {}).get("code", ""),
                "latitude": location.get("latitude"),
                "longitude": location.get("longitude"),
                "accuracy_radius": location.get("accuracy_radius"),
                "timezone": location.get("time_zone", ""),
                "continent": result.get("continent", {}).get("names", {}).get("en", ""),
                "subdivision": (
                    subdivisions[0].get("names", {}).get("en", "")
                    if subdivisions
                    else ""
                ),
                "source": "maxmind_geolite2",
            }
        except Exception as exc:
            logger.warning("GeoIP lookup failed for %s: %s", ip, exc)
            return None

    @classmethod
    def investigate_ip(cls, ip: str) -> Dict[str, Any]:
        """
        Orquestra consulta GeoIP com fallback simulado.

        Retorna estrutura padronizada com país, cidade, coordenadas,
        ASN e organização. Se o banco offline falhar, retorna dados
        simulados controlados.
        """
        result = cls.lookup(ip)

        if result:
            result["source"] = "maxmind_geolite2"
            return result

        # Simulação controlada quando o banco offline não está disponível
        logger.debug("GeoIP: using simulated data for %s", ip)

        # Generate deterministic-ish simulated data based on IP
        ip_parts = ip.split(".")
        if len(ip_parts) == 4:
            try:
                first_octet = int(ip_parts[0])
            except ValueError:
                first_octet = 0
        else:
            first_octet = 0

        # Map common IP ranges to plausible locations
        simulated_locations = {
            # RFC 1918 private ranges
            (10,): ("US", "United States", "New York", 40.7128, -74.0060, "Private Network"),
            (172,): ("US", "United States", "Chicago", 41.8781, -87.6298, "Private Network"),
            (192,): ("US", "United States", "San Francisco", 37.7749, -122.4194, "Private Network"),
            # Common cloud/CDN ranges
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

        # Find matching range
        for (start,), (country, country_name, city, lat, lon, org) in simulated_locations.items():
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
                    "source": "geoip_simulated",
                }

        # Default fallback
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
            "source": "geoip_simulated",
        }
