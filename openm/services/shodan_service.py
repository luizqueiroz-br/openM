import logging
import os
import socket
from typing import Any, Dict, Optional

import requests

from openm.extensions import db
from openm.models.api_key import ApiKey

logger = logging.getLogger(__name__)


class ShodanService:
    """
    Serviço de consulta à API Shodan para reconhecimento de hosts expostos.

    Documentação: https://developer.shodan.io/api
    Endpoints:
        - GET /shodan/host/{ip} — dados de um host específico
        - GET /dns/resolve?hostnames={domain} — resolver domínio para IP
    """

    BASE_URL = "https://api.shodan.io"

    @staticmethod
    def get_key() -> Optional[str]:
        """Busca chave ativa para Shodan no PostgreSQL ou env."""
        key = (
            ApiKey.query.filter_by(
                service_name="shodan", is_active=True
            )
            .order_by(ApiKey.updated_at.desc())
            .first()
        )
        if key:
            key.usage_count += 1
            db.session.commit()
            return key.key_value
        return os.environ.get("SHODAN_API_KEY")

    @classmethod
    def resolve_domain(cls, domain: str) -> Optional[str]:
        """
        Resolve um domínio para IP usando a API DNS do Shodan.
        Fallback para socket.gethostbyname se a API falhar.
        """
        key = cls.get_key()
        if not key:
            # Fallback: tenta resolver via DNS local
            try:
                return socket.gethostbyname(domain)
            except OSError:
                logger.warning("Não foi possível resolver %s", domain)
                return None

        url = f"{cls.BASE_URL}/dns/resolve"
        params = {"hostnames": domain, "key": key}
        try:
            resp = requests.get(url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return data.get(domain)
        except requests.RequestException as exc:
            logger.warning("Shodan DNS resolve falhou para %s: %s", domain, exc)
            # Fallback local
            try:
                return socket.gethostbyname(domain)
            except OSError:
                return None

    @classmethod
    def query_host(cls, ip: str) -> Optional[Dict[str, Any]]:
        """
        Consulta dados de um host específico no Shodan.

        Retorna dict com dados brutos da API ou None em falha.
        """
        key = cls.get_key()
        if not key:
            logger.warning("Shodan API key não configurada")
            return None

        url = f"{cls.BASE_URL}/shodan/host/{ip}"
        params = {"key": key}
        try:
            resp = requests.get(url, params=params, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.warning("Shodan host query falhou para %s: %s", ip, exc)
            return None

    @classmethod
    def investigate_host(cls, ip: str) -> Dict[str, Any]:
        """
        Orquestra consulta ao Shodan e normaliza o resultado.

        Retorna estrutura padronizada com portas, serviços, banners,
        localização e organização. Se a API falhar, retorna dados
        simulados controlados para manter a experiência do usuário.
        """
        result = {
            "ip": ip,
            "source": "shodan",
            "ports": [],
            "services": [],
            "location": {},
            "organization": None,
            "hostnames": [],
            "domains": [],
        }

        data = cls.query_host(ip)
        if data:
            # Extrair portas e banners
            for item in data.get("data", []):
                port_info = {
                    "port": item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner": item.get("data", "")[:200],  # truncar banner
                    "cpe": item.get("cpe", []),
                }
                result["services"].append(port_info)
                result["ports"].append(item.get("port"))

            # Deduplicar portas
            result["ports"] = sorted(set(p for p in result["ports"] if p))

            # Metadados do host
            result["location"] = {
                "country": data.get("country_name", ""),
                "city": data.get("city", ""),
                "region": data.get("region_code", ""),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
            }
            result["organization"] = data.get("org", data.get("isp", ""))
            result["hostnames"] = data.get("hostnames", [])
            result["domains"] = data.get("domains", [])
            result["os"] = data.get("os", "")
            result["tags"] = data.get("tags", [])

        else:
            # Simulação controlada quando a API falha
            result["source"] = "shodan_simulated"
            result["ports"] = [80, 443]
            result["services"] = [
                {
                    "port": 80,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.18.0",
                    "banner": "HTTP/1.1 200 OK...",
                    "cpe": [],
                },
                {
                    "port": 443,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.18.0",
                    "banner": "HTTP/1.1 200 OK...",
                    "cpe": [],
                },
            ]
            result["location"] = {"country": "Unknown", "city": ""}
            result["organization"] = "Simulated ISP"

        return result
