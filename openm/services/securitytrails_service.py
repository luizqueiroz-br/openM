"""
Servico de consulta a API SecurityTrails v1 (DNS history & associated).

Documentacao: https://docs.securitytrails.com/
Endpoints principais:
  - GET /v1/domain/{domain}              - info atual (whois, alexa, etc)
  - GET /v1/domain/{domain}/subdomains    - lista de subdominios
  - GET /v1/domain/{domain}/associated    - dominios associados
  - GET /v1/history/{domain}/dns/a/{type} - historico de records

Free tier: 50 queries/mes. Como cada chamada conta, o transform
prioriza o endpoint ``/domain/{domain}`` (consolidado) e so busca
subdominios/associated sob demanda (controle interno).

API key: ApiKey(service_name='securitytrails') ou env
``SECURITYTRAILS_API_KEY``. Mesmo padrao de AbuseIPDB/VT/HIBP.
"""
import logging
import os
from typing import Any, Dict, List, Optional

from openm.core.http_client import http_get
from openm.core.transform import increment_api_call_counter
from openm.extensions import db
from openm.models.api_key import ApiKey

logger = logging.getLogger(__name__)


class SecurityTrailsService:
    """Cliente SecurityTrails v1 (DNS history & associated)."""

    BASE_URL = "https://api.securitytrails.com/v1"

    DEFAULT_TIMEOUT = 15

    @staticmethod
    def get_key() -> Optional[str]:
        """Busca chave ativa para SecurityTrails no PostgreSQL ou env."""
        key = (
            ApiKey.query.filter_by(
                service_name="securitytrails", is_active=True
            )
            .order_by(ApiKey.updated_at.desc())
            .first()
        )
        if key:
            key.usage_count += 1
            db.session.commit()
            return key.key_value
        return os.environ.get("SECURITYTRAILS_API_KEY")

    @classmethod
    def _headers(cls) -> Dict[str, str]:
        """Headers com API key."""
        key = cls.get_key()
        headers = {
            "User-Agent": "OpenM-OSINT-Tool",
            "Accept": "application/json",
        }
        if key:
            headers["APIKEY"] = key
        return headers

    @classmethod
    def _request(cls, endpoint: str) -> Optional[Dict[str, Any]]:
        """GET autenticado em endpoint da API."""
        if not cls.get_key():
            logger.warning("SecurityTrails API key nao configurada")
            return None
        url = f"{cls.BASE_URL}{endpoint}"
        resp = http_get(url, headers=cls._headers(), timeout=cls.DEFAULT_TIMEOUT)
        if resp is None:
            logger.warning("SecurityTrails request falhou para %s", url)
            return None
        if resp.status_code == 404:
            return None
        if resp.status_code == 401:
            increment_api_call_counter()
            logger.warning("SecurityTrails chave invalida para %s (401)", url)
            return None
        if resp.status_code == 429:
            increment_api_call_counter()
            logger.warning("SecurityTrails rate-limit para %s", url)
            return None
        if resp.status_code != 200:
            increment_api_call_counter()
            logger.warning(
                "SecurityTrails status %d para %s", resp.status_code, url
            )
            return None
        try:
            return resp.json()
        except ValueError:
            logger.warning("SecurityTrails resposta nao-JSON para %s", url)
            return None

    @classmethod
    def get_domain_info(cls, domain: str) -> Optional[Dict[str, Any]]:
        """GET /v1/domain/{domain} - info atual (whois, alexa, etc).

        Retorna dict com chaves: hostname, alexa_rank, whois (sub-dict),
        ou None em caso de erro/chave ausente.
        """
        return cls._request(f"/domain/{domain}")

    @classmethod
    def get_associated_domains(cls, domain: str) -> Optional[List[Dict[str, Any]]]:
        """GET /v1/domain/{domain}/associated - dominios associados.

        Retorna lista de dicts (com hostname, type, etc) ou None.
        """
        data = cls._request(f"/domain/{domain}/associated")
        if data is None or not isinstance(data, dict):
            return None
        records = data.get("records")
        if not isinstance(records, list):
            return []
        return records

    @classmethod
    def get_subdomains(cls, domain: str) -> Optional[List[str]]:
        """GET /v1/domain/{domain}/subdomains - lista de subdominios.

        Retorna lista de strings (FQDN) ou None.
        """
        data = cls._request(f"/domain/{domain}/subdomains")
        if data is None or not isinstance(data, dict):
            return None
        subs = data.get("subdomains")
        if not isinstance(subs, list):
            return []
        return subs

    @classmethod
    def investigate_domain(cls, domain: str) -> Dict[str, Any]:
        """Orquestra chamada principal (info + subdominios) para um dominio.

        Retorna dict com:
          - available (bool): True se a API respondeu.
          - domain (str): dominio consultado.
          - source ('securitytrails').
          - checked_at (ISO UTC).
          - hostname, alexa_rank, whois (sub-dict).
          - subdomains (lista de strings).
          - available_full (bool): True se ambas chamadas sucederam.
          - quota_exceeded, rate_limited, key_valid (bools).
        """
        from datetime import datetime, timezone

        checked_at = datetime.now(timezone.utc).isoformat()
        key = cls.get_key()
        base: Dict[str, Any] = {
            "domain": domain,
            "source": "securitytrails",
            "available": False,
            "available_full": False,
            "hostname": None,
            "alexa_rank": None,
            "whois": None,
            "subdomains": [],
            "rate_limited": False,
            "key_valid": True,
            "checked_at": checked_at,
        }

        if not key:
            base["key_valid"] = False
            return base

        info = cls.get_domain_info(domain)
        if info is None:
            return base

        base["available"] = True

        # Info atual: hostname, alexa_rank, whois
        if isinstance(info, dict):
            base["hostname"] = info.get("hostname")
            base["alexa_rank"] = info.get("alexa_rank")
            whois = info.get("whois")
            if isinstance(whois, dict):
                base["whois"] = whois

        # Subdominios (chamada extra - consome quota)
        sub = cls.get_subdomains(domain)
        if sub is not None:
            base["subdomains"] = sub
            base["available_full"] = True
        elif sub is None and not base.get("key_valid", True):
            base["key_valid"] = False
        # else: sub retornou [] (dominio sem subdominios) ou 404

        return base
