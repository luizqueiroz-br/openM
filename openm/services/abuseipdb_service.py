import logging
import os
from typing import Any, Dict, Optional

import requests

from openm.extensions import db
from openm.models.api_key import ApiKey

logger = logging.getLogger(__name__)


class AbuseIPDBService:
    """
    Servico de consulta a API AbuseIPDB v2 para reputacao de IPs.

    Documentacao: https://docs.abuseipdb.com/
    Endpoint: GET /api/v2/check?ipAddress={ip}
    Free tier: 1.000 req/dia.

    Resposta contem `data.attributes` com abuseConfidenceScore,
    countryCode, usageType, isp, domain, totalReports, numDistinctUsers,
    lastReportedAt, etc.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    @staticmethod
    def get_key() -> Optional[str]:
        """Busca chave ativa para AbuseIPDB no PostgreSQL ou env."""
        key = (
            ApiKey.query.filter_by(
                service_name="abuseipdb", is_active=True
            )
            .order_by(ApiKey.updated_at.desc())
            .first()
        )
        if key:
            key.usage_count += 1
            db.session.commit()
            return key.key_value
        return os.environ.get("ABUSEIPDB_API_KEY")

    @classmethod
    def query_ip(cls, ip: str) -> Optional[Dict[str, Any]]:
        """
        Consulta GET /check para um endereco IP.

        Retorna o objeto `data.attributes` parseado, ou None em erro
        ou quando a chave nao esta configurada.
        """
        key = cls.get_key()
        if not key:
            logger.warning("AbuseIPDB API key nao configurada")
            return None

        url = f"{cls.BASE_URL}/check"
        headers = {
            "Key": key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "",  # free tier ignora, mas documentacao aceita
        }
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=15)
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB request falhou para %s: %s", ip, exc)
            return None

        if resp.status_code == 404:
            logger.warning("AbuseIPDB nao encontrou dados para %s", ip)
            return None
        if resp.status_code in (401, 403):
            logger.warning(
                "AbuseIPDB chave invalida para %s (status %d)", ip, resp.status_code
            )
            return None
        if resp.status_code == 429:
            logger.warning("AbuseIPDB rate-limit para %s", ip)
            return None
        if resp.status_code != 200:
            logger.warning(
                "AbuseIPDB resposta nao tratada para %s: status=%d",
                ip, resp.status_code,
            )
            return None

        try:
            data = resp.json()
        except ValueError:
            logger.warning("AbuseIPDB resposta nao-JSON para %s", ip)
            return None

        if not isinstance(data, dict):
            return None
        inner = data.get("data") or {}
        attrs = inner.get("attributes") if isinstance(inner, dict) else None
        if not isinstance(attrs, dict):
            return None
        return attrs

    @classmethod
    def investigate_ip(cls, ip: str) -> Dict[str, Any]:
        """
        Orquestra consulta ao AbuseIPDB e normaliza o resultado.

        Retorna estrutura padronizada:
          - available: True se a API respondeu com dados.
          - abuse_confidence_score: 0-100.
          - country_code, usage_type, isp, domain.
          - total_reports, num_distinct_users, last_reported_at.
          - is_public, is_whitelisted.
          - checked_at: ISO UTC.
        """
        from datetime import datetime, timezone

        checked_at = datetime.now(timezone.utc).isoformat()
        base: Dict[str, Any] = {
            "value": ip,
            "type": "IPAddress",
            "source": "abuseipdb",
            "available": False,
            "abuse_confidence_score": None,
            "country_code": None,
            "usage_type": None,
            "isp": None,
            "domain": None,
            "total_reports": None,
            "num_distinct_users": None,
            "last_reported_at": None,
            "is_public": None,
            "is_whitelisted": None,
            "checked_at": checked_at,
        }

        attrs = cls.query_ip(ip)
        if attrs is None:
            return base

        base["available"] = True
        base["abuse_confidence_score"] = attrs.get("abuseConfidenceScore")
        base["country_code"] = attrs.get("countryCode")
        base["usage_type"] = attrs.get("usageType")
        base["isp"] = attrs.get("isp")
        base["domain"] = attrs.get("domain")
        base["total_reports"] = attrs.get("totalReports")
        base["num_distinct_users"] = attrs.get("numDistinctUsers")
        base["last_reported_at"] = attrs.get("lastReportedAt")
        base["is_public"] = attrs.get("isPublic")
        base["is_whitelisted"] = attrs.get("isWhitelisted")
        return base
