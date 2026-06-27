import logging
import os
from typing import Any, Dict, List, Optional

import requests

from openm.core import http_client
from openm.extensions import db
from openm.models.api_key import ApiKey

logger = logging.getLogger(__name__)


class HibpService:
    """
    Servico de consulta a API Have I Been Pwned v3.

    Documentacao: https://haveibeenpwned.com/API/v3
    Endpoints:
        - GET /api/v3/breachedaccount/{email} — breaches de um email.
        - GET /api/v3/breacheddomain/{domain} — emails expostos de um
          dominio (requer plano pago/autorizado; retorna 401 se nao
          tiver acesso).
        - GET /api/v3/breach/{name} — detalhes de uma breach.

    Free tier: consulta de breachedaccount paga a partir de 2019; exige
    chave de API (US$ 3,95/mes no tier mais basico). Sem chave ou com
    chave invalida o endpoint retorna 401/403.
    """

    BASE_URL = "https://haveibeenpwned.com/api/v3"
    DEFAULT_TIMEOUT = 15

    @staticmethod
    def get_key() -> Optional[str]:
        """Busca chave ativa para HIBP no PostgreSQL ou env."""
        key = (
            ApiKey.query.filter_by(
                service_name="hibp", is_active=True
            )
            .order_by(ApiKey.updated_at.desc())
            .first()
        )
        if key:
            key.usage_count += 1
            db.session.commit()
            return key.key_value
        return os.environ.get("HIBP_API_KEY")

    @classmethod
    def _request(
        cls,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[requests.Response]:
        """Faz GET autenticado no HIBP com timeout e user-agent."""
        key = cls.get_key()
        if not key:
            logger.warning("HIBP API key nao configurada")
            return None

        url = f"{cls.BASE_URL}{endpoint}"
        headers = {
            "hibp-api-key": key,
            "User-Agent": "OpenM-OSINT-Tool",
        }
        resp = http_client.http_get(
            url,
            params=params or {},
            headers=headers,
            timeout=cls.DEFAULT_TIMEOUT,
        )
        if resp is None:
            logger.warning("HIBP request falhou para %s", url)
            return None

        if resp.status_code == 404:
            # 404 = nenhuma breach encontrada (email limpo ou breach
            # inexistente). Nao e erro, retornamos a Response para que
            # os callers tratem como lista vazia.
            return resp
        if resp.status_code in (401, 403):
            logger.warning(
                "HIBP chave invalida ou sem acesso para %s (status %d)",
                url, resp.status_code,
            )
            return None
        if resp.status_code == 429:
            logger.warning("HIBP rate-limit para %s", url)
            return None
        if resp.status_code != 200:
            logger.warning(
                "HIBP resposta nao tratada para %s: status=%d",
                url, resp.status_code,
            )
            return None
        return resp

    @classmethod
    def query_email_breaches(
        cls, email: str, truncate_response: bool = False,
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Consulta breaches de um email.

        Retorna lista de dicts com campos da breach, ou None em erro
        de chave/autenticacao. 404 é interpretado como lista vazia
        (email nao encontrado em nenhuma breach).
        """
        endpoint = f"/breachedaccount/{email}"
        params = {"truncateResponse": "false"} if not truncate_response else {}
        resp = cls._request(endpoint, params=params)
        if resp is None:
            return None
        if resp.status_code == 404:
            return []
        try:
            data = resp.json()
        except ValueError:
            logger.warning("HIBP resposta nao-JSON para %s", email)
            return None
        if not isinstance(data, list):
            return None
        return data

    @classmethod
    def query_domain_breaches(
        cls, domain: str,
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Consulta emails expostos de um dominio.

        Endpoint pago/autorizado. Retorna lista de dicts {email, breaches}
        ou None se a conta nao tiver acesso / chave invalida / erro.
        404 retorna lista vazia.
        """
        endpoint = f"/breacheddomain/{domain}"
        resp = cls._request(endpoint)
        if resp is None:
            return None
        if resp.status_code == 404:
            return []
        try:
            data = resp.json()
        except ValueError:
            logger.warning("HIBP resposta nao-JSON para dominio %s", domain)
            return None
        if not isinstance(data, list):
            return None
        return data

    @classmethod
    def query_breach_details(cls, name: str) -> Optional[Dict[str, Any]]:
        """Consulta detalhes de uma breach pelo nome tecnico."""
        endpoint = f"/breach/{name}"
        resp = cls._request(endpoint)
        if resp is None:
            return None
        if resp.status_code == 404:
            return None
        try:
            return resp.json()
        except ValueError:
            logger.warning("HIBP resposta nao-JSON para breach %s", name)
            return None

    @classmethod
    def investigate_email(cls, email: str) -> Dict[str, Any]:
        """
        Orquestra consulta ao HIBP para um email.

        Retorna dict:
          - available: True se obteve resposta (mesmo que vazia).
          - breaches: lista de dicts normalizados.
          - breach_count: quantidade.
          - checked_at: ISO UTC.
        """
        from datetime import datetime, timezone

        checked_at = datetime.now(timezone.utc).isoformat()
        base: Dict[str, Any] = {
            "value": email,
            "type": "Email",
            "source": "hibp",
            "available": False,
            "breaches": [],
            "breach_count": 0,
            "checked_at": checked_at,
        }

        breaches = cls.query_email_breaches(email)
        if breaches is None:
            return base

        normalized = [cls._normalize_breach(b) for b in breaches]
        base["available"] = True
        base["breaches"] = normalized
        base["breach_count"] = len(normalized)
        return base

    @classmethod
    def investigate_domain(cls, domain: str) -> Dict[str, Any]:
        """
        Orquestra consulta ao HIBP para um dominio.

        Endpoint pago; se a conta nao tiver acesso, available=False.
        """
        from datetime import datetime, timezone

        checked_at = datetime.now(timezone.utc).isoformat()
        base: Dict[str, Any] = {
            "value": domain,
            "type": "Domain",
            "source": "hibp",
            "available": False,
            "exposed_emails": [],
            "exposed_email_count": 0,
            "checked_at": checked_at,
        }

        exposed = cls.query_domain_breaches(domain)
        if exposed is None:
            return base

        base["available"] = True
        base["exposed_emails"] = exposed
        base["exposed_email_count"] = len(exposed)
        return base

    @classmethod
    def _normalize_breach(cls, breach: Dict[str, Any]) -> Dict[str, Any]:
        """Normaliza campos de uma breach para uso no grafo."""
        return {
            "name": breach.get("Name", ""),
            "title": breach.get("Title", ""),
            "domain": breach.get("Domain", ""),
            "breach_date": breach.get("BreachDate", ""),
            "added_date": breach.get("AddedDate", ""),
            "modified_date": breach.get("ModifiedDate", ""),
            "pwn_count": breach.get("PwnCount", 0),
            "description": breach.get("Description", ""),
            "data_classes": breach.get("DataClasses", []),
            "is_verified": bool(breach.get("IsVerified", False)),
            "is_fabricated": bool(breach.get("IsFabricated", False)),
            "is_sensitive": bool(breach.get("IsSensitive", False)),
            "is_retired": bool(breach.get("IsRetired", False)),
            "is_spam_list": bool(breach.get("IsSpamList", False)),
            "logo_path": breach.get("LogoPath", ""),
        }
