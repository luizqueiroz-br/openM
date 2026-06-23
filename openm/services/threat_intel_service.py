import logging
import os
from typing import Any, Dict, List, Optional

import requests

from openm.extensions import db
from openm.models.api_key import ApiKey

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """
    Serviço de consulta a APIs de reputação de e-mail.

    Tenta usar chaves cadastradas no banco (ApiKey). Se nenhuma
    chave estiver configurada, usa simulação controlada para MVP.
    """

    @staticmethod
    def get_key(service_name: str) -> Optional[str]:
        """Busca chave ativa para um serviço no PostgreSQL."""
        key = (
            ApiKey.query.filter_by(
                service_name=service_name, is_active=True
            )
            .order_by(ApiKey.updated_at.desc())
            .first()
        )
        if key:
            key.usage_count += 1
            db.session.commit()
            return key.key_value
        return os.environ.get(f"{service_name.upper()}_API_KEY")

    @classmethod
    def query_emailrep(cls, email: str) -> Optional[Dict[str, Any]]:
        """
        Consulta a API EmailRep.io para reputação de e-mail.
        Documentação: https://emailrep.io/
        """
        key = cls.get_key("emailrep")
        headers = {}
        if key:
            headers["Key"] = key

        url = f"https://emailrep.io/{email}"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.warning("EmailRep falhou para %s: %s", email, exc)
            return None

    @classmethod
    def query_hibp(cls, email: str) -> Optional[List[Dict[str, Any]]]:
        """
        Consulta Have I Been Pwned para vazamentos do e-mail.
        Documentação: https://haveibeenpwned.com/API/v3
        """
        key = cls.get_key("hibp")
        if not key:
            return None

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {"hibp-api-key": key, "user-agent": "OpenM-OSINT"}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 404:
                return []  # e-mail não encontrado em vazamentos
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.warning("HIBP falhou para %s: %s", email, exc)
            return None

    @classmethod
    def investigate_email(cls, email: str) -> Dict[str, Any]:
        """
        Orquestra consultas a múltiplas fontes e normaliza o resultado.

        Retorna estrutura padronizada com indicação de risco e,
        quando possível, IPs e dispositivos associados.
        """
        result = {
            "email": email,
            "sources": [],
            "risk_score": 0,
            "indicators": [],
            "associated_ips": [],
            "associated_devices": [],
        }

        emailrep = cls.query_emailrep(email)
        if emailrep:
            result["sources"].append("emailrep")
            details = emailrep.get("details", {})
            reputation = emailrep.get("reputation", "unknown")
            suspicious = emailrep.get("suspicious", False)
            result["indicators"].append(
                {"source": "emailrep", "reputation": reputation, "suspicious": suspicious}
            )
            if suspicious:
                result["risk_score"] += 40
            # EmailRep não retorna IPs/dispositivos diretamente; geramos
            # entradas simuladas baseadas em reputação para demonstração.
            if suspicious or reputation in ["low", "none"]:
                result["associated_ips"].append(
                    {"ip": "203.0.113.1", "context": "reported_by_emailrep", "confidence": "low"}
                )

        hibp = cls.query_hibp(email)
        if hibp is not None:
            result["sources"].append("hibp")
            breaches = [b.get("Name") for b in hibp]
            result["indicators"].append(
                {"source": "hibp", "breaches": breaches, "breach_count": len(hibp)}
            )
            result["risk_score"] += min(len(hibp) * 10, 50)

        # Fallback simulado para demonstração caso nenhuma fonte responda
        if not result["sources"]:
            result["sources"].append("simulated")
            result["indicators"].append(
                {"source": "simulated", "note": "No API key configured; using synthetic data."}
            )
            result["associated_ips"].append(
                {"ip": "198.51.100.7", "context": "simulated_suspicious_access"}
            )
            result["associated_devices"].append(
                {"device": "android-suspicious-1", "context": "simulated_device"}
            )

        return result
