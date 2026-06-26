import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

from openm.extensions import db
from openm.models.api_key import ApiKey

logger = logging.getLogger(__name__)


class VirusTotalService:
    """
    Serviço de consulta à API VirusTotal v3 para reputação de domínios
    e endereços IP.

    Documentação: https://docs.virustotal.com/
    Endpoints:
        - GET /api/v3/domains/{domain} — análise e reputação de domínio
        - GET /api/v3/ip_addresses/{ip} — análise e reputação de IP

    Free tier: 4 req/min, 500/dia (reset 00:00 UTC).
    Resposta em JSON:API com `data.attributes.last_analysis_stats`,
    `reputation` e `last_analysis_results` (por engine).
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    # Backoff exponencial para 429 (TooManyRequestsError / QuotaExceededError).
    # 60s, 120s, 240s — segue as recomendações de free tier do VT.
    BACKOFF_SCHEDULE = (60, 120, 240)

    @staticmethod
    def get_key() -> Optional[str]:
        """Busca chave ativa para VirusTotal no PostgreSQL ou env."""
        key = (
            ApiKey.query.filter_by(
                service_name="virustotal", is_active=True
            )
            .order_by(ApiKey.updated_at.desc())
            .first()
        )
        if key:
            key.usage_count += 1
            db.session.commit()
            return key.key_value
        return os.environ.get("VIRUSTOTAL_API_KEY")

    @classmethod
    def _request_with_retry(
        cls,
        url: str,
        headers: Dict[str, str],
        timeout: int = 15,
        sleep_seconds: Optional[int] = None,
    ) -> Optional[requests.Response]:
        """
        Faz GET com retry/backoff para 429.

        Retorna a Response em caso de 200, ou None em 404 (sem dados),
        em erros 4xx/5xx não retentáveis, ou após esgotar as tentativas.

        Parâmetros:
            url, headers, timeout: repassados para requests.get.
            sleep_seconds: se fornecido, sobrescreve o backoff schedule
                (usado em testes para evitar waits reais).
        """
        last_resp: Optional[requests.Response] = None
        max_retries = len(cls.BACKOFF_SCHEDULE) + 1  # 1 + 3 tentativas = 4 total
        for attempt in range(max_retries):
            try:
                resp = requests.get(url, headers=headers, timeout=timeout)
            except requests.RequestException as exc:
                logger.warning(
                    "VirusTotal request falhou para %s: %s", url, exc
                )
                return None

            if resp.status_code == 200:
                return resp
            if resp.status_code == 404:
                # Sem dados — não é falha retentável.
                return resp
            if resp.status_code == 429:
                last_resp = resp
                if attempt >= len(cls.BACKOFF_SCHEDULE):
                    logger.warning(
                        "VirusTotal rate-limit esgotou tentativas para %s",
                        url,
                    )
                    return None
                # Decide quanto esperar
                if sleep_seconds is not None:
                    wait = sleep_seconds
                else:
                    wait = cls.BACKOFF_SCHEDULE[attempt]
                logger.info(
                    "VirusTotal 429 para %s (tentativa %d/%d), aguardando %ds",
                    url, attempt + 1, max_retries, wait,
                )
                time.sleep(wait)
                continue
            if resp.status_code in (401, 403):
                logger.warning(
                    "VirusTotal chave inválida para %s (status %d)",
                    url, resp.status_code,
                )
                return None
            # Outros 4xx/5xx: log + None
            logger.warning(
                "VirusTotal resposta não tratada para %s: status=%d",
                url, resp.status_code,
            )
            return None

        return last_resp

    @classmethod
    def query_domain(
        cls, domain: str, sleep_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Consulta GET /domains/{domain}.

        Retorna o objeto `data.attributes` parseado, ou None em 404/erro.
        """
        key = cls.get_key()
        if not key:
            logger.warning("VirusTotal API key não configurada")
            return None

        url = f"{cls.BASE_URL}/domains/{domain}"
        headers = {"x-apikey": key, "accept": "application/json"}
        resp = cls._request_with_retry(
            url, headers, sleep_seconds=sleep_seconds
        )
        if resp is None or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            logger.warning("VirusTotal resposta não-JSON para %s", domain)
            return None
        # JSON:API: atributos ficam em data.attributes
        if not isinstance(data, dict):
            return None
        inner = data.get("data") or {}
        attrs = inner.get("attributes") if isinstance(inner, dict) else None
        if not isinstance(attrs, dict):
            return None
        return attrs

    @classmethod
    def query_ip(
        cls, ip: str, sleep_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Consulta GET /ip_addresses/{ip}.

        Retorna o objeto `data.attributes` parseado, ou None em 404/erro.
        """
        key = cls.get_key()
        if not key:
            logger.warning("VirusTotal API key não configurada")
            return None

        url = f"{cls.BASE_URL}/ip_addresses/{ip}"
        headers = {"x-apikey": key, "accept": "application/json"}
        resp = cls._request_with_retry(
            url, headers, sleep_seconds=sleep_seconds
        )
        if resp is None or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            logger.warning("VirusTotal resposta não-JSON para %s", ip)
            return None
        if not isinstance(data, dict):
            return None
        inner = data.get("data") or {}
        attrs = inner.get("attributes") if isinstance(inner, dict) else None
        if not isinstance(attrs, dict):
            return None
        return attrs

    @classmethod
    def _build_flagged_by(
        cls, attributes: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """
        Filtra engines que marcaram o alvo como malicious ou suspicious.

        Retorna lista de dicts `{engine, category, result}`.
        """
        results = attributes.get("last_analysis_results") or {}
        flagged: List[Dict[str, str]] = []
        if not isinstance(results, dict):
            return flagged
        for engine_name, info in results.items():
            if not isinstance(info, dict):
                continue
            category = info.get("category")
            if category in ("malicious", "suspicious"):
                flagged.append({
                    "engine": str(engine_name),
                    "category": str(category),
                    "result": str(info.get("result", "") or ""),
                })
        return flagged

    @classmethod
    def _normalize_stats(
        cls, attributes: Dict[str, Any],
    ) -> Optional[Dict[str, int]]:
        """Extrai last_analysis_stats como dict padronizado, ou None.

        Retorna None quando o atributo `last_analysis_stats` está
        ausente ou é um dict vazio (a API nem sempre retorna o campo
        para entradas recém-criadas).
        """
        stats = attributes.get("last_analysis_stats") or {}
        if not isinstance(stats, dict) or not stats:
            return None
        return {
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "timeout": int(stats.get("timeout", 0) or 0),
        }

    @classmethod
    def investigate_entity(
        cls, entity_type: str, value: str,
        sleep_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Orquestra consulta ao VirusTotal para um Domain ou IPAddress.

        Retorna estrutura padronizada com:
          - available: True se a API respondeu com dados, False caso
            contrário (404 / erro / chave ausente).
          - reputation, last_analysis_stats, flagged_by (apenas engines
            com categoria malicious ou suspicious).
        """
        from datetime import datetime, timezone

        checked_at = datetime.now(timezone.utc).isoformat()

        base: Dict[str, Any] = {
            "value": value,
            "type": entity_type,
            "source": "virustotal",
            "available": False,
            "reputation": None,
            "last_analysis_stats": None,
            "flagged_by": [],
            "checked_at": checked_at,
        }

        # Despacha para o endpoint certo
        if entity_type == "Domain":
            attributes = cls.query_domain(value, sleep_seconds=sleep_seconds)
        elif entity_type == "IPAddress":
            attributes = cls.query_ip(value, sleep_seconds=sleep_seconds)
        else:
            logger.warning(
                "VirusTotal tipo de entidade não suportado: %s", entity_type
            )
            return base

        if attributes is None:
            return base

        base["available"] = True
        base["reputation"] = attributes.get("reputation")
        base["last_analysis_stats"] = cls._normalize_stats(attributes)
        base["flagged_by"] = cls._build_flagged_by(attributes)
        return base
