"""
Serviço de consulta à API Hunter.io v2 para descoberta de pessoas/emails
associados a um domínio (Domain Search) e validação de endereços de email
(Email Verifier).

Documentação: https://hunter.io/api-documentation/v2

Rate limits:
    /domain-search   → 15 req/s + 500 req/min
    /email-verifier  → 10 req/s + 300 req/min
Free tier: 50 créditos/mês (reset mensal).

Status codes não-convencionais Hunter-específicos:
    403 = rate limit de frequência (NÃO quota mensal — retry com backoff)
    429 = quota mensal esgotada (NÃO retry — pare até reset_date)
    451 = pessoa pediu remoção (GDPR) — NÃO armazena/redistribui
    202 = verificação em progresso (específico /email-verifier, polling)
    222 = falha SMTP transitória (específico /email-verifier, retry)

Cache:
    Respostas de 200 são cacheadas em SQLite local (default
    ``/tmp/openm_hunter_cache.db``, configurável via ``HUNTER_CACHE_PATH``)
    com TTL diferenciado por endpoint. Erros, 451 e respostas sem
    `data` nunca são cacheadas.
"""

import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from openm.extensions import db
from openm.models.api_key import ApiKey
from openm.services.sqlite_cache import SqliteCache

logger = logging.getLogger(__name__)


class HunterService:
    """Cliente da API Hunter.io v2 com cache SQLite e retry especializado."""

    BASE_URL = "https://api.hunter.io/v2"

    # Cache TTLs: domain-search muda pouco (7 dias ok),
    # email-verifier é mais dinâmico (24h).
    CACHE_TTL_DOMAIN_SEARCH = 7 * 24 * 3600  # 7 dias
    CACHE_TTL_EMAIL_VERIFIER = 24 * 3600  # 24 horas

    # Configuração de retry
    BACKOFF_403_SCHEDULE = (1.0, 2.0, 4.0)  # 3 retries no máx (rate-limit freq)
    BACKOFF_222_SECONDS = 30.0  # SMTP falha
    POLL_202_SECONDS = 5.0  # verificação em progresso
    MAX_RETRIES_222 = 2  # SMTP retries

    # ---------- Instância / cache ----------

    # Instância singleton lazy (compartilhada entre os classmethods).
    # Isso permite que ``HunterService.domain_search(...)`` funcione sem
    # precisar construir uma instância na chamada — mas ainda assim
    # todos compartilham o mesmo cache em disco. Em testes, basta
    # monkeypatchar ``HunterService._shared_cache`` para isolar.
    _shared_cache: Optional[SqliteCache] = None

    def __init__(self, cache: Optional[SqliteCache] = None):
        cache_path = os.environ.get("HUNTER_CACHE_PATH")
        self.cache = cache or SqliteCache(
            db_path=cache_path or "/tmp/openm_hunter_cache.db"
        )

    @classmethod
    def _get_cache(cls) -> SqliteCache:
        """Retorna cache compartilhado (lazy singleton)."""
        if cls._shared_cache is None:
            cache_path = os.environ.get("HUNTER_CACHE_PATH")
            cls._shared_cache = SqliteCache(
                db_path=cache_path or "/tmp/openm_hunter_cache.db"
            )
        return cls._shared_cache

    # ---------- Chave de API ----------

    @staticmethod
    def get_key() -> Optional[str]:
        """Busca chave ativa para Hunter.io no PostgreSQL ou env.

        Mesma convenção do VirusTotalService: prioriza DB (mais recente
        por ``updated_at``), incrementa ``usage_count`` e faz fallback
        para ``HUNTER_API_KEY`` no ambiente.
        """
        key = (
            ApiKey.query.filter_by(
                service_name="hunter", is_active=True,
            )
            .order_by(ApiKey.updated_at.desc())
            .first()
        )
        if key:
            key.usage_count += 1
            db.session.commit()
            return key.key_value
        return os.environ.get("HUNTER_API_KEY")

    # ---------- Cache helpers ----------

    @staticmethod
    def _cache_key(prefix: str, query: str) -> str:
        """Gera chave de cache estável e não-PII (SHA256).

        Nunca usa o domain/email em claro — apenas o hash SHA256 dele,
        para que logs de DB/cache não exponham dados sensíveis.
        """
        raw = f"{prefix}:{query.lower().strip()}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return f"hunter:{prefix}:{digest}"

    # ---------- HTTP ----------

    @classmethod
    def _request(
        cls,
        endpoint: str,
        params: Dict[str, Any],
        sleep_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Faz request para Hunter.io com tratamento de status codes especiais.

        Returns:
            dict com a response parseada de Hunter (``{"data": ..., "meta": ...}``)
            ou dicts auxiliares sinalizando estados especiais:
              - ``{"quota_exceeded": True, "status": 429}``  — NÃO retentar
              - ``{"gdpr_blocked": True, "status": 451}``    — não cachear
              - ``{"error": <details>, "status": <code>}``   — outros erros
            ``None`` → falha de rede / timeout / chave ausente.
        """
        key = cls.get_key()
        if not key:
            logger.warning("Hunter API key não configurada")
            return None

        url = f"{cls.BASE_URL}{endpoint}"
        headers = {"X-API-KEY": key, "Accept": "application/json"}

        attempt_403 = 0
        attempt_222 = 0
        max_retries_403 = len(cls.BACKOFF_403_SCHEDULE)

        # Loop principal — re-tenta 202, 222 e 403 dentro dos limites.
        while True:
            try:
                resp = requests.get(url, params=params, headers=headers, timeout=20)
            except requests.RequestException as exc:
                logger.warning("Hunter request falhou para %s: %s", url, exc)
                return None

            # 200: sucesso
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    logger.warning("Hunter resposta não-JSON")
                    return {"error": "invalid_json", "status": 200}

            # 202: verificação em progresso (email-verifier) — polling
            if resp.status_code == 202:
                logger.info("Hunter email-verifier em progresso, aguardando")
                cls._sleep(cls.POLL_202_SECONDS, sleep_seconds)
                continue  # re-tenta sem contar como retry

            # 222: falha SMTP transitória (retry 30s, max 2x)
            if resp.status_code == 222:
                attempt_222 += 1
                if attempt_222 > cls.MAX_RETRIES_222:
                    logger.warning("Hunter SMTP falhou após %d retries", attempt_222 - 1)
                    return {"error": "smtp_failure", "status": 222}
                logger.info("Hunter 222 SMTP, retry %d/%d",
                            attempt_222, cls.MAX_RETRIES_222)
                cls._sleep(cls.BACKOFF_222_SECONDS, sleep_seconds)
                continue

            # 403: rate limit de frequência — backoff exponencial
            if resp.status_code == 403:
                attempt_403 += 1
                if attempt_403 > max_retries_403:
                    logger.warning(
                        "Hunter rate-limit (403) esgotou após %d retries",
                        attempt_403 - 1,
                    )
                    return {"error": "rate_limited", "status": 403}
                wait = cls.BACKOFF_403_SCHEDULE[attempt_403 - 1]
                logger.info(
                    "Hunter 403 rate-limit, backoff %.1fs (tentativa %d/%d)",
                    wait, attempt_403, max_retries_403,
                )
                cls._sleep(wait, sleep_seconds)
                continue

            # 429: quota mensal esgotada — NÃO retentar
            if resp.status_code == 429:
                logger.warning("Hunter quota mensal esgotada (429)")
                return {"quota_exceeded": True, "status": 429}

            # 451: GDPR — não armazena, não retorna dados
            if resp.status_code == 451:
                logger.warning(
                    "Hunter 451: titular pediu remoção (GDPR), não armazenando"
                )
                return {"gdpr_blocked": True, "status": 451}

            # Outros erros: extrai message do Hunter se possível
            try:
                err = resp.json()
                errors = err.get("errors", []) if isinstance(err, dict) else []
                details = errors[0].get("details") if errors else resp.text
            except ValueError:
                details = resp.text
            return {"error": details, "status": resp.status_code}

    @staticmethod
    def _sleep(plan: float, override: Optional[float]) -> None:
        """Sleep respeitando override (usado em testes para evitar waits reais).

        Sempre chama ``time.sleep`` (mesmo com 0) — mantém o call site
        observável e compatível com o padrão do ``VirusTotalService``.
        """
        actual = plan if override is None else override
        time.sleep(actual)

    # ---------- Endpoints públicos (com cache) ----------

    @classmethod
    def domain_search(
        cls,
        domain: str,
        sleep_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """GET /v2/domain-search?domain=... — com cache."""
        cache = cls._get_cache()
        cache_key = cls._cache_key("domain_search", domain)

        cached = cache.get(cache_key)
        if cached is not None:
            # Marca cache_hit via wrapper — investigate_domain cuida disso
            return {"data": cached, "_cache_hit": True}

        result = cls._request("/domain-search", {"domain": domain}, sleep_seconds)
        if result is None:
            return None

        # Estado especial (quota/gdpr/error) não é cacheado
        if "quota_exceeded" in result or "gdpr_blocked" in result or "error" in result:
            return result

        # Cacheia apenas se tiver data válida
        data = result.get("data") if isinstance(result, dict) else None
        if isinstance(data, dict):
            cache.set(cache_key, data, ttl_seconds=cls.CACHE_TTL_DOMAIN_SEARCH)
        return result

    @classmethod
    def email_verifier(
        cls,
        email: str,
        sleep_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """GET /v2/email-verifier?email=... — com cache."""
        cache = cls._get_cache()
        cache_key = cls._cache_key("email_verifier", email)

        cached = cache.get(cache_key)
        if cached is not None:
            return {"data": cached, "_cache_hit": True}

        result = cls._request("/email-verifier", {"email": email}, sleep_seconds)
        if result is None:
            return None

        if "quota_exceeded" in result or "gdpr_blocked" in result or "error" in result:
            return result

        data = result.get("data") if isinstance(result, dict) else None
        if isinstance(data, dict):
            cache.set(cache_key, data, ttl_seconds=cls.CACHE_TTL_EMAIL_VERIFIER)
        return result

    # ---------- Orquestração (entrada dos transforms) ----------

    @classmethod
    def investigate_domain(cls, domain: str) -> Dict[str, Any]:
        """Orquestra domain-search e normaliza para estrutura padrão.

        Returns:
            dict com chaves:
              - domain, source='hunter', checked_at (ISO8601)
              - available (bool): False se quota/gdpr/erro/None
              - organization, pattern, accept_all, linked_domains
              - people: lista normalizada de dicts por pessoa
              - quota_exceeded, gdpr_blocked, cache_hit
        """
        checked_at = datetime.now(timezone.utc).isoformat()
        base: Dict[str, Any] = {
            "domain": domain,
            "source": "hunter",
            "available": False,
            "organization": None,
            "pattern": None,
            "accept_all": None,
            "linked_domains": [],
            "people": [],
            "quota_exceeded": False,
            "gdpr_blocked": False,
            "cache_hit": False,
            "checked_at": checked_at,
        }

        result = cls.domain_search(domain)
        if result is None:
            return base

        # Estados especiais vindos de _request
        if result.get("quota_exceeded"):
            base["quota_exceeded"] = True
            return base
        if result.get("gdpr_blocked"):
            base["gdpr_blocked"] = True
            return base
        if result.get("error"):
            # Erro genérico — ainda retorna base com available=False
            return base

        if result.get("_cache_hit"):
            base["cache_hit"] = True

        data = result.get("data") or {}
        if not isinstance(data, dict) or not data:
            return base

        base["available"] = True
        base["organization"] = data.get("organization")
        base["pattern"] = data.get("pattern")
        base["accept_all"] = data.get("accept_all")
        linked = data.get("linked_domains") or []
        base["linked_domains"] = list(linked) if isinstance(linked, list) else []

        people: List[Dict[str, Any]] = []
        for raw in data.get("emails") or []:
            if not isinstance(raw, dict):
                continue
            email_value = raw.get("value")
            if not email_value:
                continue
            sources = raw.get("sources") or []
            verification = raw.get("verification") or {}
            people.append({
                "first_name": raw.get("first_name") or "",
                "last_name": raw.get("last_name") or "",
                "position": raw.get("position"),
                "seniority": raw.get("seniority"),
                "department": raw.get("department"),
                "confidence": int(raw.get("confidence") or 0),
                "email": email_value,
                "email_type": raw.get("type") or "personal",
                "linkedin": raw.get("linkedin"),
                "twitter": raw.get("twitter"),
                "sources": list(sources) if isinstance(sources, list) else [],
                "verification": verification if isinstance(verification, dict) else {},
            })
        base["people"] = people
        return base

    @classmethod
    def investigate_email(cls, email: str) -> Dict[str, Any]:
        """Orquestra email-verifier e normaliza.

        Returns:
            dict com chaves:
              - email, source='hunter', checked_at (ISO8601)
              - available (bool), status, score, deliverable
              - mx_records, smtp_server, smtp_check, accept_all
              - disposable, webmail, block
              - sources: lista de fontes públicas onde aparece
              - quota_exceeded, gdpr_blocked, cache_hit
        """
        checked_at = datetime.now(timezone.utc).isoformat()
        base: Dict[str, Any] = {
            "email": email,
            "source": "hunter",
            "available": False,
            "status": None,
            "score": None,
            "deliverable": None,
            "mx_records": None,
            "smtp_server": None,
            "smtp_check": None,
            "accept_all": None,
            "disposable": None,
            "webmail": None,
            "block": None,
            "sources": [],
            "quota_exceeded": False,
            "gdpr_blocked": False,
            "cache_hit": False,
            "checked_at": checked_at,
        }

        result = cls.email_verifier(email)
        if result is None:
            return base

        if result.get("quota_exceeded"):
            base["quota_exceeded"] = True
            return base
        if result.get("gdpr_blocked"):
            base["gdpr_blocked"] = True
            return base
        if result.get("error"):
            return base

        if result.get("_cache_hit"):
            base["cache_hit"] = True

        data = result.get("data") or {}
        if not isinstance(data, dict) or not data:
            return base

        base["available"] = True
        base["status"] = data.get("status")
        base["score"] = data.get("score")
        base["deliverable"] = (data.get("status") == "valid")
        base["mx_records"] = data.get("mx_records")
        base["smtp_server"] = data.get("smtp_server")
        base["smtp_check"] = data.get("smtp_check")
        base["accept_all"] = data.get("accept_all")
        base["disposable"] = data.get("disposable")
        base["webmail"] = data.get("webmail")
        base["block"] = data.get("block")
        sources = data.get("sources") or []
        base["sources"] = list(sources) if isinstance(sources, list) else []
        return base
