"""
Servico de consulta a API URLScan.io v1 para analise comportamental de
URLs/dominios.

Documentacao: https://urlscan.io/docs/api/
Endpoints principais:
    - POST /api/v1/scan/         submete uma URL para scan
    - GET  /api/v1/result/{uuid}/   resultado detalhado apos scan completar
    - GET  /api/v1/search/      busca scans anteriores

O scan e assincrono: o submit retorna um UUID e o resultado fica
disponivel apos alguns segundos. Implementamos polling com timeout
configuravel para tests nao esperarem o tempo real.

Resposta do result inclui:
    - page.domain, page.url, page.status
    - task.url, task.method
    - stats (IPv6 percentage, cookie count, etc.)
    - meta.processors
    - lists.ips, lists.domains, lists.urls, lists.countries
    - verdicts (overall.malicious, overall.score)
    - screenshot (URL)
"""
import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

from openm.core.transform import increment_api_call_counter
from openm.extensions import db
from openm.models.api_key import ApiKey

logger = logging.getLogger(__name__)


class UrlscanService:
    """Cliente URLScan.io com polling para scans assincronos."""

    BASE_URL = "https://urlscan.io/api/v1"

    DEFAULT_SUBMIT_TIMEOUT = 15
    DEFAULT_RESULT_TIMEOUT = 15
    DEFAULT_POLL_INTERVAL = 5.0  # segundos entre tentativas
    DEFAULT_POLL_MAX_WAIT = 120.0  # espera total maxima

    @staticmethod
    def get_key() -> Optional[str]:
        """Busca chave ativa para URLScan no PostgreSQL ou env."""
        key = (
            ApiKey.query.filter_by(
                service_name="urlscan", is_active=True
            )
            .order_by(ApiKey.updated_at.desc())
            .first()
        )
        if key:
            key.usage_count += 1
            db.session.commit()
            return key.key_value
        return os.environ.get("URLSCAN_API_KEY")

    @classmethod
    def _headers(cls) -> Dict[str, str]:
        """Headers padrao para URLScan (inclui API key quando configurada)."""
        key = cls.get_key()
        headers = {
            "User-Agent": "OpenM-OSINT-Tool",
            "Accept": "application/json",
        }
        if key:
            headers["API-Key"] = key
        return headers

    @classmethod
    def submit_scan(
        cls,
        target: str,
        *,
        visibility: str = "public",
        poll: bool = True,
        poll_interval: Optional[float] = None,
        poll_max_wait: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Submete uma URL para scan e opcionalmente espera o resultado.

        Args:
            target: URL completa (com scheme) ou dominio (URLScan
                normaliza adicionando https:// se faltando).
            visibility: "public", "unlisted" ou "private". Public eh
                o default. Free tier so permite public/unlisted.
            poll: se True, bloqueia ate o resultado estar pronto
                (polling com timeout).
            poll_interval: override do intervalo entre polls (tests).
            poll_max_wait: override da espera maxima (tests).

        Returns:
            Dict com keys:
              - available: True se o scan completou.
              - uuid: id do scan.
              - result_url: URL do scan no dashboard.
              - screenshot_url: URL da screenshot.
              - page_domain, page_url, page_status.
              - malicious, score.
              - technologies (lista).
              - ips, domains contactados.
              - countries contactados.
              - stats.
              - checked_at: ISO UTC.
            Retorna None se a chave nao estiver configurada ou em erro.
        """
        from datetime import datetime, timezone

        checked_at = datetime.now(timezone.utc).isoformat()
        key = cls.get_key()
        if not key:
            logger.warning("URLScan API key nao configurada")
            return None

        # Garante scheme para URLScan.
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        submit_url = f"{cls.BASE_URL}/scan/"
        try:
            resp = requests.post(
                submit_url,
                headers=cls._headers(),
                json={"url": target, "visibility": visibility},
                timeout=cls.DEFAULT_SUBMIT_TIMEOUT,
            )
        except requests.RequestException as exc:
            logger.warning("URLScan submit falhou para %s: %s", target, exc)
            return None

        if resp.status_code == 429:
            increment_api_call_counter()
            logger.warning("URLScan rate-limit para %s", target)
            return _rate_limited(checked_at)
        if resp.status_code in (401, 403):
            increment_api_call_counter()
            logger.warning(
                "URLScan chave invalida para %s (status %d)", target, resp.status_code
            )
            return _unauthorized(checked_at)
        if resp.status_code != 200:
            increment_api_call_counter()
            logger.warning(
                "URLScan resposta nao tratada para %s: status=%d",
                target, resp.status_code,
            )
            return None

        increment_api_call_counter()
        try:
            submit_data = resp.json()
        except ValueError:
            logger.warning("URLScan submit resposta nao-JSON para %s", target)
            return None

        scan_uuid = submit_data.get("uuid")
        if not scan_uuid:
            logger.warning("URLScan submit sem uuid para %s", target)
            return None

        result_url = submit_data.get("result")
        if not poll:
            return {
                "available": False,
                "uuid": scan_uuid,
                "result_url": result_url,
                "page_url": target,
                "checked_at": checked_at,
            }

        # Polling ate resultado ficar pronto ou timeout.
        interval = poll_interval if poll_interval is not None else cls.DEFAULT_POLL_INTERVAL
        max_wait = poll_max_wait if poll_max_wait is not None else cls.DEFAULT_POLL_MAX_WAIT
        return cls._poll_result(
            scan_uuid, target, result_url, checked_at,
            interval=interval, max_wait=max_wait,
        )

    @classmethod
    def _poll_result(
        cls,
        scan_uuid: str,
        target: str,
        result_url: Optional[str],
        checked_at: str,
        *,
        interval: float,
        max_wait: float,
    ) -> Optional[Dict[str, Any]]:
        deadline = time.time() + max_wait
        attempt = 0
        while time.time() < deadline:
            if attempt > 0:
                # Sleep respeitando override (tests usam 0).
                time.sleep(interval)
            attempt += 1

            url = f"{cls.BASE_URL}/result/{scan_uuid}/"
            try:
                resp = requests.get(url, headers=cls._headers(), timeout=cls.DEFAULT_RESULT_TIMEOUT)
            except requests.RequestException as exc:
                logger.warning("URLScan result poll falhou: %s", exc)
                continue

            if resp.status_code == 200:
                increment_api_call_counter()
                try:
                    data = resp.json()
                except ValueError:
                    logger.warning("URLScan result nao-JSON para %s", scan_uuid)
                    return None
                return cls._normalize_result(data, checked_at)

            if resp.status_code == 404:
                # Scan ainda processando.
                increment_api_call_counter()
                continue

            increment_api_call_counter()
            logger.warning(
                "URLScan result poll status inesperado %d (uuid=%s)",
                resp.status_code, scan_uuid,
            )
            # Nao retorna; continua tentando ate o deadline.
            continue

        # Timeout atingido — scan nao ficou pronto a tempo.
        return {
            "available": False,
            "uuid": scan_uuid,
            "result_url": result_url,
            "page_url": target,
            "checked_at": checked_at,
            "pending": True,
        }

    @classmethod
    def _normalize_result(
        cls, data: Dict[str, Any], checked_at: str,
    ) -> Dict[str, Any]:
        """Normaliza payload do /result/."""
        page = data.get("page") or {}
        task = data.get("task") or {}
        stats = data.get("stats") or []
        verdicts = data.get("verdicts") or {}
        overall = verdicts.get("overall") or {}
        lists = data.get("lists") or {}

        # Tecnologias (wappalyzer-style).
        technologies = []
        for tech in data.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", []) or []:
            technologies.append(tech)

        # Screenshots sao fornecidos via URL separada (ver docs).
        screenshot_url = (
            f"https://urlscan.io/screenshots/{data.get('uuid')}.png"
        )

        return {
            "available": True,
            "uuid": data.get("uuid"),
            "result_url": data.get("result"),
            "screenshot_url": screenshot_url,
            "page_domain": page.get("domain"),
            "page_url": page.get("url") or task.get("url"),
            "page_status": page.get("status"),
            "page_title": page.get("title"),
            "malicious": bool(overall.get("malicious")),
            "score": overall.get("score"),
            "technologies": technologies,
            "ips": cls._flatten_lists(lists.get("ips")),
            "domains": cls._flatten_lists(lists.get("domains")),
            "urls": cls._flatten_lists(lists.get("urls")),
            "countries": cls._flatten_lists(lists.get("countries")),
            "stats": {item.get("key"): item.get("result") for item in stats if isinstance(item, dict)},
            "checked_at": checked_at,
        }

    @staticmethod
    def _flatten_lists(value: Any) -> List[str]:
        """Normaliza lista de ips/dominios/countries do URLScan."""
        if not isinstance(value, list):
            return []
        out: List[str] = []
        for item in value:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                # Formato tipico: {"ip": "1.2.3.4"} ou {"domain": "x.com"}
                for k in ("ip", "domain", "url", "country"):
                    if k in item:
                        out.append(str(item[k]))
                        break
        return out


def _rate_limited(checked_at: str) -> Dict[str, Any]:
    return {
        "available": False,
        "rate_limited": True,
        "checked_at": checked_at,
    }


def _unauthorized(checked_at: str) -> Dict[str, Any]:
    return {
        "available": False,
        "key_valid": False,
        "checked_at": checked_at,
    }
