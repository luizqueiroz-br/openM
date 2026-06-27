"""
Cliente HTTP centralizado com timeout + retry policy (issue #77).

Substitui o padrao ad-hoc de ``requests.get(..., timeout=...)`` espalhado
pelos services por um helper que:

- Aplica timeout consistente (default 15s).
- Re-tenta erros retentaveis (5xx, 429, ConnectionError, Timeout) com
  backoff exponencial.
- Respeita o header ``Retry-After`` quando presente (429).
- Incrementa o contador de chamadas externas via
  ``increment_api_call_counter`` para que as metricas de transform
  (issue #80) contabilizem cada request.
- Permite override do sleep entre tentativas (usado em testes para
  nao esperar o tempo real de backoff).

Decisao de design: nao tenta-se re-tentar 4xx que nao sejam 429
(cliente invalido, sem retry), nem POSTs por padrao (cada service
decide se a chamada eh idempotente).
"""
import logging
import time
from typing import Any, Dict, Optional, Tuple

import requests

from openm.core.transform import increment_api_call_counter

logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 15.0
DEFAULT_BACKOFF_SCHEDULE = (1.0, 2.0, 4.0)  # 3 retries com backoff exponencial
DEFAULT_RETRIABLE_STATUS = (429, 500, 502, 503, 504)
MAX_BACKOFF_CAP_SECONDS = 60.0


class HttpRequestError(Exception):
    """Erro levantado pelo helper quando todos os retries falham."""


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Converte o header Retry-After em segundos.

    Suporta tanto valor numerico (segundos) quanto data HTTP. Em caso
    de valor invalido, retorna None.
    """
    if not value:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    return min(seconds, MAX_BACKOFF_CAP_SECONDS)


def http_get(
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_retries: int = 3,
    backoff_schedule: Tuple[float, ...] = DEFAULT_BACKOFF_SCHEDULE,
    retriable_status: Tuple[int, ...] = DEFAULT_RETRIABLE_STATUS,
    sleep_seconds: Optional[float] = None,
) -> Optional[requests.Response]:
    """
    GET HTTP com retry exponencial.

    Args:
        url: URL completa.
        params: query params.
        headers: headers extras (User-Agent etc).
        timeout: timeout por tentativa em segundos.
        max_retries: numero maximo de tentativas adicionais (default 3,
            alem da primeira = 4 tentativas totais).
        backoff_schedule: tupla com segundos de espera entre tentativas.
            O tamanho da tupla limita os retries: ``len(schedule)``
            tentativas com backoff depois da primeira request.
        retriable_status: status HTTP que devem disparar retry.
        sleep_seconds: se fornecido, sobrescreve o backoff schedule
            (usado em testes para nao esperar o tempo real).

    Returns:
        ``requests.Response`` em sucesso. ``None`` em falha final ou
        status nao retentavel.

    Raises:
        Nenhuma excecao eh levantada para erros HTTP. ``RequestException``
        eh capturada e o helper retorna ``None`` apos esgotar tentativas.
    """
    return _request_with_retry(
        method="GET",
        url=url,
        params=params,
        headers=headers,
        timeout=timeout,
        max_retries=max_retries,
        backoff_schedule=backoff_schedule,
        retriable_status=retriable_status,
        sleep_seconds=sleep_seconds,
    )


def http_post(
    url: str,
    *,
    json: Optional[Any] = None,
    data: Optional[Any] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_retries: int = 1,
    backoff_schedule: Tuple[float, ...] = (1.0,),
    retriable_status: Tuple[int, ...] = DEFAULT_RETRIABLE_STATUS,
    sleep_seconds: Optional[float] = None,
) -> Optional[requests.Response]:
    """
    POST HTTP com retry opcional.

    Args:
        url: URL completa.
        json: payload JSON (serializado pelo helper).
        data: payload form-encoded (alternativa a ``json``).
        headers: headers extras.
        timeout: timeout por tentativa.
        max_retries: por default 1 para POSTs (cada service decide se
            o endpoint eh idempotente e merece mais tentativas).
        sleep_seconds: override do sleep (testes).

    Returns:
        ``Response`` em sucesso ou ``None`` em falha final.
    """
    return _request_with_retry(
        method="POST",
        url=url,
        params=None,
        headers=headers,
        timeout=timeout,
        max_retries=max_retries,
        backoff_schedule=backoff_schedule,
        retriable_status=retriable_status,
        sleep_seconds=sleep_seconds,
        json=json,
        data=data,
    )


def _request_with_retry(
    method: str,
    url: str,
    *,
    params: Optional[Dict[str, Any]],
    headers: Optional[Dict[str, str]],
    timeout: float,
    max_retries: int,
    backoff_schedule: Tuple[float, ...],
    retriable_status: Tuple[int, ...],
    sleep_seconds: Optional[float],
    json: Optional[Any] = None,
    data: Optional[Any] = None,
) -> Optional[requests.Response]:
    """Implementacao compartilhada de GET/POST com retry."""
    max_attempts = min(max_retries, len(backoff_schedule)) + 1
    last_response: Optional[requests.Response] = None

    for attempt in range(max_attempts):
        try:
            if method == "GET":
                resp = requests.get(url, params=params, headers=headers, timeout=timeout)
            elif method == "POST":
                resp = requests.post(
                    url,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                    json=json,
                    data=data,
                )
            else:  # pragma: no cover - guard contra uso interno errado
                raise ValueError(f"Metodo HTTP nao suportado: {method}")
        except requests.RequestException as exc:
            # Falha de rede/timeout eh retentavel ate esgotar tentativas.
            logger.warning(
                "%s request falhou para %s (tentativa %d/%d): %s",
                method, url, attempt + 1, max_attempts, exc,
            )
            increment_api_call_counter()
            if attempt >= max_attempts - 1:
                return None
            _sleep(backoff_schedule[attempt], sleep_seconds)
            continue

        last_response = resp
        increment_api_call_counter()

        if resp.status_code < 400:
            return resp

        if resp.status_code not in retriable_status:
            # 4xx nao retentavel (exceto 429 ja coberto) — retorno imediato.
            return resp

        if attempt >= max_attempts - 1:
            logger.warning(
                "%s request esgotou retries para %s (status=%d)",
                method, url, resp.status_code,
            )
            return resp

        wait = _resolve_wait(resp, backoff_schedule[attempt])
        logger.info(
            "%s %s retornou %d (tentativa %d/%d), aguardando %.1fs",
            method, url, resp.status_code, attempt + 1, max_attempts, wait,
        )
        _sleep(wait, sleep_seconds)

    return last_response


def _resolve_wait(resp: requests.Response, default_wait: float) -> float:
    """Resolve tempo de espera, respeitando Retry-After quando presente."""
    retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
    if retry_after is not None:
        return retry_after
    return default_wait


def _sleep(plan: float, override: Optional[float]) -> None:
    """Sleep respeitando override (usado em testes)."""
    actual = plan if override is None else override
    if actual > 0:
        time.sleep(actual)


__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_BACKOFF_SCHEDULE",
    "DEFAULT_RETRIABLE_STATUS",
    "HttpRequestError",
    "http_get",
    "http_post",
]
