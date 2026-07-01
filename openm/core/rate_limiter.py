"""
Rate limiting helpers (issue #89).

Fornece:

- :func:`user_service_key` — key_func padrão: ``u<user_id>:<service_name>``
  com fallback para IP quando o user não está autenticado.
- :func:`admin_exempt` — usado como ``exempt_when`` para que admins
  não sejam bloqueados pelo rate limiter.
- :func:`rate_limit_per_user` — decorator helper para aplicar limite
  dinâmico baseado em ``g.service_name`` (resolvido dentro do handler).
- :func:`get_user_quota` — quota atual de um user para um service
  específico (lê do storage do limiter).
- :func:`register_rate_limit_handler` — registra o handler 429 que
  retorna JSON com ``{error, message, retry_after, limit}`` e
  ``Retry-After`` header, mais audit log best-effort.
- :func:`_extract_retry_after` — extrai ``int seconds`` de diferentes
  representações que o Flask-Limiter expõe.

A configuração do :class:`Limiter` (storage, strategy, headers) vive em
:mod:`openm.extensions`. Aqui ficam apenas os helpers de aplicação
(key_func, exempt, handler, quota).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Optional

from flask import Flask, g, jsonify, request
from flask_limiter.util import get_remote_address

from openm.core.audit import ACTION_RATE_LIMIT_EXCEEDED, log_action
from openm.extensions import limiter


_logger = logging.getLogger(__name__)


# Sentinel para o decorator. Usado para detectar "limite não declarado".
_LIMIT_NOT_SET = object()


def user_service_key() -> str:
    """
    ``key_func`` padrão do Limiter.

    Resolve a chave de rate limit para a request atual:

    - Se ``g.user`` está populado e ``g.service_name`` está definido,
      retorna ``f"u{user.id}:{service_name}"`` — isso isola o budget
      de cada user em cada service externo.
    - Se ``g.user`` está populado mas ``g.service_name`` ainda não foi
      resolvido (handler que não usa ``run_transform``), retorna
      ``f"u{user.id}:__global__"`` para que o limite default global
      ainda diferencie por user.
    - Caso o user NÃO esteja autenticado (ex: ``/api/auth/login``),
      cai no fallback de IP para que auth endpoints ainda sejam
      rate-limited por origem (defesa contra brute-force).
    """
    user = getattr(g, "user", None)
    if user is not None:
        user_id = getattr(user, "id", None)
        if user_id is not None:
            service_name = getattr(g, "service_name", None) or "__global__"
            return f"u{user_id}:{service_name}"
    # Fallback: IP. Funciona em endpoints sem auth (login, register)
    # e em qualquer ponto onde g.user não foi populado.
    return f"ip:{get_remote_address()}"


def admin_exempt() -> bool:
    """
    ``exempt_when`` para bypass de admins.

    Retorna True se o user atual for admin. Mais fino do que
    ``@limiter.exempt`` porque opera por request: cada rota com
    ``exempt_when=admin_exempt`` é contornada só para admins,
    mantendo o limite aplicado para analyst/viewer.
    """
    user = getattr(g, "user", None)
    if user is None:
        return False
    return getattr(user, "role", None) == "admin"


def rate_limit_per_user(
    service_name: str,
    limit: str | Callable[[], str],
) -> Callable:
    """
    Decorator helper que aplica um limite por-user/serviço.

    Args:
        service_name: nome do service (apenas para logs/metadata; o
            service_name real é resolvido em runtime a partir de
            ``g.service_name`` quando a key_func roda — o valor aqui
            é o default que aparece nos logs do 429).
        limit: string ``"N/period"`` ou callable que retorna essa
            string. Callable é avaliado em cada request, permitindo
            que o limite seja configurado por env var em runtime.

    Exemplo::

        @transforms_bp.route("/run_transform", methods=["POST"])
        @require_auth
        @require_role("admin", "analyst")
        @rate_limit_per_user("__internal__",
                             lambda: Config.RATELIMIT_SERVICES.get(
                                 getattr(g, "service_name", "__internal__"),
                                 Config.RATELIMIT_SERVICES["__internal__"],
                             ))
        def run_transform():
            ...

    Importante: a ``key_func`` e ``exempt_when`` são herdadas do
    Limiter global (``user_service_key`` + ``admin_exempt``). O
    service_name efetivo vem de ``g.service_name`` (set dentro do
    handler após ``TransformRegistry.get(...).service_name``).
    """
    def decorator(fn: Callable) -> Callable:
        # Aplica o limite. Se for callable, Flask-Limiter chama em cada
        # request via _eval_limits. Se for string, o limite é fixo.
        return limiter.limit(limit)(fn)

    # service_name é informativo (logs do decorator factory). Não é
    # usado para o limite porque o limite real é resolvido via
    # g.service_name em runtime.
    _ = service_name
    return decorator


# ---------------------------------------------------------------------------
# 429 handler
# ---------------------------------------------------------------------------

_RETRY_AFTER_INT = re.compile(r"^\d+$")


def _extract_retry_after(error: Any) -> int:
    """
    Tenta extrair ``retry_after`` (em segundos) de um erro do
    Flask-Limiter.

    O Flask-Limiter expõe ``RateLimitExceeded`` com atributos
    ``description`` (string como "10 per 1 hour") e ``limit`` (objeto
    ``RequestLimit`` com .reset_at e .limit). Como o reset real é
    determinado pelo ``strategy`` configurado (``moving-window``), o
    jeito mais robusto de obter um "tente em X segundos" é usar o
    header ``Retry-After`` que o próprio Limiter já setou na response
    (ou 60 como fallback conservador).
    """
    # 1) Tenta o header da response atual (Flask-Limiter popula).
    try:
        headers = list(request.environ.get("werkzeug.response", ()).headers)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001
        headers = []

    for h in headers:
        name = getattr(h, "key", "").lower() if hasattr(h, "key") else ""
        if name == "retry-after":
            value = getattr(h, "value", "") or ""
            if _RETRY_AFTER_INT.match(str(value).strip()):
                return int(str(value).strip())
            # Pode vir como data HTTP — não temos parser aqui, fallback.
            return 60

    # 2) Atributo do erro: alguns backends expõem reset_at como epoch.
    reset = getattr(error, "reset_at", None)
    if isinstance(reset, (int, float)):
        import time
        diff = int(reset) - int(time.time())
        return max(diff, 1)

    # 3) Fallback final.
    return 60


def _audit_rate_limit_exceeded(service: str, limit: str, retry_after: int) -> None:
    """Registra best-effort no audit log (não bloqueia a response)."""
    try:
        log_action(
            action=ACTION_RATE_LIMIT_EXCEEDED,
            target_type="rate_limit",
            target_id=service or "unknown",
            metadata={
                "service": service,
                "limit": limit,
                "retry_after": retry_after,
                "path": request.path,
                "method": request.method,
            },
        )
    except Exception as exc:  # noqa: BLE001
        _logger.warning("rate_limit_audit_failed service=%s err=%s", service, exc)


def register_rate_limit_handler(app: Flask) -> None:
    """
    Registra o handler de 429 no app.

    O handler:

    1. Extrai ``retry_after`` (em segundos) e o ``limit`` que foi
       violado.
    2. Grava um audit log best-effort (``ratelimit.exceeded``) com
       metadata incluindo service, limit, retry_after, path, method.
    3. Retorna JSON ``{error, message, retry_after, limit}`` com
       status 429 e header ``Retry-After``.
    """
    # Resolve ``g.service_name`` do request body ANTES do limiter
    # rodar. Esta before_request é registrada explicitamente ANTES
    # de ``limiter.init_app(app)`` (em app.py), para que rode antes
    # do ``_check_request_limit`` do Flask-Limiter. O hook só age em
    # ``/api/run_transform`` (POST com JSON) e usa
    # ``request.get_json(silent=True)``, que é cacheado pelo Flask
    # — view function pode chamar de novo sem erro.
    @app.before_request
    def _resolve_service_name():
        if request.method != "POST":
            return None
        # Evita o work para requests que não precisam de service_name
        # (ex: /api/auth/login). Endpoint path match é mais barato que
        # parsear JSON.
        if not request.path.endswith("/run_transform"):
            return None
        data = request.get_json(silent=True) or {}
        transform_name = data.get("transform_name")
        if not transform_name:
            return None
        # Import lazy para evitar ciclo: openm.core.rate_limiter
        # importa openm.core.transform indiretamente.
        from openm.core.transform import TransformRegistry

        transform_class = TransformRegistry.get(transform_name)
        if transform_class is None:
            return None
        g.service_name = (
            getattr(transform_class, "service_name", None) or "__internal__"
        )
        return None

    @app.errorhandler(429)
    def _handle_rate_limit_exceeded(error):  # noqa: ANN001
        # ``error.description`` é algo como "10 per 1 hour"; ``error.limit``
        # é o objeto RequestLimit.
        limit_repr: str = ""
        limit_obj = getattr(error, "limit", None)
        if limit_obj is not None:
            try:
                limit_repr = str(limit_obj.limit)  # ex: "10 per 1 hour"
            except Exception:  # noqa: BLE001
                limit_repr = str(error.description or "")

        # Identifica qual service foi o gatilho: o ``key_func`` inclui
        # o service_name como suffix, ex: "u42:shodan".
        service: str = "__global__"
        try:
            key = user_service_key()
            if ":" in key:
                service = key.split(":", 1)[1] or "__global__"
        except Exception:  # noqa: BLE001
            pass

        retry_after = _extract_retry_after(error)
        _audit_rate_limit_exceeded(service, limit_repr, retry_after)

        response = jsonify({
            "error": "rate_limit_exceeded",
            "message": (
                f"Limite de requisições excedido para o service '{service}'. "
                f"Tente novamente em {retry_after}s."
            ),
            "retry_after": retry_after,
            "limit": limit_repr,
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response


# ---------------------------------------------------------------------------
# Quota inspection
# ---------------------------------------------------------------------------

def _parse_limit_string(limit_str: str) -> tuple[int, str]:
    """
    Faz parse de ``"N/period"`` (formato Flask-Limiter) e retorna
    ``(N, period_canonical)``.

    Raises:
        ValueError: se o formato for inválido.
    """
    if not limit_str or "/" not in limit_str:
        raise ValueError(f"Invalid limit string: {limit_str!r}")
    n_str, period = limit_str.split("/", 1)
    n = int(n_str.strip())
    period = period.strip().lower()
    return n, period


def _period_to_seconds(period: str) -> int:
    """Converte ``hour/day/minute/second`` em segundos aproximados."""
    mapping = {
        "second": 1,
        "minute": 60,
        "hour": 3600,
        "day": 86400,
        "month": 30 * 86400,
        "year": 365 * 86400,
    }
    return mapping.get(period, 3600)


def get_user_quota(user_id: int, service: str) -> dict:
    """
    Retorna a quota atual de um user em um service.

    Lê o storage do limiter (in-memory em dev/test, Redis em prod) e
    retorna o estado atual. Se o user nunca fez request nesse
    service, ``used=0`` e ``remaining=limit``.

    Args:
        user_id: ID do user (PK em ``users.id``).
        service: nome do service (chave em ``Config.RATELIMIT_SERVICES``).

    Returns:
        Dict com ``name, limit, period, used, remaining, reset_at``.
    """
    from openm.config import Config

    limit_str = Config.RATELIMIT_SERVICES.get(service, "0/hour")
    try:
        limit_n, period = _parse_limit_string(limit_str)
    except ValueError:
        limit_n, period = 0, "hour"

    key = f"u{user_id}:{service}"

    # Tenta consultar o storage. Se o backend não suportar a operação
    # (alguns não implementam ``get``/``peek``), caímos em "0 used".
    used = 0
    reset_at: Optional[int] = None
    try:
        storage = limiter._storage  # type: ignore[attr-defined]
        # O storage expõe ``get`` em alguns backends (memory, redis).
        # Em memory backend, ``storage.get`` é seguro e retorna a lista
        # de timestamps no window; em outros backends pode ser None.
        window_key = f"LIMITER/{key}/{limit_str}"
        window_state = storage.get(window_key)  # type: ignore[attr-defined]
        if window_state is not None:
            # O storage retorna um objeto WindowStats (RateLimitItemPer*)
            # com .hits, .reset_time, etc. Em memory backend, é uma
            # lista de timestamps; tratamos ambos.
            hits = getattr(window_state, "hits", None)
            if isinstance(hits, int):
                used = hits
            elif isinstance(window_state, (list, tuple)):
                used = len(window_state)
            reset = getattr(window_state, "reset_time", None)
            if isinstance(reset, (int, float)):
                reset_at = int(reset)
    except Exception:  # noqa: BLE001
        # Backend sem suporte a peek — retorna zeros. Frontend mostra
        # "remaining=limit" como estado inicial conhecido.
        pass

    return {
        "name": service,
        "limit": limit_n,
        "period": period,
        "used": used,
        "remaining": max(limit_n - used, 0),
        "reset_at": reset_at,
    }


__all__ = [
    "user_service_key",
    "admin_exempt",
    "rate_limit_per_user",
    "get_user_quota",
    "register_rate_limit_handler",
    "_extract_retry_after",
    "_parse_limit_string",
]
