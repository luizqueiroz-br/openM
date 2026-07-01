"""
Helper de auditoria (issue #4): ``log_action``.

Função pública:
    log_action(action, target_type=None, target_id=None, metadata=None,
               user_id=None, ip_address=None, *, db_session=None)

O objetivo é oferecer uma única porta de entrada para registrar ações
sensíveis, garantindo:

1. **Sanitização do metadata**: campos sensíveis (senhas, tokens, chaves)
   são removidos ANTES de chegar ao banco. Mesmo que um caller passe um
   payload contendo ``{"password": "..."}``, ele nunca será gravado.
2. **Captura automática de IP e user**: se ``ip_address``/``user_id`` não
   forem passados, o helper tenta extrair de ``request`` / ``g``.
3. **Tolerância a falhas**: erros de gravação viram warning no logger
   mas NÃO quebram a request principal. Auditoria é best-effort — uma
   falha de DB não pode impedir um login legítimo.
4. **Idempotência não-garantida**: a função registra cada chamada. Se o
   caller precisa de idempotência, deduplica antes.

O helper **não** deve importar ``openm.models.audit_log`` em carga de
módulo para evitar import circular quando usado em ``openm.cli``. O
import é feito lazy dentro da função.
"""

from __future__ import annotations

import logging
from typing import Any

from flask import current_app, g, has_app_context, has_request_context, request

from openm.extensions import db as _default_db


_logger = logging.getLogger(__name__)


# Campos sensíveis que NUNCA devem aparecer em ``metadata``.
# Comparação case-insensitive contra o nome da chave (não do valor).
# Cobre os casos mais comuns em JSON payloads da nossa API:
#   password / senha / pwd
#   tokens (access, refresh, jti, csrf)
#   API keys
#   secret / signature / hash de senha
_SENSITIVE_KEYS: frozenset[str] = frozenset({
    # Senhas
    "password",
    "passwd",
    "pwd",
    "senha",
    "pass",
    # Tokens
    "token",
    "access_token",
    "refresh_token",
    "jwt",
    "jti",
    "csrf",
    "csrf_token",
    # API keys
    "api_key",
    "apikey",
    "key_value",  # ApiKey.key_value é o segredo real
    # Segredos genéricos
    "secret",
    "signature",
    "password_hash",
})


def _sanitize(value: Any, *, _depth: int = 0) -> Any:
    """
    Remove recursivamente chaves sensíveis de dicts/lists.

    Limite de profundidade para evitar ciclos infinitos em estruturas
    patológicas (ex.: ``self-referencing dicts``). Limite de 10 níveis
    cobre qualquer JSON real.
    """
    if _depth > 10:
        return None  # truncar silenciosamente

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS:
                # Substitui por marcador explícito para deixar rastro
                # do que foi removido (sem vazar o valor).
                out[k] = "[REDACTED]"
                continue
            out[k] = _sanitize(v, _depth=_depth + 1)
        return out

    if isinstance(value, list):
        return [_sanitize(item, _depth=_depth + 1) for item in value]

    # Primitivos (str, int, float, bool, None) passam intactos.
    return value


def _resolve_user_id(explicit: int | None) -> int | None:
    """Resolve o user_id a partir de (em ordem): parâmetro, g.user, None."""
    if explicit is not None:
        return explicit
    if has_app_context() and hasattr(g, "user"):
        return getattr(g.user, "id", None)
    return None


def _resolve_ip_address(explicit: str | None) -> str | None:
    """
    Resolve o IP de origem a partir de (em ordem):
    1. parâmetro explícito
    2. header ``X-Forwarded-For`` (primeiro IP da lista) — quando atrás de proxy
    3. ``request.remote_addr``
    """
    if explicit:
        return explicit[:45]  # truncar para o tamanho da coluna
    if not has_request_context():
        return None
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        # X-Forwarded-For pode ter lista "client, proxy1, proxy2".
        # O primeiro é o IP original do cliente.
        first = fwd.split(",", 1)[0].strip()
        if first:
            return first[:45]
    return (request.remote_addr or None)


def log_action(
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    *,
    user_id: int | None = None,
    ip_address: str | None = None,
    db_session=None,
) -> bool:
    """
    Registra um evento de auditoria.

    Parâmetros:
        action: nome da ação em dotted notation (ex.: ``"user.login.success"``).
        target_type: tipo do recurso afetado (``"user"``, ``"entity"``...).
        target_id: ID do recurso (string ou int convertido para str).
        metadata: dict livre. Campos sensíveis são removidos automaticamente.
        user_id: ID do ator. Se None, usa ``g.user.id`` (request context).
        ip_address: IP de origem. Se None, deduz de X-Forwarded-For/remote_addr.
        db_session: sessão SQLAlchemy alternativa (para testes). Padrão: ``db.session``.

    Retorna:
        True se gravou com sucesso, False se houve falha (best-effort).
    """
    try:
        # Import lazy pra evitar ciclo: openm.models importa openm.extensions,
        # e openm.core.audit pode ser importado cedo em outros módulos.
        from openm.models.audit_log import AuditLog

        session = db_session if db_session is not None else _default_db.session

        # Sanitização: cópia rasa não basta porque dicts aninhados podem
        # ter chaves sensíveis. _sanitize recria a estrutura.
        safe_meta = _sanitize(metadata) if metadata else None

        entry = AuditLog(
            user_id=_resolve_user_id(user_id),
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            meta=safe_meta,
            ip_address=_resolve_ip_address(ip_address),
        )
        session.add(entry)
        session.commit()
        return True

    except Exception:  # noqa: BLE001
        # Best-effort: rollback se possível, mas NÃO quebra a request.
        try:
            session = db_session if db_session is not None else _default_db.session
            session.rollback()
        except Exception:  # noqa: BLE001, S110
            pass

        # Log estruturado — caller pode ver que algo falhou sem detalhes
        # sensíveis (action passada como kwarg, não format string).
        try:
            if has_app_context():
                current_app.logger.warning(
                    "audit_log_failure action=%s error=db", action
                )
            else:
                _logger.warning("audit_log_failure action=%s error=db", action)
        except Exception:  # noqa: BLE001, S110  # pragma: no cover
            # Se nem o logger funciona, desiste silenciosamente. Caminho
            # defensivo — em prática o logger do Python sempre funciona.
            pass

        return False


# Conveniências para reduzir boilerplate nos endpoints -----------------------

# Catálogo de actions usadas pela aplicação. Centralizar aqui evita typos
# (e.g. ``"user.login.sucess"`` vs ``"user.login.success"``) e facilita
# refactor futuro (e.g. adicionar prefixo ``openm.``). NÃO é exhaustive —
# callers podem passar qualquer string, mas o uso destas constantes é
# preferível.

# Auth
ACTION_LOGIN_SUCCESS = "user.login.success"
ACTION_LOGIN_FAILED = "user.login.failed"
ACTION_LOGOUT = "user.logout"
ACTION_REGISTER = "user.register"

# Admin
ACTION_USER_ROLE_CHANGE = "user.role.change"
ACTION_USER_ACTIVE_CHANGE = "user.active.change"

# Entities
ACTION_ENTITY_CREATE = "entity.create"
ACTION_ENTITY_UPDATE = "entity.update"
ACTION_ENTITY_DELETE = "entity.delete"

# Transforms
ACTION_TRANSFORM_RUN = "transform.run"
# Issue #87: batch transform execution — uma entry por batch (não
# uma por entity). Metadata inclui batch_size, success_count,
# error_count, cache_hit_count, total_api_calls, duration_ms, status.
ACTION_TRANSFORM_BATCH_RUN = "transform.batch_run"
# Issue #81: pipeline/chain de transforms — uma entry consolidada
# por chain (não uma por hop). Metadata inclui
# chain_max_depth, total_hops, hops: [{depth, transform, input_id,
# output_ids, duration_ms, status, cache, error_message?}],
# truncated (bool), truncated_reason.
ACTION_TRANSFORM_CHAIN_RUN = "transform.chain_run"

# Investigations
ACTION_INVESTIGATION_CREATE = "investigation.create"
ACTION_INVESTIGATION_UPDATE = "investigation.update"
ACTION_INVESTIGATION_ARCHIVE = "investigation.archive"
ACTION_INVESTIGATION_UNARCHIVE = "investigation.unarchive"
ACTION_INVESTIGATION_DELETE = "investigation.delete"

# API Keys
ACTION_APIKEY_CREATE = "apikey.create"
ACTION_APIKEY_UPDATE = "apikey.update"
ACTION_APIKEY_DELETE = "apikey.delete"

# Rate limiting (issue #89)
ACTION_RATE_LIMIT_EXCEEDED = "ratelimit.exceeded"

# Graph edges
ACTION_EDGE_CREATE = "edge.create"
ACTION_EDGE_DELETE = "edge.delete"


__all__ = [
    "log_action",
    "ACTION_LOGIN_SUCCESS",
    "ACTION_LOGIN_FAILED",
    "ACTION_LOGOUT",
    "ACTION_REGISTER",
    "ACTION_USER_ROLE_CHANGE",
    "ACTION_USER_ACTIVE_CHANGE",
    "ACTION_ENTITY_CREATE",
    "ACTION_ENTITY_UPDATE",
    "ACTION_ENTITY_DELETE",
    "ACTION_TRANSFORM_RUN",
    "ACTION_TRANSFORM_BATCH_RUN",
    "ACTION_TRANSFORM_CHAIN_RUN",
    "ACTION_INVESTIGATION_CREATE",
    "ACTION_INVESTIGATION_UPDATE",
    "ACTION_INVESTIGATION_ARCHIVE",
    "ACTION_INVESTIGATION_UNARCHIVE",
    "ACTION_INVESTIGATION_DELETE",
    "ACTION_APIKEY_CREATE",
    "ACTION_APIKEY_UPDATE",
    "ACTION_APIKEY_DELETE",
    "ACTION_RATE_LIMIT_EXCEEDED",
    "ACTION_EDGE_CREATE",
    "ACTION_EDGE_DELETE",
]
