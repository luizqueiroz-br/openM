"""
Audit log API (issue #4): leitura do log para admins.

Endpoint:
- GET /api/audit-log    — lista eventos com filtros (admin only)

Filtros suportados (todos opcionais):
- user_id: int       — eventos do usuário específico
- action: str        — ação exata (ex.: "user.login.failed")
- target_type: str   — tipo do recurso (ex.: "user", "entity")
- since: ISO datetime — eventos a partir de (inclusive)
- until: ISO datetime — eventos até (exclusive)
- limit: int (1..500, default 100)
- offset: int (default 0)

Acesso restrito a ``admin`` (não a ``analyst``). O log pode conter
informações sensíveis de auditoria que analistas não devem ver.
"""

from __future__ import annotations

from datetime import datetime

from flask import Blueprint, jsonify, request
from sqlalchemy import and_

from openm.core.auth import require_auth, require_role
from openm.models.audit_log import AuditLog


audit_bp = Blueprint("audit", __name__, url_prefix="/api")

# Whitelist de campos ordenáveis (anti-SQLi via order_by).
_SORTABLE_FIELDS = {"created_at", "action"}

# Limites de paginação. Cap superior evita DOS via ?limit=999999.
DEFAULT_LIMIT = 100
MAX_LIMIT = 500


# ===================== Helpers =====================

def _parse_int(name: str, raw: str | None, *, minimum: int, maximum: int | None = None) -> int | None:
    """Converte query param para int validado. Retorna None se ausente."""
    if raw is None or raw == "":
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        # Tratamos como ausente em vez de 400 — facilita filtros opcionais.
        return None
    if value < minimum:
        return None
    if maximum is not None and value > maximum:
        return None
    return value


def _parse_datetime(name: str, raw: str | None) -> datetime | None:
    """
    Parseia ISO 8601. Aceita com/sem 'Z'.

    Retorna naive datetime (sem tzinfo) — casando com o storage do
    SQLAlchemy/SQLite, que descarta tzinfo ao gravar DateTime.

    Por que essa normalização: o ``default`` da coluna ``created_at``
    é ``datetime.now(timezone.utc)``, mas em SQLite o roundtrip perde
    o tzinfo. Se filtrássemos com tz-aware e a coluna viesse naive, a
    comparação daria errado silenciosamente (SQLite compara naive vs
    naive, ignorando o tz do filtro). Normalizar ambos os lados pra
    naive elimina essa divergência cross-backend (Postgres vs SQLite).

    Em produção (Postgres), o driver devolve tz-aware via TIMESTAMPTZ,
    e a comparação ainda funciona porque o filtro naive é convertido
    implicitamente. Para evitar essa armadilha em produção, podemos
    promover o filtro a tz-aware — mas a perda do tz em SQLite nos
    testes é o pior cenário, então ficamos com naive.

    Erros de parsing viram None (em vez de 400) para casar com a
    tolerância de _parse_int — filtros malformados simplesmente
    não aplicam, em vez de quebrar a listagem.
    """
    if not raw:
        return None
    try:
        # Python 3.11+ aceita 'Z' direto; em 3.10 normalizamos manualmente.
        normalized = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
        dt = datetime.fromisoformat(normalized)
    except (TypeError, ValueError):
        return None
    # Remove tzinfo para casar com o storage (ver docstring).
    return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


# ===================== GET /api/audit-log =====================

@audit_bp.route("/audit-log", methods=["GET"])
@require_auth
@require_role("admin")
def list_audit_log():
    """
    GET /api/audit-log[?user_id=&action=&target_type=&since=&until=&limit=&offset=]

    Lista eventos do log do mais novo para o mais antigo.
    """
    q = AuditLog.query

    # ---- filtros ----
    user_id = _parse_int("user_id", request.args.get("user_id"), minimum=1)
    if user_id is not None:
        q = q.filter(AuditLog.user_id == user_id)

    action = request.args.get("action")
    if action:
        # Match exato — actions são dotted strings, sem LIKE.
        q = q.filter(AuditLog.action == action)

    target_type = request.args.get("target_type")
    if target_type:
        q = q.filter(AuditLog.target_type == target_type)

    since = _parse_datetime("since", request.args.get("since"))
    if since is not None:
        q = q.filter(AuditLog.created_at >= since)

    until = _parse_datetime("until", request.args.get("until"))
    if until is not None:
        q = q.filter(AuditLog.created_at < until)

    # ---- ordenação ----
    sort = request.args.get("sort", "-created_at")
    desc = sort.startswith("-")
    field = sort.lstrip("-")
    if field not in _SORTABLE_FIELDS:
        return jsonify({
            "error": f"sort deve ser um de {sorted(_SORTABLE_FIELDS)} (com '-' pra desc)"
        }), 400
    sort_col = getattr(AuditLog, field)
    q = q.order_by(sort_col.desc() if desc else sort_col.asc())

    # ---- paginação ----
    limit = _parse_int(
        "limit", request.args.get("limit"),
        minimum=1, maximum=MAX_LIMIT,
    )
    if limit is None:
        # Quando o parâmetro veio inválido, voltamos ao default silenciosamente
        # (mesma estratégia dos outros filtros). Para diferenciar "não passou"
        # vs "passou inválido", só importaria se quiséssemos 400.
        limit = DEFAULT_LIMIT

    offset = _parse_int(
        "offset", request.args.get("offset"),
        minimum=0,
    )
    if offset is None:
        offset = 0

    # Total ANTES de aplicar limit/offset — útil para a UI mostrar
    # "página X de Y".
    total = q.count()

    items = q.limit(limit).offset(offset).all()

    return jsonify({
        "events": [e.to_dict() for e in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


__all__ = ["audit_bp"]