"""
Sightings endpoint (issue #129 — Inspector 3-tabs + Timeline).

Endpoint:
- GET /api/sightings — lista eventos (sightings) de uma entidade para a
  Timeline do Inspector 3-tabs.

Reaproveita a tabela ``audit_log`` existente (não há modelo ``Sighting``
próprio). A diferença em relação a ``/api/audit-log`` (issue #4) é:

- ``/api/audit-log`` é **admin-only** e expõe o log inteiro (auditoria
  forense, pode conter IP, ações sensíveis de outros usuários, etc.).
- ``/api/sightings`` é voltado para a Timeline de um investigador —
  acessível a ``admin`` e ``analyst`` (não ``viewer``) e filtra
  exclusivamente por ``target_type='entity'`` + ``target_id=<id>``.

Filtros suportados (todos via query string):
- ``entity_id`` (obrigatório): ID da entidade (string).
- ``category`` (opcional, default ``all``): um de
  ``all`` | ``transforms`` | ``edits`` | ``manual``.
- ``limit`` (opcional, 1..500, default 50): número máximo de eventos.

Resposta (200): JSON com ``sightings``, ``count``, ``entity_id``,
``category``. Cada sighting tem shape otimizado para a UI (tipo,
título, subtítulo) — não devolve o ``ip_address`` nem o payload bruto
de ``metadata``.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from openm.core.auth import require_auth, require_role
from openm.extensions import db
from openm.models.audit_log import AuditLog
from openm.models.user import User


sightings_bp = Blueprint("sightings", __name__, url_prefix="/api")

# Limites de paginação. Cap superior evita DOS via ?limit=999999.
DEFAULT_LIMIT = 50
MAX_LIMIT = 500


# ===================== Helpers =====================

def _parse_int(raw, default, min_v=None, max_v=None):
    """Converte query param para int validado.

    Reaproveitado de ``openm.api.audit._parse_int``: em vez de importar
    o helper (que tem semântica levemente diferente — retorna ``None``
    quando inválido), definimos uma versão local que casa com a
    necessidade de ``limit`` (sempre um int, com default explícito).
    """
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return default
    if min_v is not None and n < min_v:
        return min_v
    if max_v is not None and n > max_v:
        return max_v
    return n


# ===================== Categoria → actions =====================
#
# O AuditLog não tem flag ``is_transform_triggered``. Para distinguir
# "edição manual" de "edição disparada por transform", usamos a
# heurística: evento ``entity.*`` cuja ``meta.transform_name`` está
# vazia é considerado manual. Isso casa com a forma como
# ``openm.core.transform`` registra a auditoria (preenche
# ``transform_name``) vs como ``openm.api.entities`` registra
# edições manuais.
#
# Manter o mapping centralizado aqui facilita ajustar a lista de
# actions se uma nova for introduzida no helper ``openm.core.audit``.

CATEGORY_ACTIONS = {
    "all": None,  # sem filtro adicional por action
    "transforms": ["transform.run"],
    "edits": ["entity.create", "entity.update", "entity.delete"],
    # "manual" usa o mesmo set de actions; o filtro fino é aplicado
    # em Python (heurística sobre ``meta.transform_name``) porque o
    # evento entity.* pode ter sido disparado por transform OU pelo
    # usuário via UI.
    "manual": ["entity.create", "entity.update", "entity.delete"],
}


# ===================== GET /api/sightings =====================

@sightings_bp.route("/sightings", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def list_sightings():
    """
    GET /api/sightings?entity_id=<id>&category=<all|transforms|edits|manual>&limit=<n>

    Lista eventos de auditoria de uma entidade (Timeline do Inspector).
    Acessível a ``admin`` e ``analyst`` (não a ``viewer``).
    """
    entity_id = (request.args.get("entity_id") or "").strip()
    if not entity_id:
        return jsonify({"error": "entity_id é obrigatório"}), 400

    category = (request.args.get("category") or "all").strip().lower()
    if category not in CATEGORY_ACTIONS:
        return jsonify({
            "error": f"category inválida: {category!r}",
            "allowed": sorted(k for k in CATEGORY_ACTIONS if k),
        }), 400

    limit = _parse_int(
        request.args.get("limit"),
        default=DEFAULT_LIMIT,
        min_v=1,
        max_v=MAX_LIMIT,
    )

    # ---- query base ----
    query = AuditLog.query.filter(
        AuditLog.target_type == "entity",
        AuditLog.target_id == entity_id,
    )

    # ---- filtro de categoria ----
    if category in ("transforms", "edits", "manual"):
        # "edits" e "manual" compartilham o mesmo IN; a distinção fina
        # para "manual" (sem transform_name em meta) é feita em Python
        # depois do fetch para não acoplar a query ao shape do JSON.
        query = query.filter(AuditLog.action.in_(CATEGORY_ACTIONS[category]))

    # ---- ordenação + limite ----
    rows = (
        query.order_by(AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )

    # ---- filtro adicional de "manual" (heurística) ----
    if category == "manual":
        rows = [r for r in rows if not (r.meta or {}).get("transform_name")]

    # ---- serialização para a UI ----
    sightings = [_serialize_sighting(r) for r in rows]

    return jsonify({
        "sightings": sightings,
        "count": len(sightings),
        "entity_id": entity_id,
        "category": category,
    })


def _serialize_sighting(row: AuditLog) -> dict:
    """Converte um AuditLog em shape amigável para a Timeline do Inspector.

    O JSON retornado NÃO inclui ``ip_address`` (auditoria forense) nem o
    payload bruto de ``metadata`` (pode conter dados sensíveis). Apenas
    campos explicitamente aprovados são repassados.
    """
    meta = row.meta or {}

    # Actor — resolvido fora do loop principal (N+1) via cache local
    # dentro do request. Para volumes pequenos (<=500) o custo é
    # aceitável; se virar gargalo, fazer ``selectinload`` em uma
    # próxima iteração.
    actor = _resolve_actor(row.user_id)

    event_type = _event_type(row.action)
    title, subtitle = _title_subtitle(event_type, meta)

    return {
        "id": row.id,
        "type": event_type,
        "title": title,
        "subtitle": subtitle,
        "action": row.action,
        "actor": actor,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "metadata": {
            "transform_name": meta.get("transform_name"),
            "duration_ms": meta.get("duration_ms"),
            "new_entities_count": meta.get("new_entities_count"),
            "new_relationships_count": meta.get("new_relationships_count"),
            "status": meta.get("status"),
            "property_keys": meta.get("property_keys"),
            "error_message": meta.get("error_message"),
        },
    }


def _resolve_actor(user_id):
    """Resolve ``actor`` a partir de ``user_id``. Retorna dict ou None."""
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if not user:
        return None
    return {"id": user.id, "email": user.email, "role": user.role}


def _event_type(action: str) -> str:
    """Mapeia ``action`` do AuditLog para um ``type`` curto da UI."""
    if action == "transform.run":
        return "transform"
    if action == "entity.create":
        return "create"
    if action == "entity.update":
        return "update"
    if action == "entity.delete":
        return "delete"
    return "other"


def _title_subtitle(event_type: str, meta: dict) -> tuple[str, str]:
    """Gera ``(title, subtitle)`` a partir do tipo de evento + meta."""
    if event_type == "transform":
        title = meta.get("transform_name") or "Transform"
        subtitle = meta.get("transform_display_name") or title
        return title, subtitle

    if event_type in ("create", "update"):
        prop_keys = meta.get("property_keys") or []
        if prop_keys:
            base = "Criado" if event_type == "create" else "Atualizado"
            visible = ", ".join(str(k) for k in prop_keys[:3])
            if len(prop_keys) > 3:
                visible += f" (+{len(prop_keys) - 3})"
            return base, visible
        return ("Criado" if event_type == "create" else "Atualizado"), ""

    if event_type == "delete":
        return "Removido", ""

    # Fallback para actions não mapeadas — nunca acontece com o
    # conjunto atual de CATEGORY_ACTIONS, mas é defensivo.
    return event_type, ""


__all__ = ["sightings_bp"]
