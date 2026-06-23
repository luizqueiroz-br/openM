"""
Investigations API v2 (issue #26).

Endpoints:
- POST   /api/investigations              — criar
- GET    /api/investigations              — listar com filtros (status, search, sort)
- GET    /api/investigations/<id>         — detalhe (inclui graph_snapshot)
- PUT    /api/investigations/<id>         — atualizar (titulo/desc/snapshot)
- POST   /api/investigations/<id>/archive   — arquivar
- POST   /api/investigations/<id>/unarchive — desarquivar

Multi-user (issue #2): todos os endpoints filtram por user_id. Legacy
investigations (user_id=null) são visíveis para qualquer user logado.
"""

from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, ValidationError

from openm.core.auth import require_auth
from openm.extensions import db
from openm.models.investigation import Investigation

investigations_bp = Blueprint("investigations", __name__, url_prefix="/api")


# ============ Payloads ============

class CreateInvestigationPayload(BaseModel):
    title: str
    description: str | None = None
    root_entity_id: str | None = None


class UpdateInvestigationPayload(BaseModel):
    """PUT payload — todos os campos opcionais (parcial)."""
    title: str | None = None
    description: str | None = None
    graph_snapshot: dict[str, Any] | None = None
    # Espera-se { nodes: [...], edges: [...] } — Cytoscape normalizado
    # Não validamos a estrutura interna aqui (schema é responsabilidade
    # do frontend). Apenas garantimos que é um dict.


# ============ Helpers ============

def _owned_or_404(investigation_id: int) -> Investigation | None:
    """
    Retorna a investigation se ela existir E for do user autenticado
    (ou for legacy user_id=null). Senão, None (vira 404).

    Mantém anti-enumeração: 404 cross-user, não 403.
    """
    return (
        Investigation.query
        .filter(
            Investigation.id == investigation_id,
            (Investigation.user_id == g.user.id) | (Investigation.user_id.is_(None)),
        )
        .first()
    )


def _save_investigation(inv: Investigation) -> None:
    db.session.add(inv)
    db.session.commit()


# ============ POST /api/investigations ============

@investigations_bp.route("/investigations", methods=["POST"])
@require_auth
def create_investigation():
    """
    POST /api/investigations

    Cria uma nova investigação no PostgreSQL, vinculada ao usuário
    autenticado (issue #2). Status inicial: 'active' (issue #25).
    """
    data = request.get_json(silent=True) or {}
    try:
        payload = CreateInvestigationPayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    investigation = Investigation(
        title=payload.title,
        description=payload.description,
        root_entity_id=payload.root_entity_id,
        user_id=g.user.id,
    )
    _save_investigation(investigation)
    return jsonify({"investigation": investigation.to_dict()}), 201


# ============ GET /api/investigations ============

# Campos válidos para ordenação (whitelist — evita SQL injection via order_by)
_SORTABLE_FIELDS = {
    "created_at", "updated_at", "title",
}


@investigations_bp.route("/investigations", methods=["GET"])
@require_auth
def list_investigations():
    """
    GET /api/investigations?status=active&search=foo&sort=-updated_at

    Filtros (issue #26):
    - status: 'active' (default) | 'archived' | 'all'
    - search: LIKE case-insensitive em title
    - sort: created_at | updated_at | title  (prefix '-' = desc; default -updated_at)

    Multi-user (issue #2): sempre filtra por user_id do autenticado
    + legacy (user_id=null) visíveis pra todos.
    """
    # ---- status ----
    status = request.args.get("status", "active").lower()
    if status not in ("active", "archived", "all"):
        return jsonify({"error": "status deve ser 'active', 'archived' ou 'all'"}), 400

    # ---- search ----
    search = (request.args.get("search") or "").strip()

    # ---- sort ----
    sort = request.args.get("sort", "-updated_at")
    desc = sort.startswith("-")
    field = sort.lstrip("-")
    if field not in _SORTABLE_FIELDS:
        return jsonify({
            "error": f"sort deve ser um de {sorted(_SORTABLE_FIELDS)} (com '-' pra desc)"
        }), 400
    sort_col = getattr(Investigation, field)
    order_expr = sort_col.desc() if desc else sort_col.asc()

    # ---- query base ----
    q = Investigation.query.filter(
        (Investigation.user_id == g.user.id) | (Investigation.user_id.is_(None))
    )
    if status != "all":
        q = q.filter(Investigation.status == status)
    if search:
        like = f"%{search}%"
        q = q.filter(Investigation.title.ilike(like))
    q = q.order_by(order_expr)

    investigations = q.all()
    return jsonify({"investigations": [inv.to_dict() for inv in investigations]})


# ============ GET /api/investigations/<id> ============

@investigations_bp.route("/investigations/<int:investigation_id>", methods=["GET"])
@require_auth
def get_investigation(investigation_id: int):
    """
    GET /api/investigations/<id>

    Retorna detalhes de uma investigação (inclui graph_snapshot).
    404 cross-user (anti-enumeração, issue #2).
    """
    investigation = _owned_or_404(investigation_id)
    if investigation is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"investigation": investigation.to_dict()})


# ============ PUT /api/investigations/<id> ============

@investigations_bp.route("/investigations/<int:investigation_id>", methods=["PUT"])
@require_auth
def update_investigation(investigation_id: int):
    """
    PUT /api/investigations/<id>

    Atualização parcial. Campos aceitos: title, description, graph_snapshot.
    Quando graph_snapshot é enviado, last_auto_save_at é setado (auto-save).

    Resposta inclui 'saved_at' (timestamp do save) pra o frontend mostrar
    "Salvo às HH:MM" no indicador visual.
    """
    investigation = _owned_or_404(investigation_id)
    if investigation is None:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(silent=True) or {}
    try:
        payload = UpdateInvestigationPayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    # Validação mínima do graph_snapshot
    if payload.graph_snapshot is not None:
        if not isinstance(payload.graph_snapshot, dict):
            return jsonify({"error": "graph_snapshot deve ser um objeto"}), 400
        if "nodes" not in payload.graph_snapshot or "edges" not in payload.graph_snapshot:
            return jsonify({
                "error": "graph_snapshot deve ter 'nodes' e 'edges'"
            }), 400

    # Aplica mudanças (só as enviadas)
    if payload.title is not None:
        investigation.title = payload.title
    if payload.description is not None:
        investigation.description = payload.description

    if payload.graph_snapshot is not None:
        investigation.graph_snapshot = payload.graph_snapshot
        # Auto-save: registra o momento
        investigation.last_auto_save_at = datetime.now(timezone.utc)

    _save_investigation(investigation)

    return jsonify({
        "investigation": investigation.to_dict(),
        "saved_at": (
            investigation.last_auto_save_at.isoformat()
            if investigation.last_auto_save_at
            else None
        ),
    })


# ============ POST /api/investigations/<id>/archive ============

@investigations_bp.route("/investigations/<int:investigation_id>/archive", methods=["POST"])
@require_auth
def archive_investigation(investigation_id: int):
    """
    POST /api/investigations/<id>/archive

    Marca a investigação como arquivada (status=archived, archived_at=now).
    Idempotente: se já estiver arquivada, só atualiza o timestamp.
    """
    investigation = _owned_or_404(investigation_id)
    if investigation is None:
        return jsonify({"error": "not found"}), 404

    investigation.archive()
    _save_investigation(investigation)
    return jsonify({"investigation": investigation.to_dict()})


# ============ POST /api/investigations/<id>/unarchive ============

@investigations_bp.route("/investigations/<int:investigation_id>/unarchive", methods=["POST"])
@require_auth
def unarchive_investigation(investigation_id: int):
    """
    POST /api/investigations/<id>/unarchive

    Restaura a investigação para o estado ativo (status=active,
    archived_at=null). Idempotente.
    """
    investigation = _owned_or_404(investigation_id)
    if investigation is None:
        return jsonify({"error": "not found"}), 404

    investigation.unarchive()
    _save_investigation(investigation)
    return jsonify({"investigation": investigation.to_dict()})
