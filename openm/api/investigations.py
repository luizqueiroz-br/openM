"""
Investigations API v2 (issue #26).

Endpoints:
- POST   /api/investigations                 — criar
- GET    /api/investigations                 — listar com filtros (status, search, sort)
- GET    /api/investigations/<id>            — detalhe (inclui graph_snapshot)
- PUT    /api/investigations/<id>            — atualizar (titulo/desc/snapshot)
- POST   /api/investigations/<id>/archive    — arquivar
- POST   /api/investigations/<id>/unarchive  — desarquivar
- DELETE /api/investigations/<id>            — excluir (issue #35; hard delete)

Multi-user (issue #2): todos os endpoints filtram por user_id. Legacy
investigations (user_id=null) são visíveis para qualquer user logado.
"""

from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, ValidationError

from openm.core.auth import require_auth, require_role
from openm.core.audit import (
    log_action,
    ACTION_INVESTIGATION_CREATE,
    ACTION_INVESTIGATION_UPDATE,
    ACTION_INVESTIGATION_ARCHIVE,
    ACTION_INVESTIGATION_UNARCHIVE,
    ACTION_INVESTIGATION_DELETE,
)
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
@require_role("admin", "analyst")
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
    # Auditoria: criação de investigação. description pode ter PII — não
    # passamos no metadata; só tamanho como metadado opcional.
    log_action(
        action=ACTION_INVESTIGATION_CREATE,
        target_type="investigation",
        target_id=str(investigation.id),
        user_id=g.user.id,
        metadata={
            "title": investigation.title,
            "root_entity_id": investigation.root_entity_id,
        },
    )
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
@require_role("admin", "analyst")
def update_investigation(investigation_id: int):
    """
    PUT /api/investigations/<id> — atualização parcial.

    Optimistic locking (issue #37):
    - Header opcional ``If-Match: "<version>"`` ativa checagem de conflito
      (RFC 9110 — valor vem quoted com aspas duplas; servidor remove).
    - Sem header: comportamento legado (sem check; versão auto-incrementa).
    - Com header + version mismatch: 409 Conflict com ``current_snapshot``
      (frontend usa pra modal "Recarregar / Sobrescrever / Cancelar").

    Resposta 409:
        {
            "error": "conflict",
            "current_version": 3,
            "your_version": 2,
            "current_snapshot": {...}  # snapshot atual do servidor
        }

    Resposta 200 inclui ``investigation.version`` (incrementado).
    Archive/unarchive/delete NÃO mexem na versão — são idempotentes.
    """
    investigation = _owned_or_404(investigation_id)
    if investigation is None:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(silent=True) or {}
    try:
        payload = UpdateInvestigationPayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    # If-Match header (opcional). RFC 9110 § 13.1.1: valor vem quoted.
    # Aceitamos com e sem aspas pra ser lenient com clientes não-RFC.
    if_match_raw = request.headers.get("If-Match", "").strip().strip('"')
    expected_version: int | None = None
    if if_match_raw:
        try:
            expected_version = int(if_match_raw)
        except ValueError:
            return jsonify({
                "error": "If-Match header deve ser um número inteiro"
            }), 400

    # Validação mínima do graph_snapshot
    if payload.graph_snapshot is not None:
        if not isinstance(payload.graph_snapshot, dict):  # pragma: no cover
            return jsonify({"error": "graph_snapshot deve ser um objeto"}), 400
        if "nodes" not in payload.graph_snapshot or "edges" not in payload.graph_snapshot:
            return jsonify({
                "error": "graph_snapshot deve ter 'nodes' e 'edges'"
            }), 400

    # Detecta conflito via checagem da versão atual (pre-check).
    # O check atômico acontece depois no UPDATE.
    if expected_version is not None and investigation.version != expected_version:
        # 409 Conflict — não faz update, retorna snapshot do servidor.
        log_action(
            action=ACTION_INVESTIGATION_UPDATE,
            target_type="investigation",
            target_id=str(investigation.id),
            user_id=g.user.id,
            metadata={
                "conflict": True,
                "your_version": expected_version,
                "current_version": investigation.version,
            },
        )
        return jsonify({
            "error": "conflict",
            "current_version": investigation.version,
            "your_version": expected_version,
            "current_snapshot": investigation.graph_snapshot,
        }), 409

    # Aplica mudanças (sem If-Match ou com versão correta).
    changed_fields: list[str] = []
    if payload.title is not None and payload.title != investigation.title:
        changed_fields.append("title")
        investigation.title = payload.title
    if payload.description is not None and payload.description != investigation.description:
        changed_fields.append("description")
        investigation.description = payload.description

    snapshot_size_kb: int | None = None
    if payload.graph_snapshot is not None:
        changed_fields.append("graph_snapshot")
        investigation.graph_snapshot = payload.graph_snapshot
        investigation.last_auto_save_at = datetime.now(timezone.utc)
        try:
            snapshot_size_kb = round(
                len(str(payload.graph_snapshot).encode("utf-8")) / 1024, 2
            )
        except Exception:  # noqa: BLE001  # pragma: no cover
            snapshot_size_kb = None

    # Conditional UPDATE atômico: WHERE version = current
    # Garante que 2 PUTs simultâneos com mesma versão: 1 vence, outro
    # detecta rowcount=0 e retorna 409 (race condition).
    current_version = investigation.version
    new_version = current_version + 1
    update_values = {
        Investigation.version: new_version,
    }
    # Atualiza só os campos que vieram no payload (mantém valor atual).
    if payload.title is not None:
        update_values[Investigation.title] = investigation.title
    if payload.description is not None:
        update_values[Investigation.description] = investigation.description
    if payload.graph_snapshot is not None:
        update_values[Investigation.graph_snapshot] = investigation.graph_snapshot
        update_values[Investigation.last_auto_save_at] = investigation.last_auto_save_at

    rows_updated = (
        db.session.query(Investigation)
        .filter(
            Investigation.id == investigation_id,
            Investigation.version == current_version,
        )
        .update(update_values, synchronize_session=False)
    )

    if rows_updated == 0 and expected_version is not None:
        # Outra transação incrementou a versão entre nosso SELECT e UPDATE.
        # Recarrega e retorna 409.
        db.session.rollback()
        investigation = _owned_or_404(investigation_id)
        if investigation is None:
            return jsonify({"error": "not found"}), 404
        log_action(
            action=ACTION_INVESTIGATION_UPDATE,
            target_type="investigation",
            target_id=str(investigation.id),
            user_id=g.user.id,
            metadata={
                "conflict": True,
                "your_version": expected_version,
                "current_version": investigation.version,
                "race": True,
            },
        )
        return jsonify({
            "error": "conflict",
            "current_version": investigation.version,
            "your_version": expected_version,
            "current_snapshot": investigation.graph_snapshot,
        }), 409

    db.session.commit()

    # Atualiza objeto em memória para refletir a nova versão.
    investigation.version = new_version

    log_action(
        action=ACTION_INVESTIGATION_UPDATE,
        target_type="investigation",
        target_id=str(investigation_id),
        user_id=g.user.id,
        metadata={
            "changed_fields": changed_fields,
            "snapshot_size_kb": snapshot_size_kb,
            "version": new_version,
        },
    )

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
@require_role("admin", "analyst")
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
    log_action(
        action=ACTION_INVESTIGATION_ARCHIVE,
        target_type="investigation",
        target_id=str(investigation.id),
        user_id=g.user.id,
    )
    return jsonify({"investigation": investigation.to_dict()})


# ============ POST /api/investigations/<id>/unarchive ============

@investigations_bp.route("/investigations/<int:investigation_id>/unarchive", methods=["POST"])
@require_auth
@require_role("admin", "analyst")
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
    log_action(
        action=ACTION_INVESTIGATION_UNARCHIVE,
        target_type="investigation",
        target_id=str(investigation.id),
        user_id=g.user.id,
    )
    return jsonify({"investigation": investigation.to_dict()})


# ============ DELETE /api/investigations/<id> ============

@investigations_bp.route(
    "/investigations/<int:investigation_id>",
    methods=["DELETE"],
)
@require_auth
@require_role("admin", "analyst")
def delete_investigation(investigation_id: int):
    """
    DELETE /api/investigations/<id>

    Hard delete (issue #35): remove o registro da investigação
    permanentemente. Sem soft delete e sem migration.

    - Anti-enumeração cross-user: 404 (não 403) — reusa helper
      ``_owned_or_404`` (mesma convenção das outras rotas).
    - Legacy (user_id=null): qualquer analyst/admin pode deletar
      (consistente com a regra de leitura — legacy é visível para
      qualquer user logado).
    - Audit log é gravado ANTES do delete com snapshot do título e
      status_before_delete, para preservar contexto histórico mesmo
      após a remoção do registro.
    - Cascade Neo4j NÃO é aplicado — entidades no grafo permanecem
      (ownership no Neo4j é por user_id, não por investigation; ver
      issue #38). O frontend deve reagir ao 404 do AutoSave parando
      o loop e limpando o grafo.
    - Resposta: 204 No Content (sem body).
    """
    investigation = _owned_or_404(investigation_id)
    if investigation is None:
        return jsonify({"error": "not found"}), 404

    # Snapshot ANTES de deletar — o registro some logo abaixo.
    snapshot_meta = {
        "title": investigation.title,
        "status_before_delete": investigation.status,
    }

    db.session.delete(investigation)
    db.session.commit()

    log_action(
        action=ACTION_INVESTIGATION_DELETE,
        target_type="investigation",
        target_id=str(investigation_id),
        user_id=g.user.id,
        metadata=snapshot_meta,
    )

    return "", 204
