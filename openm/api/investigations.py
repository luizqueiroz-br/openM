from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, ValidationError

from openm.core.auth import require_auth
from openm.extensions import db
from openm.models.investigation import Investigation

investigations_bp = Blueprint("investigations", __name__, url_prefix="/api")


class CreateInvestigationPayload(BaseModel):
    title: str
    description: str | None = None
    root_entity_id: str | None = None


@investigations_bp.route("/investigations", methods=["POST"])
@require_auth
def create_investigation():
    """
    POST /api/investigations

    Cria uma nova investigação no PostgreSQL, vinculada ao usuário
    autenticado (issue #2 — multi-user).
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
    db.session.add(investigation)
    db.session.commit()
    return jsonify({"investigation": investigation.to_dict()}), 201


@investigations_bp.route("/investigations", methods=["GET"])
@require_auth
def list_investigations():
    """
    GET /api/investigations

    Lista apenas as investigações do usuário autenticado (issue #2).
    Investigations legadas (user_id=null) ficam visíveis pra todos os
    users logados — pra não quebrar dados antigos.
    """
    investigations = (
        Investigation.query
        .filter(
            (Investigation.user_id == g.user.id) | (Investigation.user_id.is_(None))
        )
        .order_by(Investigation.created_at.desc())
        .all()
    )
    return jsonify({"investigations": [inv.to_dict() for inv in investigations]})


@investigations_bp.route("/investigations/<int:investigation_id>", methods=["GET"])
@require_auth
def get_investigation(investigation_id: int):
    """
    GET /api/investigations/<id>

    Retorna detalhes de uma investigação. **Só do dono** — retorna 404
    (não 403, anti-enumeração) se não pertence ao usuário autenticado.
    Investigations legadas (user_id=null) são visíveis pra qualquer user
    logado.
    """
    investigation = (
        Investigation.query
        .filter(
            Investigation.id == investigation_id,
            (Investigation.user_id == g.user.id) | (Investigation.user_id.is_(None)),
        )
        .first()
    )
    if investigation is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"investigation": investigation.to_dict()})
