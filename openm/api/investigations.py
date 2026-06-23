from flask import Blueprint, jsonify, request
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

    Cria uma nova investigação no PostgreSQL.
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
    )
    db.session.add(investigation)
    db.session.commit()
    return jsonify({"investigation": investigation.to_dict()}), 201


@investigations_bp.route("/investigations", methods=["GET"])
@require_auth
def list_investigations():
    """
    GET /api/investigations

    Lista todas as investigações cadastradas.
    """
    investigations = Investigation.query.order_by(Investigation.created_at.desc()).all()
    return jsonify({"investigations": [inv.to_dict() for inv in investigations]})


@investigations_bp.route("/investigations/<int:investigation_id>", methods=["GET"])
@require_auth
def get_investigation(investigation_id: int):
    """
    GET /api/investigations/<id>

    Retorna detalhes de uma investigação específica.
    """
    investigation = Investigation.query.get_or_404(investigation_id)
    return jsonify({"investigation": investigation.to_dict()})
