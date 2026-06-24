from flask import Blueprint, jsonify, request
from pydantic import BaseModel, ValidationError

from openm.core.auth import require_auth, require_role
from openm.utils.neo4j_client import get_graph_manager

graph_bp = Blueprint("graph", __name__, url_prefix="/api")


@graph_bp.route("/subgraph/<entity_id>", methods=["GET"])
@require_auth
def get_subgraph(entity_id: str):
    """
    GET /api/subgraph/<entity_id>?depth=2

    Retorna subgrafo no formato Cytoscape.js a partir do nó central.
    """
    try:
        depth = int(request.args.get("depth", 2))
    except ValueError:
        return jsonify({"error": "depth deve ser um inteiro"}), 400

    gm = get_graph_manager()
    subgraph = gm.get_subgraph(entity_id, depth=depth)
    return jsonify(subgraph)


class CreateEdgePayload(BaseModel):
    from_id: str
    to_id: str
    rel_type: str
    properties: dict | None = None


@graph_bp.route("/edge", methods=["POST"])
@require_auth
@require_role("admin", "analyst")
def create_edge():
    """
    POST /api/edge

    Cria um vínculo manual entre duas entidades existentes.
    """
    data = request.get_json(silent=True) or {}
    try:
        payload = CreateEdgePayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    gm = get_graph_manager()
    gm.create_relationship(
        from_id=payload.from_id,
        to_id=payload.to_id,
        rel_type=payload.rel_type,
        properties=payload.properties or {},
    )
    return jsonify({
        "message": "Vínculo criado",
        "from_id": payload.from_id,
        "to_id": payload.to_id,
        "rel_type": payload.rel_type,
    }), 201


@graph_bp.route("/edge/<path:relationship_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "analyst")
def delete_edge(relationship_id: str):
    """
    DELETE /api/edge/<id>

    Remove um vínculo pelo id de elemento do Neo4j.
    """
    gm = get_graph_manager()
    gm.delete_relationship(relationship_id)
    return jsonify({"message": "Vínculo removido", "id": relationship_id}), 200
