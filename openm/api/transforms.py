from flask import Blueprint, jsonify, request

from openm.core.auth import require_auth
from openm.core.entity import ENTITY_CLASSES, Entity
from openm.core.transform import TransformRegistry
from openm.utils.neo4j_client import get_graph_manager

transforms_bp = Blueprint("transforms", __name__, url_prefix="/api")


@transforms_bp.route("/transforms/<entity_type>", methods=["GET"])
@require_auth
def list_transforms(entity_type: str):
    """
    GET /api/transforms/<entity_type>

    Lista transforms registrados compatíveis com o tipo de entidade.
    """
    return jsonify({"transforms": TransformRegistry.list_for_type(entity_type)})


@transforms_bp.route("/run_transform", methods=["POST"])
@require_auth
def run_transform():
    """
    POST /api/run_transform

    Recebe {entity_id, transform_name, entity_type?, value?, properties?}.
    Reconstrói a entidade de entrada, instancia o transform, executa e
    persiste novas entidades/relacionamentos no Neo4j.
    """
    data = request.get_json(silent=True) or {}
    transform_name = data.get("transform_name")
    entity_id = data.get("entity_id")

    if not transform_name:
        return jsonify({"error": "transform_name é obrigatório"}), 400

    transform_class = TransformRegistry.get(transform_name)
    if not transform_class:
        return jsonify({"error": f"Transform desconhecido: {transform_name}"}), 400

    # A entidade de entrada pode vir completa no payload ou ser buscada no Neo4j.
    # Para simplificar e manter stateless, reconstruímos a partir do payload.
    entity_type = data.get("entity_type")
    value = data.get("value")
    properties = data.get("properties", {})

    if not entity_type or not value:
        return jsonify({"error": "entity_type e value são obrigatórios"}), 400

    entity_class = ENTITY_CLASSES.get(entity_type)
    if not entity_class:
        return jsonify({"error": f"Tipo de entidade desconhecido: {entity_type}"}), 400

    entity = entity_class(
        value=value,
        properties=properties,
        entity_id=entity_id,
    )

    transform = transform_class()
    result = transform.run(entity)

    gm = get_graph_manager()
    gm.merge_entity(entity)

    for new_entity in result.entities:
        gm.merge_entity(new_entity)

    rels = []
    for rel in result.relationships:
        gm.create_relationship(
            from_id=rel["from_id"],
            to_id=rel["to_id"],
            rel_type=rel["type"],
            properties=rel.get("properties", {}),
        )
        rels.append(rel)

    return jsonify(
        {
            "input": entity.to_dict(),
            "entities": [e.to_dict() for e in result.entities],
            "relationships": rels,
        }
    ), 200
