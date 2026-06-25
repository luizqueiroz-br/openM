from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, ConfigDict, ValidationError

from openm.core.auth import require_auth, require_role
from openm.core.audit import (
    log_action,
    ACTION_ENTITY_CREATE,
    ACTION_ENTITY_UPDATE,
    ACTION_ENTITY_DELETE,
)
from openm.core.entity import ENTITY_CLASSES
from openm.utils.neo4j_client import get_graph_manager

entities_bp = Blueprint("entities", __name__, url_prefix="/api")


class CreateEntityPayload(BaseModel):
    """Payload validado para criação de entidade."""

    model_config = ConfigDict(extra="allow")

    type: str
    value: str


class UpdateEntityPayload(BaseModel):
    """Payload para atualização de propriedades."""

    properties: dict


def _extract_properties(data: dict) -> dict:
    """Extrai propriedades extras do payload, excluindo type e value."""
    return {k: v for k, v in data.items() if k not in ("type", "value", "id", "entity_id")}


@entities_bp.route("/entity", methods=["POST"])
@require_auth
@require_role("admin", "analyst")
def create_entity():
    """
    POST /api/entity

    Cria (merge) uma entidade no Neo4j. Se o tipo não existir,
    retorna 400. Propriedades extras são armazenadas dinamicamente.
    """
    data = request.get_json(silent=True) or {}
    try:
        payload = CreateEntityPayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    entity_class = ENTITY_CLASSES.get(payload.type)
    if not entity_class:
        return jsonify({"error": f"Tipo de entidade desconhecido: {payload.type}"}), 400

    properties = _extract_properties(data)
    entity = entity_class(value=payload.value, properties=properties)

    gm = get_graph_manager()
    gm.merge_entity(entity)

    # Auditoria: criação de entidade. Não logamos as properties inteiras
    # (podem conter dados sensíveis) — só keys como metadado.
    log_action(
        action=ACTION_ENTITY_CREATE,
        target_type="entity",
        target_id=entity.id,
        user_id=g.user.id,
        metadata={
            "entity_type": payload.type,
            "value": payload.value,
            "property_keys": sorted(properties.keys()),
        },
    )

    return jsonify({"entity": entity.to_dict()}), 201


@entities_bp.route("/entity/<entity_id>", methods=["PATCH"])
@require_auth
@require_role("admin", "analyst")
def update_entity(entity_id: str):
    """
    PATCH /api/entity/<id>

    Atualiza propriedades dinâmicas de uma entidade existente.
    """
    data = request.get_json(silent=True) or {}
    try:
        payload = UpdateEntityPayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    gm = get_graph_manager()
    if gm.get_entity(entity_id) is None:
        return jsonify({"error": "Entidade não encontrada"}), 404

    gm.update_entity_properties(entity_id, payload.properties)
    # Auditoria: atualização de propriedades. Não logamos valores (podem
    # conter dados sensíveis), só as chaves alteradas.
    log_action(
        action=ACTION_ENTITY_UPDATE,
        target_type="entity",
        target_id=entity_id,
        user_id=g.user.id,
        metadata={
            "property_keys": sorted(payload.properties.keys()),
        },
    )
    return jsonify({"message": "Entidade atualizada", "id": entity_id}), 200


@entities_bp.route("/entity/<entity_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "analyst")
def delete_entity(entity_id: str):
    """
    DELETE /api/entity/<id>

    Remove uma entidade e seus relacionamentos adjacentes.
    """
    gm = get_graph_manager()
    gm.delete_entity(entity_id)
    # Auditoria: deleção de entidade (incluindo relacionamentos adjacentes).
    log_action(
        action=ACTION_ENTITY_DELETE,
        target_type="entity",
        target_id=entity_id,
        user_id=g.user.id,
    )
    return jsonify({"message": "Entidade removida", "id": entity_id}), 200
