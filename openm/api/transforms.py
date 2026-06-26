from flask import Blueprint, g, jsonify, request

from openm.core.auth import require_auth, require_role
from openm.core.audit import log_action, ACTION_TRANSFORM_RUN
from openm.core.entity import ENTITY_CLASSES
from openm.core.transform import TransformRegistry
from openm.utils.neo4j_client import get_graph_manager

transforms_bp = Blueprint("transforms", __name__, url_prefix="/api")


@transforms_bp.route("/transforms/services", methods=["GET"])
@require_auth
def list_services():
    """
    GET /api/transforms/services

    Lista os ``service_name`` disponíveis para cadastro de API Key
    (apenas transforms que declararam ``service_name`` na classe).

    Usado para popular dinamicamente o dropdown de API Keys no
    frontend (index.html) — antes disso o dropdown estava
    hardcoded com 4 services e perdia qualquer transform novo
    (ex: VirusTotal no PR #54) até atualizacao manual.

    Returns:
        200 com ``{"services": [{"service_name", "display_name",
        "transform_name"}, ...]}`` ordenado por ``display_name``.

    IMPORTANTE: esta rota é registrada ANTES de
    ``/transforms/<entity_type>`` para que o Flask faça o match
    exato primeiro; senao ``/transforms/services`` cairia no
    parametro ``entity_type="services"`` e quebraria.
    """
    services = TransformRegistry.list_services()
    return jsonify({"services": services})


@transforms_bp.route("/transforms/<entity_type>", methods=["GET"])
@require_auth
def list_transforms(entity_type: str):
    """
    GET /api/transforms/<entity_type>

    Lista transforms registrados compatíveis com o tipo de entidade.
    """
    transforms = TransformRegistry.list_for_type(entity_type)
    return jsonify({"transforms": transforms})


@transforms_bp.route("/run_transform", methods=["POST"])
@require_auth
@require_role("admin", "analyst")
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
        msg = f"Transform desconhecido: {transform_name}"
        return jsonify({"error": msg}), 400

    # A entidade de entrada pode vir completa no payload ou ser buscada
    # no Neo4j. Para simplificar e manter stateless, reconstruímos a
    # partir do payload.
    entity_type = data.get("entity_type")
    value = data.get("value")
    properties = data.get("properties", {})

    if not entity_type or not value:
        return jsonify({"error": "entity_type e value são obrigatórios"}), 400

    entity_class = ENTITY_CLASSES.get(entity_type)
    if not entity_class:
        msg = f"Tipo de entidade desconhecido: {entity_type}"
        return jsonify({"error": msg}), 400

    entity = entity_class(
        value=value,
        properties=properties,
        entity_id=entity_id,
        created_by_user_id=g.user.id,
    )

    transform = transform_class()
    result = transform.run(entity)

    gm = get_graph_manager()
    gm.merge_entity(entity)

    # Admin não precisa checar ownership; para analyst, ele acabou de
    # tornar-se dono da entidade de input. As entidades resultantes
    # também recebem o user_id do executor.
    is_admin = getattr(g, "role", None) == "admin"
    owner_id = None if is_admin else g.user.id

    new_entities_count = 0
    for new_entity in result.entities:
        # Setar ownership do executor nas entidades resultantes do transform
        new_entity.created_by_user_id = owner_id
        gm.merge_entity(new_entity)
        new_entities_count += 1

    rels = []
    for rel in result.relationships:
        # Ownership de edge: pelo menos uma ponta pertence ao user (ou admin)
        created = gm.create_relationship(
            from_id=rel["from_id"],
            to_id=rel["to_id"],
            rel_type=rel["type"],
            properties=rel.get("properties", {}),
            user_id=owner_id,
            is_admin=is_admin,
        )
        if created:
            rels.append(rel)

    # Auditoria: execução de transform. Metadado leve (contagens) — sem
    # expor valores das entidades resultantes (podem ser PII / IOC sensível).
    log_action(
        action=ACTION_TRANSFORM_RUN,
        target_type="entity",
        target_id=entity_id or entity.id,
        user_id=g.user.id,
        metadata={
            "transform_name": transform_name,
            "entity_type": entity_type,
            "new_entities_count": new_entities_count,
            "new_relationships_count": len(rels),
        },
    )

    return jsonify(
        {
            "input": entity.to_dict(),
            "entities": [e.to_dict() for e in result.entities],
            "relationships": rels,
        }
    ), 200
