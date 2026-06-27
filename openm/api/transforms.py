from flask import Blueprint, g, jsonify, make_response, request

from openm.core.auth import require_auth, require_role
from openm.core.audit import log_action, ACTION_TRANSFORM_RUN
from openm.core.entity import ENTITY_CLASSES
from openm.core.transform import TransformRegistry
from openm.core.transform_cache import (
    get_cached_result,
    set_cached_result,
)
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

    Cache (issue #84):
        - Cada transform declara ``cache_ttl_seconds`` (0 = desabilitado).
        - Antes de executar, consulta o cache SQLite. Em HIT, retorna o
          payload cacheado sem executar o transform.
        - Após executar (em MISS), persiste o resultado no cache.
        - Query param ``?force=true`` (ou campo ``force`` no body)
          bypassa o cache.
        - Resposta inclui header ``X-Cache: HIT|MISS|BYPASS``.
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

    # force=true bypassa o cache (aceita tanto query param quanto body)
    force = (
        request.args.get("force", "").lower() == "true"
        or bool(data.get("force"))
    )

    # Cache: verifica HIT antes de executar (se TTL > 0 e não for force).
    ttl = getattr(transform_class, "cache_ttl_seconds", 0) or 0
    cached_payload = None
    cache_status = "MISS"

    if ttl > 0 and not force:
        cached_payload = get_cached_result(transform_name, entity_type, value)
        if cached_payload is not None:
            cache_status = "HIT"

    if cached_payload is not None:
        # Cache HIT: persiste input/relationships no Neo4j (sem re-executar)
        # para que ownership e audit reflitam a execução corrente.
        gm = get_graph_manager()
        if gm:
            from openm.core.entity import ENTITY_CLASSES as _EC
            input_dict = cached_payload.get("input", {})
            entity_class_hit = _EC.get(entity_type)
            if entity_class_hit is not None:
                input_entity = entity_class_hit(
                    value=input_dict.get("value", value),
                    properties=input_dict.get("properties", {}),
                    entity_id=input_dict.get("id") or entity_id,
                    created_by_user_id=g.user.id,
                )
                gm.merge_entity(input_entity)

            is_admin_hit = getattr(g, "role", None) == "admin"
            owner_id_hit = None if is_admin_hit else g.user.id
            for ent_dict in cached_payload.get("entities", []):
                ent_class = _EC.get(ent_dict.get("type"))
                if ent_class is None:
                    continue
                ent_obj = ent_class(
                    value=ent_dict.get("value", ""),
                    properties=ent_dict.get("properties", {}),
                    entity_id=ent_dict.get("id"),
                )
                ent_obj.created_by_user_id = owner_id_hit
                gm.merge_entity(ent_obj)
            for rel in cached_payload.get("relationships", []):
                gm.create_relationship(
                    from_id=rel["from_id"],
                    to_id=rel["to_id"],
                    rel_type=rel["type"],
                    properties=rel.get("properties", {}),
                    user_id=owner_id_hit,
                    is_admin=is_admin_hit,
                )

            # Audit mesmo em HIT (executar é uma ação do usuário)
            log_action(
                action=ACTION_TRANSFORM_RUN,
                target_type="entity",
                target_id=entity_id or value,
                user_id=g.user.id,
                metadata={
                    "transform_name": transform_name,
                    "entity_type": entity_type,
                    "cache": "HIT",
                    "new_entities_count": len(cached_payload.get("entities", [])),
                    "new_relationships_count": len(
                        cached_payload.get("relationships", [])
                    ),
                },
            )

        response = make_response(jsonify(cached_payload), 200)
        response.headers["X-Cache"] = cache_status
        return response

    # Cache MISS: executa o transform.
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
            "cache": "MISS",
            "new_entities_count": new_entities_count,
            "new_relationships_count": len(rels),
        },
    )

    # Monta payload de resposta (mesmo formato que será cacheado).
    response_payload = {
        "input": entity.to_dict(),
        "entities": [e.to_dict() for e in result.entities],
        "relationships": rels,
    }

    # Salva no cache se TTL > 0 e não foi bypass.
    if ttl > 0 and not force:
        set_cached_result(
            transform_name, entity_type, value, response_payload, ttl
        )

    cache_status = "BYPASS" if force and ttl > 0 else "MISS"
    response = make_response(jsonify(response_payload), 200)
    response.headers["X-Cache"] = cache_status
    return response
