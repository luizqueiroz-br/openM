from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import datetime, timedelta, timezone
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from flask import Blueprint, current_app, g, jsonify, make_response, request

from openm.config import Config
from openm.core.auth import require_auth, require_role
from openm.core.audit import (
    ACTION_TRANSFORM_BATCH_RUN,
    ACTION_TRANSFORM_RUN,
    log_action,
)
from openm.core.chain_executor import (
    DEFAULT_CHAIN_DEPTH,
    MAX_CHAIN_DEPTH,
    MIN_CHAIN_DEPTH,
    _build_chain_plan,
    _execute_chain,
    log_chain_audit,
)
from openm.core.entity import ENTITY_CLASSES
from openm.core.rate_limiter import admin_exempt, user_service_key
from openm.core.transform import TransformRegistry
from openm.core.transform_cache import get_cached_result, set_cached_result
from openm.extensions import limiter
from openm.models.audit_log import AuditLog
from openm.services.health_check import get_all_services_health, get_service_health
from openm.utils.neo4j_client import get_graph_manager

logger = logging.getLogger(__name__)


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
# Issue #89: rate limit por user+service. A key_func resolve
# ``f"u{user.id}:{service_name}"`` (fallback IP), e o lambda é avaliado
# em cada request para permitir override por env var. Admins são
# isentos via ``exempt_when``. Ordem dos decorators: @require_auth
# (outermost) → @require_role → @limiter.limit (innermost) — garante
# que ``g.user`` está populado antes de ``key_func`` rodar.
@limiter.limit(
    lambda: Config.RATELIMIT_SERVICES.get(
        getattr(g, "service_name", "__internal__"),
        Config.RATELIMIT_SERVICES["__internal__"],
    ),
    key_func=user_service_key,
    exempt_when=admin_exempt,
)
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

    Rate limit (issue #89):
        - Limite por user+service, avaliado dinamicamente via
          ``g.service_name`` (resolvido abaixo a partir do
          ``transform_class.service_name`` declarado pela classe).

    Chain (issue #81):
        - Body aceita ``chain: bool | "dry_run"`` (default false)
          e ``chain_max_depth: int`` (default 3, range 1-10).
        - ``chain=true``: executa hop 1 e recursa em
          ``downstream_transforms`` (max_chain_depth hops no total).
          1 entry consolidada ``ACTION_TRANSFORM_CHAIN_RUN`` é
          logada. Hops NÃO contam no rate limit (limitação v1).
        - ``chain="dry_run"``: retorna ``plan`` estático sem
          executar. Útil para preview no Transform Hub.
        - Batch (``/api/run_transform_batch``) NÃO suporta chain.
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

    # Issue #89: resolve o service_name do transform para que
    # ``user_service_key`` gere chaves distintas por service. A
    # ``before_request`` registrada em ``register_rate_limit_handler``
    # já popula ``g.service_name`` ANTES do limiter rodar (ela é
    # registrada antes de ``limiter.init_app`` em app.py). Esta
    # reatribuição no handler é redundante em produção (defense in
    # depth) mas importante para testes que chamam a view function
    # diretamente sem passar pelo ciclo de request completo.
    g.service_name = getattr(transform_class, "service_name", None) or "__internal__"

    # A entidade de entrada pode vir completa no payload ou ser buscada
    # no Neo4j. Para simplificar e manter stateless, reconstruímos a
    # partir do payload.
    entity_type = data.get("entity_type")
    value = data.get("value")
    properties = data.get("properties", {})

    if not entity_type or not value:
        return jsonify({"error": "entity_type e value são obrigatórios"}), 400

    # Issue #81: chain. Aceita bool ou string "dry_run". Default
    # false (comportamento single entity, sem chain).
    chain_raw = data.get("chain", False)
    if isinstance(chain_raw, str):
        chain_flag: Any = chain_raw.strip().lower() == "true"
        chain_dry_run: bool = chain_raw.strip().lower() == "dry_run"
    else:
        chain_flag = bool(chain_raw)
        chain_dry_run = False

    # chain_max_depth: 1-10, default 3. Validado aqui (400 se
    # inválido) para que dry_run nem tente executar.
    chain_max_depth_raw = data.get("chain_max_depth", DEFAULT_CHAIN_DEPTH)
    try:
        chain_max_depth = int(chain_max_depth_raw)
    except (TypeError, ValueError):
        return jsonify({
            "error": (
                f"chain_max_depth inválido: {chain_max_depth_raw!r} "
                f"(esperado inteiro entre {MIN_CHAIN_DEPTH} e {MAX_CHAIN_DEPTH})"
            ),
        }), 400
    if chain_max_depth < MIN_CHAIN_DEPTH or chain_max_depth > MAX_CHAIN_DEPTH:
        return jsonify({
            "error": (
                f"chain_max_depth fora do range: {chain_max_depth} "
                f"(permitido: {MIN_CHAIN_DEPTH}-{MAX_CHAIN_DEPTH})"
            ),
        }), 400

    # Dry-run: retorna plano estático sem executar. Útil para o
    # frontend mostrar preview no Transform Hub.
    if chain_dry_run:
        plan = _build_chain_plan(
            start_transform_name=transform_name,
            start_input_type=entity_type,
            max_chain_depth=chain_max_depth,
        )
        return jsonify({
            "dry_run": True,
            "transform_name": transform_name,
            "entity_type": entity_type,
            "chain_max_depth": chain_max_depth,
            "total_hops": len(plan),
            "plan": plan,
        }), 200

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
        # para que ownership e audit reflitam a execucao corrente.
        gm = get_graph_manager()
        chain_result: Optional[Dict[str, Any]] = None
        chain_hop1_outputs: List[Any] = []
        if gm:
            from openm.core.entity import ENTITY_CLASSES as _EC
            input_dict = cached_payload.get("input", {})
            entity_class_hit = _EC.get(entity_type)
            input_entity_hit = None
            if entity_class_hit is not None:
                input_entity_hit = entity_class_hit(
                    value=input_dict.get("value", value),
                    properties=input_dict.get("properties", {}),
                    entity_id=input_dict.get("id") or entity_id,
                    created_by_user_id=g.user.id,
                )
                gm.merge_entity(input_entity_hit)

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
                # Acumular outputs para o chain (issue #81).
                chain_hop1_outputs.append(ent_obj)
            for rel in cached_payload.get("relationships", []):
                gm.create_relationship(
                    from_id=rel["from_id"],
                    to_id=rel["to_id"],
                    rel_type=rel["type"],
                    properties=rel.get("properties", {}),
                    user_id=owner_id_hit,
                    is_admin=is_admin_hit,
                )

            # Audit mesmo em HIT (executar e uma acao do usuario).
            # Metricas: em cache hit nao executamos o transform, entao
            # duration e desconhecido (0), api_calls=0, status=success.
            entities_count = len(cached_payload.get("entities", []))
            relationships_count = len(cached_payload.get("relationships", []))
            log_action(
                action=ACTION_TRANSFORM_RUN,
                target_type="entity",
                target_id=entity_id or value,
                user_id=g.user.id,
                metadata={
                    "transform_name": transform_name,
                    "entity_type": entity_type,
                    "cache": "HIT",
                    "new_entities_count": entities_count,
                    "new_relationships_count": relationships_count,
                    "duration_ms": 0,
                    "status": "success",
                    "api_calls": 0,
                },
            )

            # Issue #81: chain execution (pós-hop-1). Mesmo em cache
            # HIT, executamos os hops 2..N se chain=true.
            if chain_flag and input_entity_hit is not None:
                chain_result = _execute_chain(
                    initial_transform_name=transform_name,
                    initial_input_entity=input_entity_hit,
                    initial_input_type=entity_type,
                    initial_output_entities=chain_hop1_outputs,
                    is_admin=is_admin_hit,
                    owner_id=owner_id_hit,
                    user_id=g.user.id,
                    max_chain_depth=chain_max_depth,
                    force=force,
                )
                # Audit consolidado do chain.
                log_chain_audit(
                    user_id=g.user.id,
                    target_id=entity_id or value,
                    transform_name=transform_name,
                    entity_type=entity_type,
                    chain_max_depth=chain_max_depth,
                    result=chain_result,
                    metadata_extra={
                        "hop1_cache": "HIT",
                        "hop1_duration_ms": 0,
                    },
                )

        # Monta payload de resposta. Em chain=true, inclui os
        # resultados dos hops 2..N.
        response_payload = dict(cached_payload)
        if chain_flag and chain_result is not None:
            # Os outputs do hop 1 já estão em cached_payload.
            # chain.hops traz telemetria hops 2..N.
            response_payload["chain"] = {
                "hops": chain_result.get("hops", []),
                "truncated": bool(chain_result.get("truncated")),
                "truncated_reason": chain_result.get("truncated_reason"),
                "chain_max_depth": chain_max_depth,
                "total_hops": len(chain_result.get("hops", [])),
            }

        response = make_response(jsonify(response_payload), 200)
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
    metrics = getattr(result, "_metrics", None)

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

    # Auditoria: execucao de transform. Metadado leve (contagens) — sem
    # expor valores das entidades resultantes (podem ser PII / IOC sensivel).
    # Inclui metricas de duracao, status, chamadas externas e cache.
    audit_metadata = {
        "transform_name": transform_name,
        "entity_type": entity_type,
        "cache": "MISS",
        "new_entities_count": new_entities_count,
        "new_relationships_count": len(rels),
    }
    if metrics is not None:
        audit_metadata.update({
            "duration_ms": metrics.duration_ms,
            "status": metrics.status,
            "api_calls": metrics.api_calls,
        })
        if metrics.error_message:
            audit_metadata["error_message"] = metrics.error_message

    log_action(
        action=ACTION_TRANSFORM_RUN,
        target_type="entity",
        target_id=entity_id or entity.id,
        user_id=g.user.id,
        metadata=audit_metadata,
    )

    # Monta payload de resposta (mesmo formato que sera cacheado).
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

    # Issue #81: chain execution (pós-hop-1). Se chain=true, recursa
    # em downstream_transforms e loga audit consolidado.
    chain_response: Optional[Dict[str, Any]] = None
    if chain_flag:
        chain_result = _execute_chain(
            initial_transform_name=transform_name,
            initial_input_entity=entity,
            initial_input_type=entity_type,
            initial_output_entities=list(result.entities),
            is_admin=is_admin,
            owner_id=owner_id,
            user_id=g.user.id,
            max_chain_depth=chain_max_depth,
            force=force,
        )
        log_chain_audit(
            user_id=g.user.id,
            target_id=entity_id or entity.id,
            transform_name=transform_name,
            entity_type=entity_type,
            chain_max_depth=chain_max_depth,
            result=chain_result,
            metadata_extra={
                "hop1_cache": "MISS",
                "hop1_duration_ms": (
                    metrics.duration_ms if metrics is not None else 0
                ),
            },
        )
        chain_response = {
            "hops": chain_result.get("hops", []),
            "truncated": bool(chain_result.get("truncated")),
            "truncated_reason": chain_result.get("truncated_reason"),
            "chain_max_depth": chain_max_depth,
            "total_hops": len(chain_result.get("hops", [])),
        }

    cache_status = "BYPASS" if force and ttl > 0 else "MISS"
    if chain_response is not None:
        response_payload["chain"] = chain_response
    response = make_response(jsonify(response_payload), 200)
    response.headers["X-Cache"] = cache_status
    return response


# ---------------------------------------------------------------------------
# Issue #87: Bulk/batch transform execution
# ---------------------------------------------------------------------------


def _process_one(
    app_obj,
    transform_class,
    ctx_kwargs,
    entity,
    force,
    ttl,
    user_id,
    is_admin,
):
    """
    Worker function — roda em uma thread com seu próprio app_context.

    Estratégia B (issue #87): check do cache em paralelo (mesma fase
    da execução). Se HIT, faz replay das entidades/relacionamentos
    no Neo4j sem executar o transform. Se MISS, executa o transform
    e persiste resultado.

    Retorna um dict com ``status`` ("success" | "error") e campos
    de telemetria. Nunca levanta exceção para o caller — qualquer
    falha é convertida em status="error" para que o batch
    continue processando as demais entities (decisão issue #87).
    """
    with app_obj.app_context():
        try:
            value = entity.get("value", "")
            properties = entity.get("properties", {})
            entity_id = entity.get("entity_id")
            entity_type = ctx_kwargs["entity_type"]
            transform_name = ctx_kwargs["transform_name"]

            # Cache check (estratégia B — paralelo).
            cache_status = "MISS"
            if ttl > 0 and not force:
                cached = get_cached_result(transform_name, entity_type, value)
                if cached is not None:
                    # Replay no Neo4j (mesmo padrão de /api/run_transform
                    # em cache HIT): reconstrói Entity objects a partir
                    # dos dicts cacheados e faz merge.
                    gm = get_graph_manager()
                    if gm is not None:
                        input_dict = cached.get("input", {})
                        input_cls = ENTITY_CLASSES.get(entity_type)
                        if input_cls is not None:
                            input_entity = input_cls(
                                value=input_dict.get("value", value),
                                properties=input_dict.get("properties", {}),
                                entity_id=input_dict.get("id") or entity_id,
                                created_by_user_id=user_id,
                            )
                            gm.merge_entity(input_entity)
                        owner_id = None if is_admin else user_id
                        for ent_dict in cached.get("entities", []):
                            ent_cls = ENTITY_CLASSES.get(ent_dict.get("type"))
                            if ent_cls is None:
                                continue
                            ent_obj = ent_cls(
                                value=ent_dict.get("value", ""),
                                properties=ent_dict.get("properties", {}),
                                entity_id=ent_dict.get("id"),
                            )
                            ent_obj.created_by_user_id = owner_id
                            gm.merge_entity(ent_obj)
                        for rel in cached.get("relationships", []):
                            gm.create_relationship(
                                from_id=rel["from_id"],
                                to_id=rel["to_id"],
                                rel_type=rel["type"],
                                properties=rel.get("properties", {}),
                                user_id=owner_id,
                                is_admin=is_admin,
                            )
                    return {
                        "value": value,
                        "status": "success",
                        "cache": "HIT",
                        "entities": len(cached.get("entities", [])),
                        "relationships": len(cached.get("relationships", [])),
                        "api_calls": 0,
                        "duration_ms": 0,
                    }

            # Cache MISS — executa o transform.
            entity_class = ENTITY_CLASSES.get(entity_type)
            if entity_class is None:
                # Erro de config (entity_type não existe). Não aborta
                # o batch — devolve error só para esta entity.
                return {
                    "value": value,
                    "status": "error",
                    "error": f"Tipo de entidade desconhecido: {entity_type}",
                    "error_type": "UnknownEntityType",
                }
            entity_obj = entity_class(
                value=value,
                properties=properties,
                entity_id=entity_id,
                created_by_user_id=user_id,
            )
            transform = transform_class()
            result = transform.run(entity_obj)
            metrics = getattr(result, "_metrics", None)

            # O template method ``Transform.run`` ENGOLLE exceções e
            # devolve um ``TransformResult()`` vazio com
            # ``metrics.status="error"`` (ou "timeout"). Precisamos
            # checar isso para reportar o erro no batch em vez de
            # marcar como success silencioso.
            if metrics is not None and metrics.status in ("error", "timeout"):
                return {
                    "value": value,
                    "status": metrics.status,
                    "error": metrics.error_message or "transform failed",
                    "error_type": "TransformError",
                    "duration_ms": metrics.duration_ms,
                }

            gm = get_graph_manager()
            if gm is not None:
                gm.merge_entity(entity_obj)
                owner_id = None if is_admin else user_id
                for new_entity in result.entities:
                    new_entity.created_by_user_id = owner_id
                    gm.merge_entity(new_entity)
                for rel in result.relationships:
                    gm.create_relationship(
                        from_id=rel["from_id"],
                        to_id=rel["to_id"],
                        rel_type=rel["type"],
                        properties=rel.get("properties", {}),
                        user_id=owner_id,
                        is_admin=is_admin,
                    )

            if ttl > 0 and not force:
                payload = {
                    "input": entity_obj.to_dict(),
                    "entities": [e.to_dict() for e in result.entities],
                    "relationships": [
                        {
                            "from_id": r["from_id"],
                            "to_id": r["to_id"],
                            "type": r["type"],
                            "properties": r.get("properties", {}),
                        }
                        for r in result.relationships
                    ],
                }
                set_cached_result(
                    transform_name, entity_type, value, payload, ttl
                )

            return {
                "value": value,
                "status": "success",
                "cache": cache_status,
                "entities": len(result.entities),
                "relationships": len(result.relationships),
                "api_calls": metrics.api_calls if metrics else 0,
                "duration_ms": metrics.duration_ms if metrics else 0,
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "batch entity failed value=%s err=%s",
                entity.get("value"),
                exc,
            )
            return {
                "value": entity.get("value"),
                "status": "error",
                "error": str(exc),
                "error_type": type(exc).__name__,
            }


@transforms_bp.route("/run_transform_batch", methods=["POST"])
@require_auth
@require_role("admin", "analyst")
# Issue #87: rate limit por user+service. 1 count por batch (não por
# entity) — o decorator conta 1 hit por request HTTP, independente
# de quantas entities o batch contém. Lambda é avaliado em cada
# request para permitir override por env var. Admins são isentos
# via ``exempt_when``. Ordem dos decorators: @require_auth →
# @require_role → @limiter.limit (innermost) — garante que
# ``g.user`` está populado antes de ``key_func`` rodar.
@limiter.limit(
    lambda: Config.RATELIMIT_SERVICES.get(
        getattr(g, "service_name", "__internal__"),
        Config.RATELIMIT_SERVICES["__internal__"],
    ),
    key_func=user_service_key,
    exempt_when=admin_exempt,
)
def run_transform_batch():
    """
    POST /api/run_transform_batch

    Recebe ``{transform_name, entity_type, entities: [...]}`` e
    executa o transform em N entities em paralelo
    (``ThreadPoolExecutor`` com ``max_workers`` configurável).

    Cada entity é processada independentemente: erro em uma
    não aborta as demais (``status: error`` apenas para ela).
    O endpoint retorna um ``summary`` agregado e um array
    ``results`` com o status de cada entity. ATENÇÃO: ``results``
    NÃO preserva a ordem de input (a ordem reflete a ordem de
    conclusão de cada worker, não de envio). Se ordem for
    importante, use o campo ``value`` de cada item para
    indexar externamente.

    Body:
        {
            "transform_name": "email_to_domain",
            "entity_type":   "Email",
            "entities": [
                {"value": "a@x.com"},
                {"value": "b@x.com", "properties": {...}}
            ],
            "force": false  # opcional, bypassa cache
        }

    Response (200):
        {
            "summary": {
                "batch_size": N,
                "success_count": ...,
                "error_count": ...,
                "timeout_count": ...,
                "cache_hit_count": ...,
                "duration_ms": ...,
                "total_api_calls": ...,
                "max_workers": ...,
                "batch_timeout_seconds": ...
            },
            "results": [
                {"value": "...", "status": "success", ...},
                {"value": "...", "status": "error", ...}
            ]
        }

    Errors:
        400 — payload inválido (transform/entity_type ausente, entities
              não-list, etc.)
        413 — entities excede ``Config.BATCH_MAX_ENTITIES`` (default 100)
        429 — rate limit excedido (issue #89)
    """
    data = request.get_json(silent=True) or {}
    transform_name = data.get("transform_name")
    entity_type = data.get("entity_type")
    entities_payload = data.get("entities", [])
    force = bool(data.get("force"))

    if not transform_name:
        return jsonify({"error": "transform_name é obrigatório"}), 400
    if not entity_type:
        return jsonify({"error": "entity_type é obrigatório"}), 400
    if not isinstance(entities_payload, list):
        return jsonify({"error": "entities deve ser uma lista"}), 400
    if len(entities_payload) == 0:
        return jsonify({"error": "entities não pode ser vazia"}), 400
    if len(entities_payload) > Config.BATCH_MAX_ENTITIES:
        return (
            jsonify(
                {
                    "error": "batch_exceeds_max",
                    "max_entities": Config.BATCH_MAX_ENTITIES,
                    "received": len(entities_payload),
                }
            ),
            413,
        )

    transform_class = TransformRegistry.get(transform_name)
    if not transform_class:
        return (
            jsonify({"error": f"Transform desconhecido: {transform_name}"}),
            400,
        )
    # Resolve entity_type agora para falhar cedo (antes de abrir
    # o pool) — o worker também valida, mas falhar aqui dá erro
    # 400 determinístico em vez de N errors genéricos.
    if entity_type not in ENTITY_CLASSES:
        return (
            jsonify({"error": f"Tipo de entidade desconhecido: {entity_type}"}),
            400,
        )

    # Setar g.service_name (defesa em profundidade; a before_request
    # em core/rate_limiter.py já populou isso ANTES do limiter rodar
    # para /api/run_transform_batch). A reatribuição aqui é
    # importante para testes que chamam a view function diretamente
    # sem passar pelo ciclo de request completo.
    g.service_name = (
        getattr(transform_class, "service_name", None) or "__internal__"
    )

    ttl = getattr(transform_class, "cache_ttl_seconds", 0) or 0
    user_id = g.user.id
    is_admin = getattr(g, "role", None) == "admin"
    # app_obj precisa ser capturado do request handler — workers
    # não têm acesso a ``current_app`` (não há request context na
    # thread). _get_current_object() devolve o app real, sem proxy.
    app_obj = current_app._get_current_object()
    ctx_kwargs = {
        "transform_name": transform_name,
        "entity_type": entity_type,
    }

    # Execução paralela. ``max_workers`` é cap em
    # ``len(entities_payload)`` para não abrir mais threads que
    # entities (desperdício). 1 thread se batch tem 1 entity
    # (overhead zero).
    max_workers = min(Config.BATCH_MAX_WORKERS, len(entities_payload))
    start_ts = time.perf_counter()
    results: list[dict] = []
    cache_hit_count = 0

    with ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix="openm-batch",
    ) as executor:
        futures = {
            executor.submit(
                _process_one,
                app_obj,
                transform_class,
                ctx_kwargs,
                entity,
                force,
                ttl,
                user_id,
                is_admin,
            ): entity
            for entity in entities_payload
        }
        try:
            for fut in as_completed(
                futures, timeout=Config.BATCH_TIMEOUT_SECONDS
            ):
                entity = futures[fut]
                try:
                    outcome = fut.result(timeout=0)
                    results.append(outcome)
                    if outcome.get("cache") == "HIT":
                        cache_hit_count += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning("batch future exception: %s", exc)
                    results.append(
                        {
                            "value": entity.get("value"),
                            "status": "error",
                            "error": str(exc),
                            "error_type": type(exc).__name__,
                        }
                    )
        except FuturesTimeout:
            # Timeout global do batch atingido. Os futures que ainda
            # não completaram viram status="timeout" no results. Não
            # tentamos ``future.cancel()`` (issue #87: não confiar —
            # a thread pode já estar executando o transform).
            for fut, entity in futures.items():
                if not fut.done():
                    results.append(
                        {
                            "value": entity.get("value"),
                            "status": "timeout",
                        }
                    )

    duration_ms = round((time.perf_counter() - start_ts) * 1000, 2)

    # Summary agregado.
    success = [r for r in results if r.get("status") == "success"]
    errors = [r for r in results if r.get("status") == "error"]
    timeouts = [r for r in results if r.get("status") == "timeout"]
    total_api_calls = sum(r.get("api_calls", 0) for r in success)

    # 1 entry consolidada de audit (issue #87) — não uma por entity.
    log_action(
        action=ACTION_TRANSFORM_BATCH_RUN,
        target_type="batch",
        target_id=str(uuid.uuid4()),
        user_id=user_id,
        metadata={
            "transform_name": transform_name,
            "entity_type": entity_type,
            "batch_size": len(entities_payload),
            "success_count": len(success),
            "error_count": len(errors),
            "timeout_count": len(timeouts),
            "cache_hit_count": cache_hit_count,
            "total_api_calls": total_api_calls,
            "duration_ms": duration_ms,
            "status": (
                "success"
                if not errors and not timeouts
                else "partial"
                if success
                else "error"
            ),
        },
    )

    return jsonify(
        {
            "summary": {
                "batch_size": len(entities_payload),
                "success_count": len(success),
                "error_count": len(errors),
                "timeout_count": len(timeouts),
                "cache_hit_count": cache_hit_count,
                "duration_ms": duration_ms,
                "total_api_calls": total_api_calls,
                "max_workers": max_workers,
                "batch_timeout_seconds": Config.BATCH_TIMEOUT_SECONDS,
            },
            # ⚠️ paralelo, não preserva ordem de input. Use o
            # campo ``value`` para mapear de volta ao input.
            "results": results,
        }
    )


@transforms_bp.route("/transforms/metrics", methods=["GET"])
@require_auth
@require_role("admin")
def transform_metrics():
    """
    GET /api/transforms/metrics

    Retorna metricas agregadas de execucao de transforms a partir do
    audit_log (acao ``transform.run``). Admin-only.

    Query params:
        - transform_name: filtrar por transform especifico.
        - entity_type: filtrar por tipo de entidade de entrada.
        - user_id: filtrar por usuario.
        - period_days: janela de dias (default 7, max 90).

    Resposta:
        {
            "period_days": int,
            "filters": {...},
            "summary": {
                "total_runs": int,
                "success_count": int,
                "error_count": int,
                "timeout_count": int,
                "quota_exceeded_count": int,
                "cache_hit_count": int,
                "avg_duration_ms": float,
                "total_api_calls": int,
                "avg_api_calls": float,
            },
            "by_transform": [
                {
                    "transform_name": str,
                    "total_runs": int,
                    "success_count": int,
                    "error_count": int,
                    "avg_duration_ms": float,
                    "total_api_calls": int,
                }
            ]
        }
    """
    try:
        period_days = min(int(request.args.get("period_days", 7)), 90)
    except (ValueError, TypeError):
        period_days = 7

    transform_name = request.args.get("transform_name")
    entity_type = request.args.get("entity_type")
    user_id_raw = request.args.get("user_id")
    user_id = None
    if user_id_raw is not None:
        try:
            user_id = int(user_id_raw)
        except (ValueError, TypeError):
            pass

    since = datetime.now(timezone.utc) - timedelta(days=period_days)

    query = AuditLog.query.filter(
        AuditLog.action == ACTION_TRANSFORM_RUN,
        AuditLog.created_at >= since,
    )
    if transform_name:
        # JSONB path nao e portavel para SQLite; filtramos em Python.
        pass
    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)

    rows = query.all()
    filtered_rows = []
    for row in rows:
        meta = row.meta or {}
        if transform_name and meta.get("transform_name") != transform_name:
            continue
        if entity_type and meta.get("entity_type") != entity_type:
            continue
        filtered_rows.append(row)

    summary = {
        "total_runs": 0,
        "success_count": 0,
        "error_count": 0,
        "timeout_count": 0,
        "quota_exceeded_count": 0,
        "cache_hit_count": 0,
        "avg_duration_ms": 0.0,
        "total_api_calls": 0,
        "avg_api_calls": 0.0,
    }
    durations: list[float] = []
    api_calls_values: list[int] = []
    by_transform: dict[str, dict[str, Any]] = {}

    for row in filtered_rows:
        meta = row.meta or {}
        status = meta.get("status", "success")
        cache = meta.get("cache", "MISS")
        duration = meta.get("duration_ms", 0) or 0
        api_calls = meta.get("api_calls", 0) or 0
        name = meta.get("transform_name", "unknown")

        summary["total_runs"] += 1
        if status == "success":
            summary["success_count"] += 1
        elif status == "error":
            summary["error_count"] += 1
        elif status == "timeout":
            summary["timeout_count"] += 1
        elif status == "quota_exceeded":
            summary["quota_exceeded_count"] += 1

        if cache == "HIT":
            summary["cache_hit_count"] += 1

        durations.append(float(duration))
        api_calls_values.append(int(api_calls))
        summary["total_api_calls"] += int(api_calls)

        bucket = by_transform.setdefault(name, {
            "transform_name": name,
            "total_runs": 0,
            "success_count": 0,
            "error_count": 0,
            "timeout_count": 0,
            "quota_exceeded_count": 0,
            "avg_duration_ms": 0.0,
            "total_api_calls": 0,
            "runs": [],
        })
        bucket["total_runs"] += 1
        if status == "success":
            bucket["success_count"] += 1
        elif status == "error":
            bucket["error_count"] += 1
        elif status == "timeout":
            bucket["timeout_count"] += 1
        elif status == "quota_exceeded":
            bucket["quota_exceeded_count"] += 1
        bucket["total_api_calls"] += int(api_calls)
        bucket["runs"].append(float(duration))

    if durations:
        summary["avg_duration_ms"] = round(sum(durations) / len(durations), 2)
    if api_calls_values:
        summary["avg_api_calls"] = round(sum(api_calls_values) / len(api_calls_values), 2)

    by_transform_list: list[dict[str, Any]] = []
    for bucket in by_transform.values():
        runs = bucket.pop("runs")
        bucket["avg_duration_ms"] = round(sum(runs) / len(runs), 2) if runs else 0.0
        by_transform_list.append(bucket)

    by_transform_list.sort(key=lambda x: x["total_runs"], reverse=True)

    return jsonify({
        "period_days": period_days,
        "filters": {
            "transform_name": transform_name,
            "entity_type": entity_type,
            "user_id": user_id,
        },
        "summary": summary,
        "by_transform": by_transform_list,
    })


@transforms_bp.route("/services/health", methods=["GET"])
@require_auth
@require_role("admin")
def services_health():
    """
    GET /api/services/health

    Health check dos services externos (issue #79). Admin-only.

    Para cada service que declara ``service_name`` em um transform
    registrado, faz uma chamada leve ao endpoint de health do service
    externo para validar a chave cadastrada e a disponibilidade. O
    resultado e cacheado por 5 minutos para evitar consumir quota.

    Query params:
        - service: restringir a um service especifico (ex: ?service=shodan).
        - force=true: bypassa o cache e pinga o service de novo.

    Resposta:
        {
            "services": {
                "shodan": {"status": "ok", "key_valid": true, ...},
                "virustotal": {"status": "ok", "key_valid": true, ...},
                "hunter": {"status": "error", "key_valid": false, "message": "..."}
            }
        }
    """
    force = request.args.get("force", "").lower() == "true"
    single = request.args.get("service")

    if single:
        return jsonify({"services": {single: get_service_health(single, force=force)}})

    return jsonify({"services": get_all_services_health(force=force)})


@transforms_bp.route("/services/quota", methods=["GET"])
@require_auth
def services_quota():
    """
    GET /api/services/quota (issue #89)

    Retorna a quota atual do user autenticado em cada service
    declarado em ``Config.RATELIMIT_SERVICES``. Não é admin-only:
    cada user consulta seu próprio budget (info retornada ao
    usuário final para o frontend exibir avisos tipo "5/10 shodan
    requests este minuto").

    Resposta:
        {
            "services": [
                {
                    "name": "shodan",
                    "limit": 10,
                    "period": "hour",
                    "used": 0,
                    "remaining": 10,
                    "reset_at": null
                },
                ...
            ]
        }
    """
    from openm.core.rate_limiter import get_user_quota

    user = g.user
    quotas = [
        get_user_quota(user.id, service_name)
        for service_name in Config.RATELIMIT_SERVICES.keys()
    ]
    return jsonify({"services": quotas})
