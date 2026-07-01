from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, g, jsonify, make_response, request

from openm.config import Config
from openm.core.auth import require_auth, require_role
from openm.core.audit import ACTION_TRANSFORM_RUN, log_action
from openm.core.entity import ENTITY_CLASSES
from openm.core.rate_limiter import admin_exempt, user_service_key
from openm.core.transform import TransformRegistry
from openm.core.transform_cache import get_cached_result, set_cached_result
from openm.extensions import limiter
from openm.models.audit_log import AuditLog
from openm.services.health_check import get_all_services_health, get_service_health
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

    cache_status = "BYPASS" if force and ttl > 0 else "MISS"
    response = make_response(jsonify(response_payload), 200)
    response.headers["X-Cache"] = cache_status
    return response


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
