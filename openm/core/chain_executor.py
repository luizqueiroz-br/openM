"""
Issue #81 — encadeamento automático de transforms (pipeline/chain).

Vanilla (zero deps): BFS/recursão sobre ``Transform.downstream_transforms``
com guard de profundidade (``max_chain_depth``, default 3, hard cap 10) e
``Set[entity_id] visited`` para defesa contra ciclos.

Ciclo de defesa (3 camadas, conforme decisão arquitetural):

1. **Boot-time**: ``TransformRegistry.detect_cycles()`` é chamado em
   ``create_app`` (após o registry ser populado pelos imports em
   ``openm.transforms``). Loga warning, não levanta exceção — defesa
   em profundidade.
2. **Runtime**: ``visited: Set[str]`` impede que a mesma entity_id
   seja re-executada num hop. Hops que tocam visited são pulados
   (``status='skipped_visited'``).
3. **Cap**: ``max_chain_depth`` (1-10) limita a profundidade do
   chain. 0 = executar apenas o hop 1 (sem chain).

Estado:

- ``_execute_chain`` retorna uma lista de hops com metadata
  ``[{depth, transform, input_id, output_ids, status, duration_ms,
  cache, error_message?}, ...]``. Cada hop inclui ``input_id`` e
  ``output_ids`` (a entity_id de cada entidade resultante) para
  que o frontend consiga mapear o que foi descoberto.
- ``_build_chain_plan`` retorna um plano estático (sem executar)
  usado pelo ``chain="dry_run"``.
- Persistência: cada hop chama ``gm.merge_entity`` e
  ``gm.create_relationship`` no Neo4j. Em testes, ``get_graph_manager``
  é mockado e aceita qualquer chamada.
- Audit: 1 entry consolidada ``ACTION_TRANSFORM_CHAIN_RUN`` por
  chain (não 1 por hop). Metadata inclui ``hops`` completa,
  ``chain_max_depth``, ``total_hops``, ``truncated`` (bool) e
  ``truncated_reason`` ("max_chain_depth" | "cycle" | "no_downstream"
  | "downstream_not_registered" | "downstream_input_type_mismatch").
- Cache (issue #84): hop 1 (executado em ``api/transforms.py``)
  consulta cache; se HIT, replays o payload cacheado como input
  do hop 2. Hops 2+ executam normal (cada um com seu próprio
  cache_ttl_seconds e ciclo de cache HIT/MISS).
- Rate limit (issue #89): 1 hit por request HTTP. Hops NÃO
  contam separadamente em v1 (limitação documentada).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set, Type

from .audit import ACTION_TRANSFORM_CHAIN_RUN, log_action
from .entity import ENTITY_CLASSES, Entity
from .transform import Transform
from .transform_cache import get_cached_result, set_cached_result

logger = logging.getLogger(__name__)


# Limites do param ``chain_max_depth`` (consistente com a API).
MIN_CHAIN_DEPTH = 1
MAX_CHAIN_DEPTH = 10
DEFAULT_CHAIN_DEPTH = 3


def _validate_chain_max_depth(value: Any) -> int:
    """Converte e valida ``chain_max_depth``. Levanta ``ValueError`` se inválido.

    Aceita ``int`` (coerce de string se for o caso). Default = 3.
    """
    if value is None:
        return DEFAULT_CHAIN_DEPTH
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"chain_max_depth inválido: {value!r}")
    if v < MIN_CHAIN_DEPTH or v > MAX_CHAIN_DEPTH:
        raise ValueError(
            f"chain_max_depth fora do range: {v} "
            f"(permitido: {MIN_CHAIN_DEPTH}-{MAX_CHAIN_DEPTH})"
        )
    return v


# ────────────────────────────────────────────────────────────────────
# Dry-run: planejar hops sem executar
# ────────────────────────────────────────────────────────────────────


def _build_chain_plan(
    start_transform_name: str,
    start_input_type: str,
    max_chain_depth: int,
    visited: Optional[Set[str]] = None,
    current_depth: int = 1,
) -> List[Dict[str, Any]]:
    """
    Constrói um plano estático de hops sem executar nada.

    Args:
        start_transform_name: nome do transform inicial (hop 1).
        start_input_type: tipo da entity que será entrada do hop 1
            (ex.: "Domain").
        max_chain_depth: limite máximo de profundidade.
        visited: ``Set`` interno para guardar transforms já visitados
            (defesa contra cycle). Não incluir no call externo.
        current_depth: profundidade atual (hop 1 = 1). Não incluir
            no call externo.

    Returns:
        Lista de dicts, um por hop planejado:
        ``{"hop": 1, "transform": "resolve_ip", "input_type":
        "Domain", "expected_outputs": ["IPAddress"]}``.
    """
    if visited is None:
        visited = set()
    if current_depth > max_chain_depth:
        return []
    if start_transform_name in visited:
        return []
    visited.add(start_transform_name)

    from .transform import TransformRegistry

    t_class = TransformRegistry.get(start_transform_name)
    if t_class is None:
        return []

    plan: List[Dict[str, Any]] = [{
        "hop": current_depth,
        "transform": start_transform_name,
        "input_type": start_input_type,
        "expected_outputs": list(getattr(t_class, "output_types", [])),
    }]

    # Recursão em cada downstream.
    for downstream_name in getattr(t_class, "downstream_transforms", []):
        # downstream_transforms é uma lista de nomes de transforms;
        # seus input_types podem ser múltiplos. Para o plano,
        # usamos o primeiro output_type do hop atual como
        # input_type "primário" do próximo hop (best effort).
        primary_output = (
            plan[-1]["expected_outputs"][0]
            if plan[-1]["expected_outputs"]
            else start_input_type
        )
        sub_plan = _build_chain_plan(
            downstream_name,
            primary_output,
            max_chain_depth,
            visited,
            current_depth + 1,
        )
        plan.extend(sub_plan)
    return plan


# ────────────────────────────────────────────────────────────────────
# Execução: BFS/recursão com cache, persistência e audit
# ────────────────────────────────────────────────────────────────────


def _persist_entities(
    gm: Any,
    entities: List[Entity],
    is_admin: bool,
    owner_id: Optional[int],
) -> None:
    """Persiste cada entity no Neo4j (best-effort)."""
    for ent in entities:
        if ent.created_by_user_id is None:
            ent.created_by_user_id = owner_id
        try:
            gm.merge_entity(ent)
        except Exception as exc:  # pragma: no cover - mock em testes
            logger.warning("Falha ao persistir entity %s: %s", ent.id, exc)


def _persist_relationships(
    gm: Any,
    relationships: List[Dict[str, Any]],
    is_admin: bool,
    owner_id: Optional[int],
) -> List[Dict[str, Any]]:
    """Persiste cada rel no Neo4j e retorna a lista das criadas."""
    out: List[Dict[str, Any]] = []
    for rel in relationships:
        try:
            created = gm.create_relationship(
                from_id=rel["from_id"],
                to_id=rel["to_id"],
                rel_type=rel["type"],
                properties=rel.get("properties", {}),
                user_id=owner_id,
                is_admin=is_admin,
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("Falha ao criar rel: %s", exc)
            created = False
        if created:
            out.append(rel)
    return out


def _execute_chain(
    *,
    initial_transform_name: str,
    initial_input_entity: Entity,
    initial_input_type: str,
    initial_output_entities: List[Entity],
    is_admin: bool,
    owner_id: Optional[int],
    user_id: Optional[int],
    max_chain_depth: int,
    force: bool = False,
) -> Dict[str, Any]:
    """Entry point "leve" do chain — usado pelo endpoint single.

    O hop 1 já foi executado pelo endpoint (em ``run_transform``),
    que passou os outputs (entities resultantes) para esta função.
    A função recursa em cada downstream configurado em
    ``downstream_transforms`` do transform do hop 1.

    Args:
        initial_transform_name: nome do transform executado no hop 1.
        initial_input_entity: entity de entrada do hop 1 (já
            persistida).
        initial_input_type: tipo da entity de entrada.
        initial_output_entities: entities resultantes do hop 1
            (usadas como inputs do hop 2).
        is_admin: se True, ownership é ignorado.
        owner_id: ID do user (analyst) para ownership.
        user_id: ID do user para audit.
        max_chain_depth: limite total de profundidade (incluindo
            o hop 1). Se <= 1, retorna sem chamar recursão.
        force: bypassa cache.

    Returns:
        Dict com:
          - ``hops``: lista de hops 2..N (NÃO inclui hop 1 — esse
            é logado pelo endpoint em ``ACTION_TRANSFORM_RUN``).
          - ``truncated``: bool.
          - ``truncated_reason``: str | None.
    """
    if max_chain_depth <= 1:
        return {
            "hops": [],
            "truncated": False,
            "truncated_reason": None,
        }

    from .transform import TransformRegistry

    initial_class = TransformRegistry.get(initial_transform_name)
    if initial_class is None:
        return {
            "hops": [],
            "truncated": True,
            "truncated_reason": "downstream_not_registered",
        }

    # visited: Set de entity_ids que já foram processadas neste
    # chain. Inclui o input do hop 1 para que o hop 2 não
    # re-processe o mesmo entity_id.
    visited: Set[str] = {initial_input_entity.id}

    # A primeira chamada de ``execute_chain_recursive`` recebe
    # ``transform_class=initial_class`` mas NÃO deve executá-lo
    # (o hop 1 já foi executado pelo endpoint). Ela deve
    # recursar imediatamente em cada downstream.
    #
    # Para evitar re-executar o transform inicial, saltamos o
    # step de execução usando a flag ``skip_execution=True`` no
    # primeiro hop (depth=2). O executor sabe que o input já é
    # output do hop 1.
    return _skip_and_recurse_into_downstream(
        transform_class=initial_class,
        initial_output_entities=initial_output_entities,
        is_admin=is_admin,
        owner_id=owner_id,
        user_id=user_id,
        max_chain_depth=max_chain_depth,
        force=force,
        visited_entities=visited,
        current_depth=2,
        hops_collector=[],
    )


def _skip_and_recurse_into_downstream(
    *,
    transform_class: Type[Transform],
    initial_output_entities: List[Entity],
    is_admin: bool,
    owner_id: Optional[int],
    user_id: Optional[int],
    max_chain_depth: int,
    force: bool,
    visited_entities: Set[str],
    current_depth: int,
    hops_collector: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Pula a execução do ``transform_class`` (hop 1 já foi feito) e recursa.

    Diferente de ``execute_chain_recursive`` que SEMPRE executa o
    transform no hop atual, esta função apenas usa
    ``initial_output_entities`` como inputs do próximo hop.
    """
    from .transform import TransformRegistry

    if current_depth > max_chain_depth:
        return {
            "hops": hops_collector,
            "truncated": True,
            "truncated_reason": "max_chain_depth",
        }

    next_hop_inputs: List[Entity] = []
    for ent in initial_output_entities:
        # NÃO adicionar a visited aqui — a próxima chamada de
        # ``execute_chain_recursive`` (depth=current_depth+1)
        # vai processar este entity e adicioná-lo a visited
        # quando a execução começar.
        next_hop_inputs.append(ent)

    if not next_hop_inputs:
        return {
            "hops": hops_collector,
            "truncated": True,
            "truncated_reason": "no_downstream",
        }

    truncated_flag = False
    truncated_reason_final: Optional[str] = None
    for downstream_name in getattr(
        transform_class, "downstream_transforms", []
    ):
        downstream_class = TransformRegistry.get(downstream_name)
        if downstream_class is None:
            continue
        matching_inputs = [
            e for e in next_hop_inputs
            if e.type in downstream_class.input_types
        ]
        if not matching_inputs:
            continue
        sub = execute_chain_recursive(
            transform_class=downstream_class,
            input_entities=matching_inputs,
            is_admin=is_admin,
            owner_id=owner_id,
            user_id=user_id,
            max_chain_depth=max_chain_depth,
            force=force,
            visited_entities=visited_entities,
            current_depth=current_depth + 1,
            hops_collector=hops_collector,
        )
        if sub.get("truncated"):
            truncated_flag = True
            if not truncated_reason_final:
                truncated_reason_final = sub.get("truncated_reason")

    return {
        "hops": hops_collector,
        "truncated": truncated_flag,
        "truncated_reason": truncated_reason_final,
    }


def execute_chain_recursive(
    *,
    transform_class: Type[Transform],
    input_entities: List[Entity],
    is_admin: bool,
    owner_id: Optional[int],
    user_id: Optional[int],
    max_chain_depth: int,
    force: bool = False,
    visited_entities: Optional[Set[str]] = None,
    current_depth: int = 1,
    hops_collector: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    BFS/recursão completa do chain — usa a assinatura esperada pela API.

    Este é o entry point usado por ``api/transforms.py``. Ele
    executa o transform atual em cada entity de ``input_entities``,
    persiste os resultados, e recursa em cada downstream até
    ``max_chain_depth`` ou enquanto houver outputs.

    Args:
        transform_class: classe do transform a executar NESTE hop.
        input_entities: lista de entities de entrada.
        is_admin: se True, ownership é ignorado.
        owner_id: ID do user (analyst) para ownership.
        user_id: ID do user para audit.
        max_chain_depth: limite total de profundidade (incluindo
            este hop).
        force: bypassa cache.
        visited_entities: ``Set[entity_id]`` para cycle detection.
        current_depth: profundidade atual (1 = primeiro hop).
        hops_collector: lista mutável onde os hops são acumulados
            (para o audit consolidado).

    Returns:
        Dict com ``hops`` (lista completa, incluindo este hop) e
        ``truncated`` / ``truncated_reason``.
    """
    from openm.utils.neo4j_client import get_graph_manager

    if hops_collector is None:
        hops_collector = []
    if visited_entities is None:
        visited_entities = set()

    # Trunca se já estamos no limite.
    if current_depth > max_chain_depth:
        return {
            "hops": hops_collector,
            "truncated": True,
            "truncated_reason": "max_chain_depth",
        }

    transform_name = transform_class.name
    gm = get_graph_manager()

    # Acumula outputs de todos os inputs deste hop para passar
    # ao próximo hop (BFS-like).
    next_hop_inputs: List[Entity] = []

    for entity in input_entities:
        # Cycle defense no nível de entity: se já processamos
        # esta entity concreta (em qualquer hop), pulamos com
        # status="skipped_visited". Hop 1 NUNCA cai aqui (o
        # visited só é populado com entity_ids, não transform
        # names).
        if entity.id in visited_entities:
            hops_collector.append({
                "depth": current_depth,
                "transform": transform_name,
                "input_id": entity.id,
                "input_value": entity.value,
                "input_type": entity.type,
                "output_ids": [],
                "status": "skipped_visited",
                "duration_ms": 0,
                "cache": "N/A",
            })
            continue
        visited_entities.add(entity.id)

        ttl = getattr(transform_class, "cache_ttl_seconds", 0) or 0
        cache_status = "MISS"
        cached_payload: Optional[Dict[str, Any]] = None
        if ttl > 0 and not force:
            cached_payload = get_cached_result(
                transform_name, entity.type, entity.value
            )
            if cached_payload is not None:
                cache_status = "HIT"

        hop: Dict[str, Any] = {
            "depth": current_depth,
            "transform": transform_name,
            "input_id": entity.id,
            "input_value": entity.value,
            "input_type": entity.type,
            "output_ids": [],
            "status": "success",
            "duration_ms": 0,
            "cache": cache_status,
        }
        t0 = time.perf_counter()

        try:
            if cached_payload is not None:
                # Cache HIT: replay payload.
                result_entities_dicts = cached_payload.get("entities", [])
                result_relationships = cached_payload.get(
                    "relationships", []
                )
                # Reconstruir Entity objects (best effort — apenas
                # para obter o id).
                for ed in result_entities_dicts:
                    ec = ENTITY_CLASSES.get(ed.get("type"))
                    if ec is None:
                        continue
                    ent_obj = ec(
                        value=ed.get("value", ""),
                        properties=ed.get("properties", {}),
                        entity_id=ed.get("id"),
                    )
                    next_hop_inputs.append(ent_obj)
                    hop["output_ids"].append(ent_obj.id)
                # Persistir (em cache HIT, como no endpoint single).
                if gm:
                    for ed in result_entities_dicts:
                        ec = ENTITY_CLASSES.get(ed.get("type"))
                        if ec is None:
                            continue
                        ent_obj = ec(
                            value=ed.get("value", ""),
                            properties=ed.get("properties", {}),
                            entity_id=ed.get("id"),
                        )
                        ent_obj.created_by_user_id = owner_id
                        try:
                            gm.merge_entity(ent_obj)
                        except Exception as exc:  # pragma: no cover
                            logger.warning(
                                "chain cache HIT merge falhou: %s", exc
                            )
                    _persist_relationships(
                        gm, result_relationships, is_admin, owner_id
                    )
            else:
                # Cache MISS: executar transform.
                transform_instance = transform_class()
                result = transform_instance.run(entity)
                metrics = getattr(result, "_metrics", None)
                if metrics is not None:
                    hop["duration_ms"] = metrics.duration_ms
                    hop["status"] = metrics.status
                    if metrics.error_message:
                        hop["error_message"] = metrics.error_message
                # Persistir input e outputs.
                if gm:
                    entity.created_by_user_id = owner_id
                    try:
                        gm.merge_entity(entity)
                    except Exception as exc:  # pragma: no cover
                        logger.warning(
                            "chain merge input falhou: %s", exc
                        )
                    _persist_entities(
                        gm, result.entities, is_admin, owner_id
                    )
                    _persist_relationships(
                        gm, result.relationships, is_admin, owner_id
                    )
                # Acumular outputs para o próximo hop.
                for new_ent in result.entities:
                    next_hop_inputs.append(new_ent)
                    hop["output_ids"].append(new_ent.id)
                # Salvar no cache.
                if ttl > 0 and not force and hop["status"] == "success":
                    response_payload = {
                        "input": entity.to_dict(),
                        "entities": [e.to_dict() for e in result.entities],
                        "relationships": list(result.relationships),
                    }
                    set_cached_result(
                        transform_name,
                        entity.type,
                        entity.value,
                        response_payload,
                        ttl,
                    )
        except Exception as exc:
            hop["status"] = "error"
            hop["error_message"] = str(exc)
            if not hop.get("duration_ms"):
                hop["duration_ms"] = round(
                    (time.perf_counter() - t0) * 1000.0, 2
                )

        hops_collector.append(hop)

    # Recursão nos downstream.
    if not next_hop_inputs:
        return {
            "hops": hops_collector,
            "truncated": True,
            "truncated_reason": "no_downstream",
        }

    if current_depth >= max_chain_depth:
        return {
            "hops": hops_collector,
            "truncated": True,
            "truncated_reason": "max_chain_depth",
        }

    from .transform import TransformRegistry

    truncated_flag = False
    truncated_reason_final: Optional[str] = None
    for downstream_name in getattr(
        transform_class, "downstream_transforms", []
    ):
        downstream_class = TransformRegistry.get(downstream_name)
        if downstream_class is None:
            continue
        # Filtrar inputs que combinam com input_types do
        # downstream.
        matching_inputs = [
            e for e in next_hop_inputs if e.type in downstream_class.input_types
        ]
        if not matching_inputs:
            continue
        sub = execute_chain_recursive(
            transform_class=downstream_class,
            input_entities=matching_inputs,
            is_admin=is_admin,
            owner_id=owner_id,
            user_id=user_id,
            max_chain_depth=max_chain_depth,
            force=force,
            visited_entities=visited_entities,
            current_depth=current_depth + 1,
            hops_collector=hops_collector,
        )
        if sub.get("truncated"):
            truncated_flag = True
            if not truncated_reason_final:
                truncated_reason_final = sub.get("truncated_reason")

    return {
        "hops": hops_collector,
        "truncated": truncated_flag,
        "truncated_reason": truncated_reason_final,
    }


def log_chain_audit(
    *,
    user_id: Optional[int],
    target_id: Optional[str],
    transform_name: str,
    entity_type: str,
    chain_max_depth: int,
    result: Dict[str, Any],
    metadata_extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Loga 1 entry consolidada ``ACTION_TRANSFORM_CHAIN_RUN``.

    Args:
        result: dict retornado por ``execute_chain_recursive``.
        metadata_extra: campos extras para o metadata (ex:
            ``cache`` do hop 1, ``duration_ms`` do hop 1).
    """
    meta: Dict[str, Any] = {
        "transform_name": transform_name,
        "entity_type": entity_type,
        "chain_max_depth": chain_max_depth,
        "total_hops": len(result.get("hops", [])),
        "hops": result.get("hops", []),
        "truncated": bool(result.get("truncated")),
        "truncated_reason": result.get("truncated_reason"),
    }
    if metadata_extra:
        meta.update(metadata_extra)
    try:
        log_action(
            action=ACTION_TRANSFORM_CHAIN_RUN,
            target_type="entity",
            target_id=target_id,
            user_id=user_id,
            metadata=meta,
        )
    except Exception as exc:  # pragma: no cover - audit é best-effort
        logger.warning("Falha ao logar audit chain: %s", exc)
