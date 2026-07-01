"""
Cache de resultados de transform com TTL por transform.

Camada fina sobre ``SqliteCache`` focada em payloads de transform
(entities + relationships já serializados como dict). Cada transform
declara seu TTL via ``cache_ttl_seconds`` — ``0`` desabilita o cache.

Cache key:
    ``{transform_name}:{entity_type}:{value_normalized}``

Onde ``value_normalized`` é o ``entity.value`` em lowercase stripped.
Isso garante que ``Example.com`` e ``example.com`` batem no mesmo slot.

Schema do payload cacheado (JSON):
    {
        "input": {...},            # entity serializada (to_dict)
        "entities": [{...}, ...],  # novas entidades (to_dict cada)
        "relationships": [{...}, ...]
    }

Mesmo formato da resposta de ``/api/run_transform``, então o endpoint
pode cachear a resposta inteira e retornar direto no HIT.
"""

import logging
import sqlite3  # noqa: F401 — referenced for type/docs; connection lives in services/sqlite_cache
import threading  # noqa: F401 — referenced for type/docs; lock lives in services/sqlite_cache
from typing import Any, Dict, Optional

from openm.services.sqlite_cache import SqliteCache

logger = logging.getLogger(__name__)


# Thread-safety (issue #87 — batch transform execution):
# A classe ``SqliteCache`` mantém UMA conexão persistente com
# ``check_same_thread=False`` + ``PRAGMA journal_mode=WAL`` e
# serializa get/set/delete via ``threading.Lock``. Isso permite
# que múltiplos workers (até ``OPENM_BATCH_MAX_WORKERS``) do endpoint
# ``/api/run_transform_batch`` usem o mesmo singleton do cache
# simultaneamente sem ``SQLITE_MISUSE``. O singleton
# ``_default_cache`` continua sendo compartilhado — todas as calls
# do cache transform caem nele e são protegidas internamente.
#
# API pública deste módulo (não quebrar):
#   - get_cached_result(transform_name, entity_type, value) -> dict|None
#   - set_cached_result(transform_name, entity_type, value, payload, ttl)
#   - clear_cache_for(transform_name, entity_type, value)
#   - make_cache_key(transform_name, entity_type, value) -> str
#   - make_response_payload(entity, result_entities, result_relationships)


# Singleton para evitar abrir múltiplas conexões SQLite na mesma instância.
_default_cache: Optional[SqliteCache] = None


def _get_cache() -> SqliteCache:
    """Retorna a instância singleton do cache."""
    global _default_cache
    if _default_cache is None:
        _default_cache = SqliteCache()
    return _default_cache


def make_cache_key(transform_name: str, entity_type: str, value: str) -> str:
    """
    Constroi a chave de cache para um (transform, entity) específico.

    Normalização:
        - transform_name: lowercase, stripped
        - entity_type: stripped (já vem canônico do ENTITY_CLASSES)
        - value: lowercase, stripped

    Args:
        transform_name: nome do transform (ex: 'whois_lookup').
        entity_type: tipo da entidade (ex: 'Domain').
        value: valor da entidade (ex: 'example.com').

    Returns:
        Chave única no formato ``transform_name:entity_type:value``.
    """
    tn = (transform_name or "").strip().lower()
    et = (entity_type or "").strip()
    v = (value or "").strip().lower()
    return f"{tn}:{et}:{v}"


def get_cached_result(
    transform_name: str,
    entity_type: str,
    value: str,
) -> Optional[Dict[str, Any]]:
    """
    Busca resultado cacheado para (transform, entity_type, value).

    Retorna o dict de resposta (mesmo formato de /api/run_transform) ou
    None se ausente/expirado.

    Args:
        transform_name: nome do transform.
        entity_type: tipo da entidade.
        value: valor da entidade.

    Returns:
        Dict com 'input', 'entities', 'relationships' ou None.
    """
    cache = _get_cache()
    key = make_cache_key(transform_name, entity_type, value)
    return cache.get(key)


def set_cached_result(
    transform_name: str,
    entity_type: str,
    value: str,
    payload: Dict[str, Any],
    ttl_seconds: int,
) -> None:
    """
    Persiste resultado de transform no cache.

    Args:
        transform_name: nome do transform.
        entity_type: tipo da entidade.
        value: valor da entidade.
        payload: dict de resposta (mesmo formato de /api/run_transform).
        ttl_seconds: TTL em segundos.

    Silencia erros de IO para não derrubar a request por falha de cache.
    """
    if ttl_seconds <= 0:
        return
    key = make_cache_key(transform_name, entity_type, value)
    try:
        cache = _get_cache()
        cache.set(key, payload, ttl_seconds=ttl_seconds)
    except Exception as exc:  # pragma: no cover - defensivo
        logger.warning("Falha ao salvar cache para %s: %s", key, exc)


def clear_cache_for(transform_name: str, entity_type: str, value: str) -> None:
    """
    Remove entrada específica do cache. Útil para testes ou admin tools.
    """
    cache = _get_cache()
    key = make_cache_key(transform_name, entity_type, value)
    cache.delete(key)


def make_response_payload(entity, result_entities, result_relationships):
    """
    Constroi o payload de resposta no formato de /api/run_transform.

    Usado tanto pelo endpoint quanto pelo cache (mesma estrutura).
    """
    return {
        "input": entity.to_dict(),
        "entities": [e.to_dict() for e in result_entities],
        "relationships": list(result_relationships),
    }
