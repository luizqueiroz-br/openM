"""
Health check centralizado dos services com API key (issue #79).

Para cada service registrado (shodan, virustotal, hunter, abuseipdb,
hibp, ...) consulta um endpoint leve para validar a chave e a
disponibilidade do servico externo. Retorna status padronizado que o
endpoint admin ``GET /api/services/health`` consome.

Status possiveis:
    - ``ok``         service respondeu com 200 e chave valida.
    - ``error``      service respondeu com 4xx/5xx ou chave invalida.
    - ``unchecked``  sem chave configurada ou service offline.
"""
import logging
import time
from typing import Any, Dict, Optional

import requests

from openm.core.transform import TransformRegistry
from openm.models.api_key import ApiKey

logger = logging.getLogger(__name__)


# Cache em memoria com TTL curto (5 min) para evitar consumir quota
# dos services externos a cada chamada do health endpoint.
_HEALTH_CACHE: dict[str, tuple[float, Dict[str, Any]]] = {}
_HEALTH_CACHE_TTL_SECONDS = 300


def _cached_health(service_name: str) -> Optional[Dict[str, Any]]:
    """Retorna health cacheado se ainda nao expirou."""
    cached = _HEALTH_CACHE.get(service_name)
    if not cached:
        return None
    expires_at, payload = cached
    if expires_at < time.time():
        return None
    return payload


def _store_health(service_name: str, payload: Dict[str, Any]) -> None:
    """Guarda health no cache com TTL."""
    _HEALTH_CACHE[service_name] = (time.time() + _HEALTH_CACHE_TTL_SECONDS, payload)


def _get_active_key(service_name: str) -> Optional[ApiKey]:
    """Retorna a chave ativa mais recente do service, ou None."""
    return (
        ApiKey.query.filter_by(service_name=service_name, is_active=True)
        .order_by(ApiKey.updated_at.desc())
        .first()
    )


# Endpoints de health check por service (GETs leves que validam a chave).
# Caso o endpoint retorne dados relevantes (ex: credits_remaining), sao
# extraidos no payload final.
_HEALTH_ENDPOINTS: dict[str, Dict[str, Any]] = {
    "shodan": {
        "url": "https://api.shodan.io/api-info",
        "method": "GET",
        "params_key": "key",
        "key_header": None,
        "extract": lambda data: {
            "credits_remaining": data.get("usage_limits", {}).get("available_credits")
            if isinstance(data.get("usage_limits"), dict)
            else None,
            "plan": data.get("plan"),
        },
    },
    "virustotal": {
        "url": None,  # Construido dinamicamente com a chave
        "method": "GET",
        "key_header": "x-apikey",
        "extract": lambda data: {
            "user": (data.get("data") or {}).get("attributes", {}).get("user")
            if isinstance(data.get("data"), dict)
            else None,
        },
    },
    "hunter": {
        "url": "https://api.hunter.io/v2/account",
        "method": "GET",
        "key_header": None,
        "params_key": "api_key",
        "extract": lambda data: {
            "plan_name": (data.get("data") or {}).get("plan_name"),
            "requests_limit": (data.get("data") or {}).get("requests_limit"),
            "requests_used": (data.get("data") or {}).get("requests_used"),
        },
    },
    "abuseipdb": {
        "url": "https://api.abuseipdb.com/api/v2/check",
        "method": "GET",
        "key_header": "Key",
        "params": {"ipAddress": "127.0.0.1"},
        "extract": lambda data: {
            "usage": (data.get("data") or {}).get("usage"),
        },
    },
    "hibp": {
        "url": "https://haveibeenpwned.com/api/v3/breaches",
        "method": "GET",
        "key_header": "hibp-api-key",
        "extract": lambda data: None,
    },
}


def _ping_service(service_name: str) -> Dict[str, Any]:
    """Faz ping ao endpoint de health do service e retorna payload."""
    cfg = _HEALTH_ENDPOINTS.get(service_name)
    if cfg is None:
        return {
            "status": "unchecked",
            "key_valid": False,
            "message": f"Service '{service_name}' nao tem health check configurado",
        }

    api_key_obj = _get_active_key(service_name)
    if api_key_obj is None:
        return {
            "status": "unchecked",
            "key_valid": False,
            "message": "Nenhuma chave ativa configurada",
        }

    api_key = api_key_obj.key_value

    # VirusTotal requer endpoint com a propria chave na URL.
    if service_name == "virustotal":
        url = f"https://www.virustotal.com/api/v3/users/{api_key}"
    else:
        url = cfg["url"]

    headers = {"User-Agent": "OpenM-HealthCheck/1.0", "Accept": "application/json"}
    if cfg.get("key_header"):
        headers[cfg["key_header"]] = api_key

    params: Dict[str, Any] = {}
    if cfg.get("params_key"):
        params[cfg["params_key"]] = api_key
    if cfg.get("params"):
        params.update(cfg["params"])

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
    except requests.RequestException as exc:
        return {
            "status": "error",
            "key_valid": False,
            "message": f"Falha de rede: {exc}",
        }

    if resp.status_code in (401, 403):
        return {
            "status": "error",
            "key_valid": False,
            "message": f"Chave invalida ou sem acesso (HTTP {resp.status_code})",
        }
    if resp.status_code == 429:
        return {
            "status": "error",
            "key_valid": True,
            "message": "Rate-limit atingido",
        }
    if resp.status_code != 200:
        return {
            "status": "error",
            "key_valid": False,
            "message": f"HTTP {resp.status_code}",
        }

    payload: Dict[str, Any] = {"status": "ok", "key_valid": True}
    try:
        data = resp.json()
    except ValueError:
        return {**payload, "message": "Resposta nao-JSON"}

    extract = cfg.get("extract")
    if extract:
        try:
            extra = extract(data) or {}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Health extract falhou para %s: %s", service_name, exc)
            extra = {}
        payload.update({k: v for k, v in extra.items() if v is not None})

    return payload


def get_service_health(service_name: str, *, force: bool = False) -> Dict[str, Any]:
    """
    Retorna o status de um service.

    Args:
        service_name: nome canonico do service (ex: "shodan").
        force: se True, ignora cache.

    Returns:
        Dict com chaves: status, key_valid, message (opcional), e
        campos extras especificos (ex: credits_remaining).
    """
    if not force:
        cached = _cached_health(service_name)
        if cached is not None:
            return {**cached, "cached": True}

    payload = _ping_service(service_name)
    _store_health(service_name, payload)
    return payload


def get_all_services_health(*, force: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Retorna o health check para todos os services registrados.

    Combina os services que tem health endpoint configurado
    (``_HEALTH_ENDPOINTS``) com os ``service_name`` declarados pelos
    transforms registrados, garantindo que nenhum service com chave
    ativa fica sem diagnostico.

    Returns:
        Dict ``{service_name: health_payload}``.
    """
    services = set(_HEALTH_ENDPOINTS.keys())
    # Inclui tambem services declarados via transforms (sem health
    # endpoint dedicado). Para esses, retorna ``unchecked``.
    try:
        transforms = TransformRegistry.list_services()
        services.update(t["service_name"] for t in transforms)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Falha ao listar services do registry: %s", exc)

    out: Dict[str, Dict[str, Any]] = {}
    for name in sorted(services):
        out[name] = get_service_health(name, force=force)
    return out
