import json
import logging
import os
import urllib.error
import urllib.request
from typing import List, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_RESULTS = 200
CRTSH_ENDPOINT = "https://crt.sh/"

# Cap configurável via env, sem expor o número como constante hardcoded.
_MAX_RESULTS_ENV = os.environ.get("OPENM_CRTSH_MAX_RESULTS")
DEFAULT_MAX_RESULTS = int(_MAX_RESULTS_ENV) if _MAX_RESULTS_ENV else DEFAULT_MAX_RESULTS


def query_crtsh(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[List[dict]]:
    """
    Query crt.sh Certificate Transparency logs para um domínio.

    Endpoint público:
        https://crt.sh/?q=%25.{domain}&output=json

    Args:
        domain: domínio a buscar (ex: example.com).
        timeout: timeout da request HTTP em segundos.

    Returns:
        Lista de dicts com campos ``name_value``, ``not_before``,
        ``not_after``, ``issuer_name``, etc. Retorna ``None`` em caso
        de falha de rede, HTTP error, JSON inválido ou IP inválido.
        Retorna lista vazia se nenhum resultado encontrado.
    """
    url = f"{CRTSH_ENDPOINT}?q=%25.{domain}&output=json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "openm-osint/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        logger.warning("crt.sh falhou para %s: %s", domain, exc)
        return None

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        logger.warning("crt.sh retornou JSON inválido para %s: %s", domain, exc)
        return None

    if not isinstance(data, list):
        return []

    return data


def extract_subdomains(
    entries: List[dict],
    parent_domain: str,
    max_results: int = DEFAULT_MAX_RESULTS,
) -> List[str]:
    """
    Extrai e deduplica subdomínios distintos de uma lista de entries do crt.sh.

    Cada entry tem ``name_value`` que pode conter múltiplos domínios
    separados por quebra de linha. Wildcards (``*.foo.example.com``)
    são normalizados para ``foo.example.com`` (sem o ``*.``).

    Args:
        entries: lista de dicts retornados por ``query_crtsh``.
        parent_domain: domínio pai para filtrar (evita entries de outros
            domínios que aparecem por coincidência em CT logs).
        max_results: limite máximo de subdomínios retornados.

    Returns:
        Lista ordenada de subdomínios distintos, sem o domínio pai.
        Se o próprio parent_domain aparecer (válido em CT), também
        é incluído.
    """
    seen = set()
    parent = parent_domain.lower().strip()

    for entry in entries[:max_results * 2]:  # margem para dedup
        name_value = entry.get("name_value") or ""
        for raw in name_value.splitlines():
            candidate = raw.strip().lower()
            if not candidate:
                continue
            # Remove wildcard prefix
            if candidate.startswith("*."):
                candidate = candidate[2:]
            if not candidate or candidate == parent:
                continue
            # Filtrar apenas domínios que terminam com o parent
            # (evita CT noise de outros domínios)
            if not (candidate == parent or candidate.endswith("." + parent)):
                continue
            seen.add(candidate)

    return sorted(seen)[:max_results]
