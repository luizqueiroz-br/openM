"""
SSL/TLS certificate inspection service.

Conexão TLS direta via stdlib (ssl + socket). Sem dependências extras.
Usado pelo SslCertTransform para extrair issuer, SAN, validade,
fingerprint e metadados do certificado de um domínio.
"""

import hashlib
import logging
import socket
import ssl
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10.0


def _format_name(name_tuple) -> Dict[str, str]:
    """
    Converte ((commonName, value), (organizationName, value), ...) em
    dict simples.
    """
    if not name_tuple:
        return {}
    out = {}
    for key, value in name_tuple:
        # chave vem em formato 'commonName' ou 'organizationName' etc.
        short = key.replace("Name", "").lower() if key else "field"
        # Evita colisão se houver múltiplos campos do mesmo tipo
        if short in out:
            out[f"{short}_alt"] = value
        else:
            out[short] = value
    return out


def inspect_ssl(
    domain: str,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[Dict[str, Any]]:
    """
    Conecta via TLS no (domain:port) e extrai metadados do certificado.

    Args:
        domain: domínio alvo (ex: example.com).
        port: porta TLS (default 443).
        timeout: timeout da operação em segundos.

    Returns:
        Dict com campos:
            issuer (dict), subject (dict), san_domains (list),
            valid_from (str), valid_until (str),
            fingerprint_sha256 (str), signature_algorithm (str),
            version (int), serial_number (str), raw_pem (str),
            source ("ssl").

        Retorna None em qualquer falha (timeout, conexão recusada,
        sem TLS, domínio sem cert, etc).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # queremos inspecionar mesmo se houver mismatch
    ctx.verify_mode = ssl.CERT_NONE

    socket.setdefaulttimeout(timeout)
    try:
        with socket.create_connection((domain, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as tls_sock:
                der_bytes = tls_sock.getpeercert(binary_form=True)
                cert_dict = tls_sock.getpeercert()
    except (socket.timeout, OSError, ssl.SSLError, ConnectionError) as exc:
        logger.warning("SSL inspect falhou para %s:%d: %s", domain, port, exc)
        return None
    finally:
        socket.setdefaulttimeout(None)

    if not cert_dict or not der_bytes:
        return None

    # SAN (Subject Alternative Names) — pode estar em 'subjectAltName'
    san_entries = cert_dict.get("subjectAltName", []) or []
    san_domains: List[str] = []
    for entry in san_entries:
        # entry = (kind, value) — kind='DNS' ou 'IP Address'
        if not isinstance(entry, tuple) or len(entry) != 2:
            continue
        kind, value = entry
        if kind == "DNS" and isinstance(value, str):
            san_domains.append(value.lower().strip())
        # Ignora IP entries (kind == "IP Address") — fora de escopo deste transform

    # Issuer / Subject são tuples of tuples ((field, value), ...)
    issuer = _format_name(cert_dict.get("issuer", ()))
    subject = _format_name(cert_dict.get("subject", ()))

    # Fingerprint SHA-256 do cert em formato DER
    fingerprint = hashlib.sha256(der_bytes).hexdigest()

    # PEM encoding (opcional — útil para debug)
    pem = ssl.DER_cert_to_PEM_cert(der_bytes)

    return {
        "issuer": issuer,
        "subject": subject,
        "san_domains": san_domains,
        "valid_from": cert_dict.get("notBefore"),
        "valid_until": cert_dict.get("notAfter"),
        "fingerprint_sha256": fingerprint,
        "version": cert_dict.get("version"),
        "serial_number": cert_dict.get("serialNumber"),
        "raw_pem": pem,
        "source": "ssl",
    }


def extract_san_domains(cert_data: Dict[str, Any]) -> List[str]:
    """
    Extrai lista de SAN domains de um payload retornado por inspect_ssl.

    Filtra wildcards (*.foo.example.com → foo.example.com) e remove
    duplicatas. Sempre retorna lista ordenada.
    """
    san = cert_data.get("san_domains") or []
    seen = set()
    for raw in san:
        if not raw:
            continue
        candidate = raw.strip().lower()
        if candidate.startswith("*."):
            candidate = candidate[2:]
        if candidate:
            seen.add(candidate)
    return sorted(seen)
