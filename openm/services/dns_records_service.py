"""
Servico de consulta de registros DNS.

Resolve multiplos tipos de registro (A, AAAA, MX, NS, TXT, CNAME, SOA)
usando dnspython. Sem API key (consulta DNS publico).
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

from openm.services.dns_service import reverse_dns as socket_reverse_dns

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
DEFAULT_NAMESERVERS = None  # usa resolvers do sistema
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _resolver(timeout: float = DEFAULT_TIMEOUT) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    return resolver


def _extract_rdata(record_type: str, rdata: Any) -> Dict[str, Any]:
    """Converte um objeto dns.rdata em dict serializavel."""
    rt = record_type.upper()
    if rt == "A":
        return {"record_value": str(rdata.address), "record_data": {"address": str(rdata.address)}}
    if rt == "AAAA":
        return {"record_value": str(rdata.address), "record_data": {"address": str(rdata.address)}}
    if rt == "MX":
        return {
            "record_value": str(rdata.exchange).rstrip("."),
            "record_data": {"exchange": str(rdata.exchange).rstrip("."), "priority": int(rdata.preference)},
            "record_priority": int(rdata.preference),
        }
    if rt in {"NS", "CNAME", "PTR"}:
        return {"record_value": str(rdata).rstrip("."), "record_data": {"target": str(rdata).rstrip(".")}}
    if rt == "TXT":
        # TXT pode ter multiplos strings; concatenamos com espaco para legibilidade.
        decoded = []
        for s in rdata.strings:
            if isinstance(s, bytes):
                decoded.append(str(s, encoding="utf-8", errors="replace"))
            else:
                decoded.append(str(s))
        text = " ".join(decoded)
        return {
            "record_value": text,
            "record_data": {"strings": decoded},
        }
    if rt == "SOA":
        return {
            "record_value": str(rdata.mname).rstrip("."),
            "record_data": {
                "mname": str(rdata.mname).rstrip("."),
                "rname": str(rdata.rname).rstrip("."),
                "serial": int(rdata.serial),
                "refresh": int(rdata.refresh),
                "retry": int(rdata.retry),
                "expire": int(rdata.expire),
                "minimum": int(rdata.minimum),
            },
        }
    return {"record_value": str(rdata), "record_data": {"raw": str(rdata)}}


def query_records(
    domain: str,
    record_types: Optional[List[str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """
    Consulta multiplos tipos de registro DNS para um dominio.

    Args:
        domain: nome de dominio a consultar (sem ponto final).
        record_types: lista de tipos (default: A, AAAA, MX, NS, TXT, CNAME, SOA).
        timeout: timeout por consulta em segundos.

    Returns:
        Tupla (canonical_domain, records).
        - canonical_domain: nome canonico obtido via CNAME chain, ou o
          proprio domain se nao houver CNAME.
        - records: lista de dicts com chaves: record_type, record_value,
          record_ttl, record_data, record_priority (se aplicavel),
          resolved_domain.
        Em falha total (resolver inacessivel, dominio inexistente) retorna
        (None, []).
    """
    if not domain or not isinstance(domain, str):
        return None, []

    target = domain.rstrip(".")
    record_types = [rt.upper() for rt in (record_types or DEFAULT_RECORD_TYPES)]
    resolver = _resolver(timeout=timeout)
    records: List[Dict[str, Any]] = []

    # Descobre CNAME chain primeiro para reportar canonical_domain.
    canonical_domain = target
    try:
        answer = resolver.resolve(target, "CNAME")
        if answer.rrset:
            cname_rdata = answer.rrset[0]
            canonical_domain = str(cname_rdata).rstrip(".")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
        pass
    except Exception as exc:
        logger.warning("Falha ao consultar CNAME de %s: %s", target, exc)

    for rt in record_types:
        try:
            answer = resolver.resolve(target, rt)
            if not answer.rrset:
                continue
            ttl = int(answer.rrset.ttl)
            for rdata in answer.rrset:
                extracted = _extract_rdata(rt, rdata)
                records.append(
                    {
                        "record_type": rt,
                        "record_ttl": ttl,
                        "resolved_domain": target,
                        "canonical_domain": canonical_domain,
                        **extracted,
                    }
                )
        except dns.resolver.NoAnswer:
            # Tipo de registro nao existe para este dominio: ignora silenciosamente.
            continue
        except dns.resolver.NXDOMAIN:
            logger.warning("Dominio %s nao existe (NXDOMAIN)", target)
            return None, []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            logger.warning("Falha ao consultar %s %s: %s", rt, target, exc)
            continue
        except Exception as exc:
            logger.warning("Erro inesperado ao consultar %s %s: %s", rt, target, exc)
            continue

    return canonical_domain, records


def reverse_dns_ptr(ip: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[Tuple[str, List[str], List[Dict[str, Any]]]]:
    """
    Resolve IP para hostname PTR e consulta registros DNS desse hostname.

    Args:
        ip: endereco IPv4 ou IPv6.
        timeout: timeout em segundos.

    Returns:
        Tupla (hostname, aliases, records) ou None se nao houver PTR.
        records sao os registros DNS consultados no hostname descoberto.
    """
    result = socket_reverse_dns(ip, timeout=timeout)
    if not result:
        return None

    hostname, aliases = result
    _, records = query_records(hostname, timeout=timeout)
    return hostname, list(aliases or []), records
