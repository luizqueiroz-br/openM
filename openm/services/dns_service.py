import socket
import logging
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


def resolve_domain(domain: str, timeout: float = 5.0) -> List[str]:
    """
    Resolve um domínio para seus endereços IPv4.

    Usa socket.gethostbyname_ex, que retorna o nome canonizado
    e uma lista de IPs associados ao domínio.

    Args:
        domain: nome de domínio a ser resolvido.
        timeout: timeout da operação DNS em segundos.

    Returns:
        Lista de endereços IP (strings).
    """
    socket.setdefaulttimeout(timeout)
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        return ip_list
    except socket.gaierror as exc:
        logger.warning("Falha ao resolver domínio %s: %s", domain, exc)
        return []
    finally:
        socket.setdefaulttimeout(None)


def reverse_dns(ip: str, timeout: float = 5.0) -> Optional[Tuple[str, List[str]]]:
    """
    Resolve um IP para seu nome canônico via registro PTR (reverse DNS).

    Usa socket.gethostbyaddr, que retorna o hostname canonizado
    e uma lista de aliases do IP.

    Args:
        ip: endereço IPv4 ou IPv6.
        timeout: timeout da operação DNS em segundos.

    Returns:
        Tupla (hostname, aliases) ou None se a resolução falhar
        (sem PTR, timeout, IP inválido, etc).
    """
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, aliases = socket.gethostbyaddr(ip)
        return hostname, list(aliases or [])
    except (socket.herror, socket.gaierror, socket.timeout, OSError) as exc:
        logger.warning("Falha no reverse DNS de %s: %s", ip, exc)
        return None
    finally:
        socket.setdefaulttimeout(None)
