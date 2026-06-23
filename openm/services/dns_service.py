import socket
import logging
from typing import List

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
