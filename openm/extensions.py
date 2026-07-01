from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter

# Instâncias globais de extensões Flask, inicializadas em app.py

db = SQLAlchemy()


def _user_service_key():
    """
    Resolved late to avoid circular import: rate_limiter imports
    ``limiter`` from this module.

    The actual implementation lives in :mod:`openm.core.rate_limiter`
    under the same name ``user_service_key``. We forward to it here
    so the Limiter can call it without a hard import cycle.
    """
    from openm.core.rate_limiter import user_service_key
    return user_service_key()


# Limiter configurado com:
#  - key_func por user+service (fallback IP para endpoints sem auth).
#  - default_limits globais (mantidos por compatibilidade).
#  - headers_enabled=True para emitir X-RateLimit-Limit/Remaining/Reset
#    em TODAS as responses (issue #89).
#  - strategy="moving-window" para evitar burst no boundary do window
#    (anti-burst vs default fixed-window).
#
# Os limites por service são aplicados por decorator (@limiter.limit)
# nas rotas relevantes; este default_limits é fallback para rotas sem
# decorator explícito.
limiter = Limiter(
    key_func=_user_service_key,
    default_limits=["200 per day", "50 per hour"],
    headers_enabled=True,
    strategy="moving-window",
)
