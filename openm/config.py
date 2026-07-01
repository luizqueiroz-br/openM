import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env, se existir.
load_dotenv()


def _int_env(name: str, default: int, *, cap: int | None = None) -> int:
    """
    Lê uma env var como int com fallback seguro.

    - Se a env var não estiver setada ou vier vazia → ``default``.
    - Se vier inválida (não-conversível) → ``default`` (best-effort;
      não derruba a app por config ruim).
    - Se ``cap`` for fornecido e o valor exceder → clampa em ``cap``
      (defesa contra valores absurdos via env).

    Usado por ``Config`` para ``BATCH_*`` (issue #87) e qualquer
    outro int configurável que se queira blindar.
    """
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw.strip())
    except (ValueError, TypeError):
        return default
    if cap is not None and value > cap:
        return cap
    if value < 0:
        return default
    return value


@dataclass
class Config:
    """Configuração base da aplicação OpenM."""

    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-key")

    # PostgreSQL via SQLAlchemy
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL", "postgresql://openm:openm123@postgres:5432/openm"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # Neo4j
    NEO4J_URI: str = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
    NEO4J_USER: str = os.environ.get("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.environ.get("NEO4J_PASSWORD", "openm123")

    # Rate limiting
    RATELIMIT_STORAGE_URI: str = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

    # === Issue #87: Bulk/batch transform execution ===
    # Tamanho do ThreadPoolExecutor usado em /api/run_transform_batch.
    # Cap 50 para evitar storm de threads (cada worker abre app context
    # e potencialmente chama Neo4j / API externa).
    BATCH_MAX_WORKERS: int = _int_env("OPENM_BATCH_MAX_WORKERS", 5, cap=50)
    # Timeout global do batch (as_completed timeout). Se exceder, os
    # futures pendentes viram status="timeout" no results. Cap 600s
    # (10 min) — bem acima de qualquer transform individual.
    BATCH_TIMEOUT_SECONDS: int = _int_env("OPENM_BATCH_TIMEOUT", 60, cap=600)
    # Hard cap de entities por batch. 413 (Payload Too Large) se
    # exceder. Cap 1000 — limite razoável para uso legítimo e que
    # não sobrecarrega Neo4j (cada entity vira N calls de merge).
    BATCH_MAX_ENTITIES: int = _int_env("OPENM_BATCH_MAX_ENTITIES", 100, cap=1000)

    # === Issue #89: Rate limiting per service (per-user) ===
    # Limites default por service externo (configurável via env).
    # Formato: "N/period" (period: second|minute|hour|day|month|year)
    # Chave "__internal__" é usada para transforms sem service_name
    # declarado (ex: whois, geoip, resolve_ip).
    RATELIMIT_SERVICES: dict = field(
        default_factory=lambda: {
            "shodan":         os.environ.get("OPENM_RATE_LIMIT_SHODAN",         "10/hour"),
            "virustotal":     os.environ.get("OPENM_RATE_LIMIT_VIRUSTOTAL",     "4/minute"),
            "hunter":         os.environ.get("OPENM_RATE_LIMIT_HUNTER",         "10/day"),
            "hibp":           os.environ.get("OPENM_RATE_LIMIT_HIBP",           "10/minute"),
            "urlscan":        os.environ.get("OPENM_RATE_LIMIT_URLSCAN",        "100/day"),
            "abuseipdb":      os.environ.get("OPENM_RATE_LIMIT_ABUSEIPDB",      "1000/day"),
            "securitytrails": os.environ.get("OPENM_RATE_LIMIT_SECURITYTRAILS", "5/day"),
            "emailrep":       os.environ.get("OPENM_RATE_LIMIT_EMAILREP",       "100/day"),
            "threat_intel":   os.environ.get("OPENM_RATE_LIMIT_THREAT_INTEL",   "10/hour"),
            "__internal__":   os.environ.get("OPENM_RATE_LIMIT_INTERNAL",       "100/hour"),
        }
    )

    # CORS liberado para uso local
    CORS_ORIGINS: str = os.environ.get("CORS_ORIGINS", "*")

    # === Auth / JWT ===
    # JWT_SECRET: reutiliza SECRET_KEY se não houver um específico para auth.
    JWT_SECRET: str = os.environ.get("JWT_SECRET", os.environ.get("SECRET_KEY", "dev-secret-key"))
    JWT_ALGORITHM: str = os.environ.get("JWT_ALGORITHM", "HS256")

    # TTLs (em minutos para access, dias para refresh).
    JWT_ACCESS_TTL_MINUTES: int = int(os.environ.get("JWT_ACCESS_TTL_MINUTES", "15"))
    JWT_REFRESH_TTL_DAYS: int = int(os.environ.get("JWT_REFRESH_TTL_DAYS", "7"))

    # Issuer / audience incluídos nos claims.
    JWT_ISSUER: str = os.environ.get("JWT_ISSUER", "openm")
    JWT_AUDIENCE: str = os.environ.get("JWT_AUDIENCE", "openm-api")

    # Política de registro: padrão FALSE em produção.
    # Para primeiro deploy/local, defina ALLOW_REGISTRATION=true.
    ALLOW_REGISTRATION: bool = os.environ.get("ALLOW_REGISTRATION", "false").lower() in (
        "1",
        "true",
        "yes",
    )

    # === Cookies httpOnly para auth (issue #13) ===
    # Nomes dos cookies usados pelo /api/auth/*.
    JWT_COOKIE_ACCESS_NAME: str = os.environ.get("JWT_COOKIE_ACCESS_NAME", "openm_access")
    JWT_COOKIE_REFRESH_NAME: str = os.environ.get("JWT_COOKIE_REFRESH_NAME", "openm_refresh")

    # Secure flag: True em produção (HTTPS) para o navegador só enviar os
    # cookies em conexões seguras. False em dev local (HTTP).
    JWT_COOKIE_SECURE: bool = os.environ.get("JWT_COOKIE_SECURE", "false").lower() in (
        "1",
        "true",
        "yes",
    )

    # Domínio opcional dos cookies (None = só o host atual).
    JWT_COOKIE_DOMAIN: str | None = os.environ.get("JWT_COOKIE_DOMAIN") or None

    # === Audit log (issue #4) ===
    # Retenção em dias. Logs mais antigos que esse valor são removidos pelo
    # comando CLI ``flask audit purge --days N`` (que usa esse valor como
    # default). 0 desabilita a sugestão de retenção — o purge nunca é auto.
    AUDIT_LOG_RETENTION_DAYS: int = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", "90"))


# Materializa o dict no nível da classe para que ``app.config.from_object``
# (Flask) descubra o atributo via ``dir(Config)``. Dataclass fields com
# ``default_factory`` são aplicados apenas em instâncias, não na classe
# — sem esta atribuição, ``app.config["RATELIMIT_SERVICES"]`` ficaria
# vazio após ``app.config.from_object(Config)``.
Config.RATELIMIT_SERVICES = {
    "shodan":         os.environ.get("OPENM_RATE_LIMIT_SHODAN",         "10/hour"),
    "virustotal":     os.environ.get("OPENM_RATE_LIMIT_VIRUSTOTAL",     "4/minute"),
    "hunter":         os.environ.get("OPENM_RATE_LIMIT_HUNTER",         "10/day"),
    "hibp":           os.environ.get("OPENM_RATE_LIMIT_HIBP",           "10/minute"),
    "urlscan":        os.environ.get("OPENM_RATE_LIMIT_URLSCAN",        "100/day"),
    "abuseipdb":      os.environ.get("OPENM_RATE_LIMIT_ABUSEIPDB",      "1000/day"),
    "securitytrails": os.environ.get("OPENM_RATE_LIMIT_SECURITYTRAILS", "5/day"),
    "emailrep":       os.environ.get("OPENM_RATE_LIMIT_EMAILREP",       "100/day"),
    "threat_intel":   os.environ.get("OPENM_RATE_LIMIT_THREAT_INTEL",   "10/hour"),
    "__internal__":   os.environ.get("OPENM_RATE_LIMIT_INTERNAL",       "100/hour"),
}
