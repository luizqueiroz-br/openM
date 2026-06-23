import os
from dataclasses import dataclass
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env, se existir.
load_dotenv()


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
