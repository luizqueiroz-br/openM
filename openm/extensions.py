from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Instâncias globais de extensões Flask, inicializadas em app.py

db = SQLAlchemy()

# Limiter configurado com storage em memória (Redis pode ser usado em produção)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)
