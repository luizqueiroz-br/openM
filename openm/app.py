"""Factory e aplicação Flask do OpenM."""

from flask import Flask, jsonify
from flask_cors import CORS

from openm.config import Config
from openm.extensions import db, limiter
from openm.api import (
    entities_bp,
    graph_bp,
    investigations_bp,
    keys_bp,
    transforms_bp,
    auth_bp,
)
from openm.frontend.routes import frontend_bp

# Importa models para garantir que db.create_all() registre as tabelas
# (incluindo users e revoked_tokens usadas pela autenticação JWT).
from openm import models  # noqa: E402, F401

# Importa transforms para registro automático no TransformRegistry.
# Deve ocorrer antes de as rotas consultarem quais transforms existem.
from openm.transforms import (  # noqa: E402, F401
    CheckFraudEmailTransform,
    ResolveIPTransform,
)


def create_app(config_class=Config) -> Flask:
    """Application factory do OpenM."""
    app = Flask(
        __name__,
        template_folder="frontend/templates",
        static_folder="frontend/static",
    )
    app.config.from_object(config_class)

    # Inicializa extensões
    db.init_app(app)
    limiter.init_app(app)

    # CORS liberado para uso local
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Registra blueprints da API
    app.register_blueprint(entities_bp)
    app.register_blueprint(transforms_bp)
    app.register_blueprint(graph_bp)
    app.register_blueprint(investigations_bp)
    app.register_blueprint(keys_bp)
    app.register_blueprint(auth_bp)

    # Páginas HTML (login/registro/logout)
    app.register_blueprint(frontend_bp)

    @app.route("/")
    def index():
        """Página principal do OpenM (protegida — exige sessão)."""
        from flask import render_template

        from openm.core.auth import login_required_page

        @login_required_page
        def _render():
            return render_template("index.html")

        return _render()

    @app.route("/health")
    def health():
        """Healthcheck simples."""
        return jsonify({"status": "ok"})

    # Cria tabelas do PostgreSQL via CLI ou explicitamente; não executa
    # automaticamente aqui para evitar conexão ao importar em testes.
    return app


# Instância padrão usada pelo `flask run`.
app = create_app()
