"""Factory e aplicação Flask do OpenM."""

from flask import Flask, jsonify
from flask_cors import CORS
from flask_migrate import Migrate

from openm.config import Config
from openm.extensions import db, limiter
from openm.api import (
    admin_bp,
    entities_bp,
    graph_bp,
    investigations_bp,
    keys_bp,
    transforms_bp,
    auth_bp,
    audit_bp,
    sightings_bp,
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
    ShodanTransform,
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
    Migrate(app, db)

    # Issue #89: registra o ``before_request`` que resolve
    # ``g.service_name`` ANTES do ``_check_request_limit`` do
    # Flask-Limiter. A ordem importa: a before_request do Limiter
    # é adicionada em ``limiter.init_app(app)`` abaixo, então
    # nosso hook precisa estar registrado ANTES.
    from openm.core.rate_limiter import register_rate_limit_handler
    register_rate_limit_handler(app)
    limiter.init_app(app)

    # Issue #81: cycle detection boot-time (camada 1 de 3). Após
    # todos os transforms terem sido registrados (via
    # ``openm.transforms`` import no topo), varre a DAG de
    # ``downstream_transforms`` e loga warning se encontrar
    # ciclo. Não levanta exceção — defesa em profundidade
    # (runtime ``Set visited`` e ``max_chain_depth`` são as
    # outras camadas).
    from openm.core.transform import TransformRegistry

    try:
        cycles = TransformRegistry.detect_cycles()
        if cycles:
            for cycle in cycles:
                app.logger.warning(
                    "[issue#81] cycle detected em downstream_transforms: %s",
                    " -> ".join(cycle),
                )
    except Exception as exc:  # pragma: no cover - defensivo
        app.logger.warning("Falha ao detectar cycles de transform: %s", exc)

    # CORS liberado para uso local
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Registra blueprints da API
    app.register_blueprint(entities_bp)
    app.register_blueprint(transforms_bp)
    app.register_blueprint(graph_bp)
    app.register_blueprint(investigations_bp)
    app.register_blueprint(keys_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(sightings_bp)

    # Páginas HTML (login/registro/logout)
    app.register_blueprint(frontend_bp)

    # CLI customizado (ex.: flask admin create-admin, flask audit purge)
    from openm.cli import admin_cli, audit_cli
    app.cli.add_command(admin_cli)
    app.cli.add_command(audit_cli)

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
