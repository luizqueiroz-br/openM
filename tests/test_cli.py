"""
Testes do CLI OpenM (issue #3 — comando create-admin).

Cobre:
- Criação de admin a partir do zero.
- Bloqueio de email duplicado.
- Validação de senha curta.
- Validação de email inválido.
- Modo --force para promover um usuário existente.
- Idempotência: rodar duas vezes sem --force não corrompe o estado.
"""

from openm.core.auth import verify_password
from openm.extensions import db
from openm.models.user import User


# ===================== Helpers =====================

def _invoke(app, *args):
    """Atalho: roda um comando CLI no contexto do app de teste."""
    runner = app.test_cli_runner()
    return runner.invoke(args=args, catch_exceptions=False)


# ===================== Caminho feliz =====================

def test_create_admin_success(app):
    result = _invoke(
        app, "admin", "create-admin",
        "--email", "firstadmin@example.com",
        "--password", "senha-forte-123",
    )
    assert result.exit_code == 0, result.output
    assert "criado" in result.output.lower() or "criada" in result.output.lower()

    with app.app_context():
        user = User.query.filter_by(email="firstadmin@example.com").first()
        assert user is not None
        assert user.role == "admin"
        assert user.is_active is True
        assert verify_password("senha-forte-123", user.password_hash)


def test_create_admin_normalizes_email(app):
    """O domínio do email é normalizado para lowercase."""
    result = _invoke(
        app, "admin", "create-admin",
        "--email", "Admin.User@Example.COM",
        "--password", "senha-forte-123",
    )
    assert result.exit_code == 0, result.output

    with app.app_context():
        user = User.query.filter_by(email="Admin.User@example.com").first()
        assert user is not None
        assert user.role == "admin"


# ===================== Validações =====================

def test_create_admin_short_password_rejected(app):
    result = _invoke(
        app, "admin", "create-admin",
        "--email", "x@example.com",
        "--password", "1234",  # < 8 chars
    )
    assert result.exit_code == 2  # click.BadParameter
    assert "8 caracteres" in result.output

    with app.app_context():
        assert User.query.filter_by(email="x@example.com").first() is None


def test_create_admin_invalid_email_rejected(app):
    result = _invoke(
        app, "admin", "create-admin",
        "--email", "not-an-email",
        "--password", "senha-forte-123",
    )
    assert result.exit_code == 2

    with app.app_context():
        assert User.query.filter_by(email="not-an-email").first() is None


def test_create_admin_missing_options_shows_error(app):
    result = _invoke(app, "admin", "create-admin")
    assert result.exit_code == 2
    # click indica qual opção faltou
    assert "email" in result.output.lower() or "password" in result.output.lower()


# ===================== Email duplicado =====================

def test_create_admin_duplicate_email_aborts(app):
    # Primeiro cria
    _invoke(
        app, "admin", "create-admin",
        "--email", "dup@example.com",
        "--password", "senha-forte-123",
    )
    # Tenta recriar sem --force
    result = _invoke(
        app, "admin", "create-admin",
        "--email", "dup@example.com",
        "--password", "outra-senha-456",
    )
    assert result.exit_code == 1
    assert "já existe" in result.output.lower()

    # Senha original NÃO foi alterada.
    with app.app_context():
        user = User.query.filter_by(email="dup@example.com").first()
        assert verify_password("senha-forte-123", user.password_hash)
        assert not verify_password("outra-senha-456", user.password_hash)


def test_create_admin_idempotent_for_existing_admin(app):
    # Criar e rodar de novo — sem --force deve abortar sem corromper nada.
    _invoke(
        app, "admin", "create-admin",
        "--email", "stable@example.com",
        "--password", "senha-forte-123",
    )
    result = _invoke(
        app, "admin", "create-admin",
        "--email", "stable@example.com",
        "--password", "senha-forte-123",
    )
    assert result.exit_code == 1


# ===================== --force (promover) =====================

def test_create_admin_force_promotes_existing_analyst(app):
    """--force promove um usuário existente para admin e reseta a senha."""
    with app.app_context():
        u = User(
            email="analyst-to-promote@example.com",
            password_hash="hash-antigo",
            role="analyst",
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()

    result = _invoke(
        app, "admin", "create-admin",
        "--email", "analyst-to-promote@example.com",
        "--password", "nova-senha-789",
        "--force",
    )
    assert result.exit_code == 0, result.output
    assert "promovido" in result.output.lower()

    with app.app_context():
        u = User.query.filter_by(email="analyst-to-promote@example.com").first()
        assert u.role == "admin"
        assert verify_password("nova-senha-789", u.password_hash)


def test_create_admin_force_on_existing_admin_is_noop(app):
    """--force em alguém que já é admin: nada muda, mensagem clara."""
    _invoke(
        app, "admin", "create-admin",
        "--email", "already-admin@example.com",
        "--password", "senha-forte-123",
    )

    result = _invoke(
        app, "admin", "create-admin",
        "--email", "already-admin@example.com",
        "--password", "outra-senha-456",
        "--force",
    )
    assert result.exit_code == 0
    assert "já é admin" in result.output.lower()

    # Senha NÃO foi sobrescrita (porque já é admin, é noop completo).
    with app.app_context():
        u = User.query.filter_by(email="already-admin@example.com").first()
        assert u.role == "admin"
        assert verify_password("senha-forte-123", u.password_hash)
        assert not verify_password("outra-senha-456", u.password_hash)


# ===================== Integração com sistema de auth =====================

def test_created_admin_can_login_via_api(app, client):
    """
    Após criar via CLI, o admin deve conseguir logar normalmente
    na API e receber role='admin' em /api/auth/me.
    """
    _invoke(
        app, "admin", "create-admin",
        "--email", "realadmin@example.com",
        "--password", "senha-forte-123",
    )

    resp = client.post(
        "/api/auth/login",
        json={"email": "realadmin@example.com", "password": "senha-forte-123"},
    )
    assert resp.status_code == 200
    token = resp.get_json()["access_token"]

    resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["user"]["role"] == "admin"


def test_create_admin_works_even_when_registration_disabled(app):
    """
    O comando CLI deve funcionar independente de ``ALLOW_REGISTRATION`` —
    é justamente pra ser o canal de bootstrap em produção.
    """
    app.config["ALLOW_REGISTRATION"] = False

    result = _invoke(
        app, "admin", "create-admin",
        "--email", "bootstrap@example.com",
        "--password", "senha-forte-123",
    )
    assert result.exit_code == 0, result.output

    with app.app_context():
        assert User.query.filter_by(email="bootstrap@example.com").first().role == "admin"
