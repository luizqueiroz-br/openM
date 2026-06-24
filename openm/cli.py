"""
Comandos CLI do OpenM (Flask CLI via Click).

Uso:
    flask --app openm.app create-admin --email admin@x.com --password 'senha-forte-123'

Por que isso existe:
    Em produção, ``ALLOW_REGISTRATION=false`` por design — não queremos
    que a API pública permita criar contas (e muito menos admins).
    Para o primeiro deploy (sistema vazio), este comando é o canal
    seguro de bootstrap: roda no servidor com acesso ao DB e exige
    interação direta do operador.

    Após o primeiro admin existir, promovam-se outros admins pela API
    (``PATCH /api/admin/users/<id>/role``).
"""

from __future__ import annotations

import sys

import click
from flask.cli import AppGroup

from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User


# ============ Helpers ============

def _normalize_email(raw: str) -> str:
    """Valida e normaliza o email. Levanta click.BadParameter em erro."""
    # Import lazy pra não exigir email_validator em ambientes só-CLI sem auth.
    from email_validator import EmailNotValidError, validate_email

    try:
        info = validate_email(raw, check_deliverability=False)
    except EmailNotValidError as exc:
        raise click.BadParameter(f"email inválido: {exc}") from exc
    return info.normalized


# ============ Grupo CLI ============

admin_cli = AppGroup("admin", help="Comandos administrativos (ex.: criar admin).")


@admin_cli.command("create-admin")
@click.option("--email", required=True, help="Email do novo admin.")
@click.option("--password", required=True, help="Senha (mínimo 8 caracteres).")
@click.option(
    "--force/--no-force",
    default=False,
    help=(
        "Se o email já existir como analyst, promove para admin ao invés de "
        "abortar. NÃO use para rebaixar — apenas promove."
    ),
)
def create_admin(email: str, password: str, force: bool) -> None:
    """
    Cria (ou promove) um usuário com role='admin'.

    Por padrão, aborta se o email já existe. Com --force, promove o usuário
    existente para admin (útil para recuperar um sistema onde o admin se
    trancou fora, embora o sistema já proteja contra auto-rebaixamento).

    A senha é validada (mínimo 8 caracteres) e armazenada com bcrypt
    rounds=12 — mesmo padrão do registro via API.
    """
    if len(password) < 8:
        click.echo("Erro: senha deve ter no mínimo 8 caracteres.", err=True)
        sys.exit(2)

    normalized = _normalize_email(email)

    # current_app tem o app_context ativo durante o comando CLI.
    existing = User.query.filter_by(email=normalized).first()

    if existing is not None:
        if not force:
            click.echo(
                f"Erro: já existe um usuário com o email '{normalized}' "
                f"(role atual: '{existing.role}'). "
                f"Use --force para promovê-lo a admin.",
                err=True,
            )
            sys.exit(1)

        if existing.role == "admin":
            click.echo(f"'{normalized}' já é admin. Nada a fazer.")
            return

        old_role = existing.role
        existing.role = "admin"
        existing.is_active = True
        existing.password_hash = hash_password(password)
        db.session.commit()
        click.echo(
            f"OK: '{normalized}' promovido de '{old_role}' para 'admin'. "
            f"Senha redefinida."
        )
        return

    user = User(
        email=normalized,
        password_hash=hash_password(password),
        role="admin",
        is_active=True,
    )
    db.session.add(user)
    db.session.commit()
    click.echo(f"OK: admin '{normalized}' criado (id={user.id}).")


__all__ = ["admin_cli", "create_admin"]
