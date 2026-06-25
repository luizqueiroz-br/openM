"""
Comandos CLI do OpenM (Flask CLI via Click).

Uso:
    flask --app openm.app admin create-admin --email admin@x.com --password 'senha-forte-123'
    flask --app openm.app audit purge --days 90

Por que isso existe:
    Em produção, ``ALLOW_REGISTRATION=false`` por design — não queremos
    que a API pública permita criar contas (e muito menos admins).
    Para o primeiro deploy (sistema vazio), este comando é o canal
    seguro de bootstrap: roda no servidor com acesso ao DB e exige
    interação direta do operador.

    Após o primeiro admin existir, promovam-se outros admins pela API
    (``PATCH /api/admin/users/<id>/role``).

    O subgrupo ``audit`` implementa a retenção configurável (issue #4):
    ``flask audit purge --days N`` apaga entradas mais antigas que N
    dias. Sem isso, a tabela cresce indefinidamente.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

import click
from flask import current_app
from flask.cli import AppGroup

from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User
from openm.models.audit_log import AuditLog


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


# ============ Audit log retention (issue #4) ============

audit_cli = AppGroup(
    "audit",
    help="Comandos de manutenção do audit log (retenção, etc.).",
)


@audit_cli.command("purge")
@click.option(
    "--days",
    type=int,
    default=None,
    help=(
        "Remove entradas mais antigas que N dias. "
        "Default: AUDIT_LOG_RETENTION_DAYS da config (90)."
    ),
)
@click.option(
    "--dry-run/--no-dry-run",
    default=False,
    help="Se ligado, apenas conta quantas entradas seriam removidas sem apagar.",
)
def audit_purge(days: int | None, dry_run: bool) -> None:
    """
    Apaga entradas do audit log anteriores ao cutoff (issue #4).

    Exemplo:
        flask audit purge --days 90           # usa cutoff = now() - 90 dias
        flask audit purge --days 90 --dry-run # apenas reporta

    O cutoff é "estritamente menor que" — entradas com created_at == cutoff
    são MANTIDAS. Isso evita apagar entradas que foram geradas exatamente
    no momento do cutoff.
    """
    if days is None:
        days = int(current_app.config.get("AUDIT_LOG_RETENTION_DAYS", 90))

    if days < 0:
        click.echo("Erro: --days deve ser >= 0.", err=True)
        sys.exit(2)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    query = AuditLog.query.filter(AuditLog.created_at < cutoff)
    count = query.count()

    if dry_run:
        click.echo(
            f"[dry-run] {count} entradas seriam removidas "
            f"(cutoff={cutoff.isoformat()}, days={days})."
        )
        return

    if count == 0:
        click.echo(
            f"Nada a remover (cutoff={cutoff.isoformat()}, days={days})."
        )
        return

    # synchronize_session=False: evita flush desnecessário de objetos
    # em sessão. Adequado para deleções em massa (a sessão é limpa depois).
    query.delete(synchronize_session=False)
    db.session.commit()
    click.echo(
        f"OK: {count} entradas removidas (cutoff={cutoff.isoformat()}, "
        f"days={days})."
    )


__all__ = ["admin_cli", "audit_cli", "create_admin", "audit_purge"]
