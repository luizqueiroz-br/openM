#!/usr/bin/env python3
"""
Cria (ou promove) um admin no OpenM — script standalone.

Pensado para rodar **fora** do venv Flask / sem o código completo
instalado. Útil especialmente em:

- Kame (ou outro host) que só tem acesso ao Postgres, sem o app.
- Containers efêmeros de bootstrap.
- Recuperação de sistemas onde o último admin se trancou fora.

Uso:
    # Forma recomendada (carrega .env automaticamente):
    python scripts/create_admin.py --email admin@x.com --password 'senha-forte-123'

    # Promover um usuário existente ao invés de falhar:
    python scripts/create_admin.py --email admin@x.com --password 'nova-senha' --force

    # Conectar a um Postgres específico (sem .env):
    python scripts/create_admin.py \\
        --email admin@x.com --password 'senha-forte-123' \\
        --database-url 'postgresql://user:pass@host:5432/dbname'

Estratégia:
    1. Tenta usar o pacote ``openm`` (mesmo código do ``flask create-admin``).
       Requer rodar do diretório do projeto ou ter o pacote instalado.
    2. Se o pacote não estiver disponível, conecta **direto** no Postgres
       via ``DATABASE_URL`` e faz o INSERT/UPDATE manualmente — gera o
       hash bcrypt inline (sem dependência do openm.core.auth).

Em ambos os casos o resultado é o mesmo: um usuário com ``role='admin'``
e ``is_active=true`` no banco.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Garante que o root do projeto está no sys.path, para que ``import openm``
# funcione quando o script é invocado de fora do venv (ex.: ``python
# scripts/create_admin.py``). Quando rodado dentro do venv (caso comum),
# o pacote já está instalado e isso é um noop.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Carrega .env se existir (mesmo padrão do openm.config).
try:
    from dotenv import load_dotenv
    # Procura .env no diretório atual e no pai (caso o script rode de fora).
    for candidate in (Path.cwd() / ".env", Path(__file__).resolve().parent.parent / ".env"):
        if candidate.exists():
            load_dotenv(candidate)
            break
except ImportError:
    pass  # sem python-dotenv — confia em env vars explícitas


# ===================== Cores / output =====================

class _C:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _ok(msg: str) -> None:
    print(f"{_C.GREEN}✓{_C.RESET} {msg}")


def _err(msg: str) -> None:
    print(f"{_C.RED}✗{_C.RESET} {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"{_C.YELLOW}!{_C.RESET} {msg}")


def _info(msg: str) -> None:
    print(f"{_C.DIM}  {msg}{_C.RESET}")


# ===================== Validações =====================

def _normalize_email(raw: str) -> str:
    """Valida e normaliza o email. Retorna (normalized, ok, error_msg)."""
    try:
        from email_validator import EmailNotValidError, validate_email
        info = validate_email(raw, check_deliverability=False)
        return info.normalized, True, ""
    except ImportError:
        # Fallback mínimo se email_validator não estiver instalado:
        # aceita qualquer coisa com '@' e sem espaços.
        if "@" not in raw or " " in raw:
            return raw, False, "email parece inválido (instale 'email_validator' para validação completa)"
        return raw.lower(), True, ""
    except EmailNotValidError as exc:
        return raw, False, str(exc)


def _validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "senha deve ter no mínimo 8 caracteres"
    return True, ""


# ===================== Estratégia A: via pacote openm =====================

def _try_via_openm(email: str, password: str, force: bool) -> tuple[bool, str]:
    """
    Tenta usar o pacote ``openm`` (mesmo caminho do ``flask create-admin``).
    Retorna (sucesso, mensagem).
    """
    try:
        from openm.app import create_app  # noqa: F401
        from openm.config import Config
        from openm.core.auth import hash_password
        from openm.extensions import db
        from openm.models.user import User
    except ImportError as exc:
        return False, f"pacote openm não disponível ({exc})"

    # Cria app efêmero só pra ter o contexto do DB.
    app = create_app(Config)
    with app.app_context():
        # Não criamos tabelas defensivamente: o schema é gerenciado por
        # Flask-Migrate / Alembic (issue #36). Em produção o operador
        # deve rodar ``flask db upgrade`` antes deste script; em dev
        # local o Makefile já provê ``make db-upgrade``. Se a tabela
        # ``users`` não existir, falhamos com mensagem clara.
        from sqlalchemy import inspect

        inspector = inspect(db.engine)
        if not inspector.has_table("users"):
            print(
                "WARNING: 'users' table missing. "
                "Run 'flask db upgrade' before this script.",
                file=sys.stderr,
            )
            sys.exit(1)

        existing = User.query.filter_by(email=email).first()

        if existing is not None:
            if not force:
                return False, (
                    f"já existe um usuário com email '{email}' "
                    f"(role='{existing.role}'). Use --force para promovê-lo."
                )
            if existing.role == "admin":
                return True, f"'{email}' já é admin — nada a fazer"
            existing.role = "admin"
            existing.is_active = True
            existing.password_hash = hash_password(password)
            db.session.commit()
            return True, f"'{email}' promovido para admin (senha redefinida)"

        user = User(
            email=email,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        return True, f"admin '{email}' criado (id={user.id})"


# ===================== Estratégia B: direto no Postgres =====================

def _try_via_postgres(email: str, password: str, force: bool) -> tuple[bool, str]:
    """
    Fallback: conecta direto no Postgres via DATABASE_URL.
    Faz INSERT/UPDATE manualmente, com hash bcrypt inline.
    """
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        return False, (
            "nem o pacote 'openm' nem 'psycopg2-binary' estão disponíveis. "
            "Instale um dos dois para rodar este script."
        )

    # bcrypt para gerar o hash sem dependência do openm.
    try:
        import bcrypt
    except ImportError:
        return False, (
            "'psycopg2' está disponível mas falta 'bcrypt' para gerar o hash. "
            "pip install bcrypt"
        )

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        return False, (
            "DATABASE_URL não definida. Passe via env var ou --database-url."
        )

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")

    try:
        conn = psycopg2.connect(database_url)
    except Exception as exc:
        return False, f"falha ao conectar no Postgres: {exc}"

    try:
        with conn, conn.cursor() as cur:
            # Verifica se usuário já existe.
            cur.execute(
                "SELECT id, role FROM users WHERE email = %s", (email,)
            )
            row = cur.fetchone()

            if row is not None:
                user_id, current_role = row
                if not force:
                    return False, (
                        f"já existe um usuário com email '{email}' "
                        f"(role='{current_role}'). Use --force para promovê-lo."
                    )
                if current_role == "admin":
                    return True, f"'{email}' já é admin — nada a fazer"
                cur.execute(
                    """
                    UPDATE users
                       SET role = 'admin',
                           is_active = true,
                           password_hash = %s,
                           updated_at = NOW()
                     WHERE id = %s
                    """,
                    (password_hash, user_id),
                )
                return True, f"'{email}' promovido para admin (senha redefinida)"

            cur.execute(
                """
                INSERT INTO users (email, password_hash, role, is_active,
                                   created_at, updated_at)
                VALUES (%s, %s, 'admin', true, NOW(), NOW())
                RETURNING id
                """,
                (email, password_hash),
            )
            new_id = cur.fetchone()[0]
            return True, f"admin '{email}' criado (id={new_id})"
    finally:
        conn.close()


# ===================== Main =====================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cria ou promove um admin no OpenM (standalone).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--email", required=True, help="Email do admin.")
    parser.add_argument(
        "--password", required=True,
        help="Senha (mínimo 8 caracteres). Dica: use aspas pra evitar expansão do shell.",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Promove um usuário existente ao invés de abortar.",
    )
    parser.add_argument(
        "--database-url",
        help="Override do DATABASE_URL (senão usa .env / env var).",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Desativa saída colorida.",
    )
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        # Desativa cores em CI / pipes.
        for attr in dir(_C):
            if not attr.startswith("_"):
                setattr(_C, attr, "")

    # Aplica override do DB url antes de qualquer leitura do .env.
    if args.database_url:
        os.environ["DATABASE_URL"] = args.database_url

    # Validações.
    email, ok, err = _normalize_email(args.email)
    if not ok:
        _err(err)
        return 2

    ok, err = _validate_password(args.password)
    if not ok:
        _err(err)
        return 2

    # Tenta estratégia A (openm); se falhar, vai pra B (postgres direto).
    _info(f"target: {email}")
    _info(f"force:  {args.force}")
    db_url = os.environ.get("DATABASE_URL", "(não definida)")
    _info(f"db:     {db_url[:60]}{'...' if len(db_url) > 60 else ''}")

    success, message = _try_via_openm(email, args.password, args.force)
    strategy = "openm (Flask app)"

    if not success and "pacote openm não disponível" in message:
        _warn("pacote openm indisponível — tentando via Postgres direto")
        success, message = _try_via_postgres(email, args.password, args.force)
        strategy = "Postgres direto"

    if not success:
        _err(message)
        return 1

    _ok(f"{message}")
    _info(f"via: {strategy}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
