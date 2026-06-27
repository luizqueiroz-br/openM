"""
Testes para scripts/create_admin.py.

Cobre:
- Estratégia A (via pacote openm) — já é exercitada indiretamente via
  tests/test_cli.py; aqui validamos o caminho direto via script.
- Estratégia B (Postgres direto via psycopg2) — usando mock do psycopg2
  para não precisar de Postgres real.
- Validações: email, senha curta, --force, email duplicado.
- argparse: --help, --no-color, --database-url.
- Carregamento de .env (load_dotenv).
- Fallbacks: sem email_validator, sem psycopg2.
- Erros de conexão Postgres.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "create_admin.py"


# ===================== Estratégia A: openm (funções puras) =====================

@pytest.fixture
def sqlite_config(monkeypatch, tmp_path):
    """Garante que _try_via_openm use SQLite em vez de Postgres.

    O Config lê ``DATABASE_URL`` em import-time e congela na classe, então
    ``monkeypatch.setenv`` não basta — precisamos patchar o atributo da
    classe diretamente.

    Usa arquivo temporário (não :memory:) porque cada ``create_app()``
    gera um engine novo, e SQLite em memória tem DBs isolados por conexão.
    """
    db_path = tmp_path / "rbac_openm.db"
    import openm.config as cfg_module
    monkeypatch.setattr(
        cfg_module.Config,
        "SQLALCHEMY_DATABASE_URI",
        f"sqlite:///{db_path}",
    )
    # Limpa qualquer DATABASE_URL poluído do ambiente.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return db_path


@pytest.fixture
def shared_sqlite_env(monkeypatch, tmp_path):
    """Sincroniza _try_via_openm com o app fixture do conftest.

    Sem isso, _try_via_openm escreve no DB do ``Config`` (Postgres, do
    .env) enquanto a fixture ``app`` escreve no ``TestConfig`` (SQLite
    temporário), gerando inconsistência. Aqui forçamos ambos a usar
    o MESMO arquivo SQLite.
    """
    db_path = tmp_path / "shared_openm.db"

    # Patch no Config para _try_via_openm e create_app.
    import openm.config as cfg_module
    monkeypatch.setattr(
        cfg_module.Config,
        "SQLALCHEMY_DATABASE_URI",
        f"sqlite:///{db_path}",
    )
    # Patch também no TestConfig para a fixture ``app``.
    import tests.conftest as conftest_module
    monkeypatch.setattr(
        conftest_module.TestConfig,
        "SQLALCHEMY_DATABASE_URI",
        f"sqlite:///{db_path}",
    )
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return db_path


def test_via_openm_creates_admin(shared_sqlite_env):
    """Estratégia A: cria admin via pacote openm (mesma config do Flask CLI)."""
    from scripts.create_admin import _try_via_openm
    from openm.config import Config
    from openm.app import create_app
    from openm.extensions import db
    from openm.models.user import User

    # Setup: bootstrap do schema (Flask-Migrate não roda aqui — script
    # exige 'flask db upgrade' antes; testes unitários criam manualmente).
    app = create_app(Config)
    with app.app_context():
        db.create_all()
        db.session.remove()

    ok, msg = _try_via_openm("viaopenm@example.com", "senha-forte-123", force=False)
    assert ok is True
    assert "criado" in msg.lower()

    # Lê via app separado no MESMO arquivo SQLite (não a fixture `app`,
    # que pode dropar tabelas entre chamadas).
    app = create_app(Config)
    with app.app_context():
        user = User.query.filter_by(email="viaopenm@example.com").first()
        assert user is not None
        assert user.role == "admin"
        db.session.remove()


def test_via_openm_duplicate_email_aborts(shared_sqlite_env):
    from scripts.create_admin import _try_via_openm
    from openm.config import Config
    from openm.app import create_app
    from openm.extensions import db

    # Bootstrap do schema antes do script rodar.
    app = create_app(Config)
    with app.app_context():
        db.create_all()
        db.session.remove()

    _try_via_openm("dup@example.com", "senha-forte-123", force=False)
    ok, msg = _try_via_openm("dup@example.com", "outra-senha-456", force=False)

    assert ok is False
    assert "já existe" in msg.lower()


def test_via_openm_force_promotes(shared_sqlite_env):
    """Promove analyst existente para admin via --force."""
    from scripts.create_admin import _try_via_openm
    from openm.config import Config
    from openm.app import create_app
    from openm.extensions import db
    from openm.core.auth import hash_password
    from openm.models.user import User

    # Setup: cria analyst diretamente via SQLAlchemy.
    app = create_app(Config)
    with app.app_context():
        db.create_all()
        u = User(
            email="promote@example.com",
            password_hash=hash_password("senha-antiga-123"),
            role="analyst",
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        db.session.remove()

    ok, msg = _try_via_openm("promote@example.com", "senha-nova-456", force=True)
    assert ok is True
    assert "promovido" in msg.lower()

    # Verifica promoção no MESMO DB.
    app = create_app(Config)
    with app.app_context():
        u = User.query.filter_by(email="promote@example.com").first()
        assert u is not None
        assert u.role == "admin"
        db.session.remove()


def test_via_openm_force_on_admin_is_noop(shared_sqlite_env):
    from scripts.create_admin import _try_via_openm
    from openm.config import Config
    from openm.app import create_app
    from openm.extensions import db

    # Bootstrap do schema antes do script rodar.
    app = create_app(Config)
    with app.app_context():
        db.create_all()
        db.session.remove()

    _try_via_openm("already@example.com", "senha-forte-123", force=False)
    ok, msg = _try_via_openm("already@example.com", "outra-senha-456", force=True)

    assert ok is True
    assert "já é admin" in msg.lower()


def test_via_openm_missing_package_returns_helpful_error():
    """Quando o pacote openm não está disponível, retorna string específica
    para acionar o fallback."""
    with patch.dict(sys.modules, {"openm.app": None, "openm.config": None,
                                  "openm.core.auth": None, "openm.extensions": None,
                                  "openm.models.user": None}):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("openm."):
                raise ImportError(f"simulated: {name} not available")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            from scripts import create_admin
            ok, msg = create_admin._try_via_openm(
                "any@example.com", "senha-forte-123", force=False
            )
            assert ok is False
            assert "pacote openm não disponível" in msg


def test_via_openm_missing_users_table(shared_sqlite_env):
    """Quando a tabela ``users`` não existe (schema não foi migrado),
    ``_try_via_openm`` deve retornar ``(False, ...)`` em vez de abortar
    o processo via ``sys.exit`` — quem decide o exit code é o ``main()``.

    Usa o DB vazio (sem ``db.create_all()``) para forçar a falha do
    inspect().has_table("users").
    """
    from scripts import create_admin

    ok, msg = create_admin._try_via_openm(
        "ghost@example.com", "senha-forte-123", force=False
    )

    assert ok is False
    assert "users" in msg.lower()
    assert "flask db upgrade" in msg.lower()


# ===================== Estratégia B: Postgres direto =====================

@pytest.fixture
def mock_psycopg2():
    """Mocka o módulo psycopg2 que é importado lazy dentro de _try_via_postgres."""
    fake_module = MagicMock()
    with patch.dict(sys.modules, {"psycopg2": fake_module, "psycopg2.extras": MagicMock()}):
        yield fake_module


def test_via_postgres_creates_user(mock_psycopg2):
    """Cria usuário via INSERT quando não existe."""
    from scripts.create_admin import _try_via_postgres

    mock_cursor = MagicMock()
    # SELECT retorna None (não existe); INSERT...RETURNING retorna id=42.
    mock_cursor.fetchone.side_effect = [None, (42,)]

    mock_conn = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

    mock_psycopg2.connect.return_value = mock_conn

    with patch.dict(os.environ, {"DATABASE_URL": "postgresql://x:y@host:5432/db"}):
        ok, msg = _try_via_postgres(
            "pg-create@example.com", "senha-forte-123", force=False
        )

    assert ok is True
    assert "criado" in msg.lower()
    # Confirma que rodou INSERT, não UPDATE
    calls = [str(c) for c in mock_cursor.execute.call_args_list]
    assert any("INSERT INTO users" in c for c in calls)


def test_via_postgres_promotes_existing_user(mock_psycopg2):
    from scripts.create_admin import _try_via_postgres

    mock_cursor = MagicMock()
    # SELECT retorna um user analyst existente
    mock_cursor.fetchone.return_value = (42, "analyst")

    mock_conn = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

    mock_psycopg2.connect.return_value = mock_conn

    with patch.dict(os.environ, {"DATABASE_URL": "postgresql://x:y@host/db"}):
        ok, msg = _try_via_postgres(
            "pg-promote@example.com", "nova-senha-456", force=True
        )

    assert ok is True
    assert "promovido" in msg.lower()
    # UPDATE rodou, não INSERT
    calls = [str(c) for c in mock_cursor.execute.call_args_list]
    assert any("UPDATE users" in c for c in calls)


def test_via_postgres_duplicate_aborts_without_force(mock_psycopg2):
    from scripts.create_admin import _try_via_postgres

    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (42, "analyst")

    mock_conn = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

    mock_psycopg2.connect.return_value = mock_conn

    with patch.dict(os.environ, {"DATABASE_URL": "postgresql://x:y@host/db"}):
        ok, msg = _try_via_postgres(
            "dup@example.com", "senha-forte-123", force=False
        )

    assert ok is False
    assert "já existe" in msg.lower()


def test_via_postgres_admin_noop(mock_psycopg2):
    from scripts.create_admin import _try_via_postgres

    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (1, "admin")  # já é admin

    mock_conn = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

    mock_psycopg2.connect.return_value = mock_conn

    with patch.dict(os.environ, {"DATABASE_URL": "postgresql://x:y@host/db"}):
        ok, msg = _try_via_postgres(
            "alreadypg@example.com", "nova-senha", force=True
        )

    assert ok is True
    assert "já é admin" in msg.lower()


def test_via_postgres_connection_failure_returns_error(mock_psycopg2):
    """Falha de conexão Postgres → erro descritivo, exit 1."""
    from scripts.create_admin import _try_via_postgres

    mock_psycopg2.connect.side_effect = Exception("connection refused")

    with patch.dict(os.environ, {"DATABASE_URL": "postgresql://nope:nope@nowhere/db"}):
        ok, msg = _try_via_postgres(
            "x@example.com", "senha-forte-123", force=False
        )

    assert ok is False
    assert "falha ao conectar" in msg.lower()


def test_via_postgres_missing_env_returns_error():
    """Sem DATABASE_URL e sem --database-url → erro claro."""
    from scripts import create_admin

    # Garante que DATABASE_URL não está setada.
    env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    with patch.dict(os.environ, env, clear=True):
        ok, msg = create_admin._try_via_postgres(
            "x@example.com", "senha-forte-123", force=False
        )

    assert ok is False
    assert "DATABASE_URL" in msg


def test_via_postgres_missing_psycopg2_returns_error():
    """Sem psycopg2 instalado → erro claro sobre dependência."""
    import builtins
    from scripts import create_admin

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psycopg2" or name.startswith("psycopg2."):
            raise ImportError("simulated: psycopg2 not installed")
        return real_import(name, *args, **kwargs)

    with patch.dict(os.environ, {"DATABASE_URL": "postgresql://x/db"}):
        with patch("builtins.__import__", side_effect=fake_import):
            ok, msg = create_admin._try_via_postgres(
                "x@example.com", "senha-forte-123", force=False
            )

    assert ok is False
    assert "psycopg2" in msg


# ===================== Validações puras =====================

def test_normalize_email_valid():
    from scripts.create_admin import _normalize_email

    normalized, ok, err = _normalize_email("Admin@Example.COM")
    assert ok is True
    assert err == ""
    # Domínio é lowercased; local-part preservado.
    assert "@example.com" in normalized


def test_normalize_email_invalid_format():
    from scripts.create_admin import _normalize_email

    normalized, ok, err = _normalize_email("not-an-email")
    assert ok is False
    # email-validator retorna mensagem em inglês; só checamos que há erro.
    assert err != ""


def test_normalize_email_without_validator_fallback():
    """Quando email_validator não está instalado, usa fallback mínimo."""
    import builtins
    from scripts import create_admin

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "email_validator":
            raise ImportError("simulated: email_validator not installed")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        # Email válido pelo fallback (tem @, sem espaços)
        normalized, ok, err = create_admin._normalize_email("User@Example.COM")
        assert ok is True
        # Fallback só faz .lower()
        assert normalized == "user@example.com"

        # Email inválido pelo fallback (sem @)
        normalized, ok, err = create_admin._normalize_email("not-an-email")
        assert ok is False
        assert "inválido" in err.lower() or "instale" in err.lower()


def test_validate_password_too_short():
    from scripts.create_admin import _validate_password

    ok, err = _validate_password("1234567")
    assert ok is False
    assert "8 caracteres" in err


def test_validate_password_exactly_minimum():
    from scripts.create_admin import _validate_password

    ok, err = _validate_password("12345678")
    assert ok is True
    assert err == ""


def test_validate_password_long_is_ok():
    from scripts.create_admin import _validate_password

    ok, _ = _validate_password("uma-senha-bem-longa-e-complexa-123!@#")
    assert ok is True


# ===================== CLI end-to-end (subprocess) =====================

def test_script_help_exits_zero():
    """--help deve sair com código 0 e mostrar usage."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "create-admin" in result.stdout or "Usage" in result.stdout


def test_script_missing_args_exits_nonzero():
    """Sem --email/--password, exit code 2 (argparse error)."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "required" in combined.lower() or "usage" in combined.lower()


def test_script_short_password_exits_2():
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH),
         "--email", "x@example.com", "--password", "123",
         "--no-color"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 2
    assert "8 caracteres" in result.stderr


def test_script_invalid_email_exits_2():
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH),
         "--email", "not-an-email", "--password", "senha-forte-123",
         "--no-color"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 2


def test_script_end_to_end_with_sqlite(tmp_path):
    """
    Roda o script de verdade via subprocess, com DATABASE_URL apontando
    para SQLite em arquivo temporário e verifica que o admin foi criado.
    """
    db_file = tmp_path / "script_e2e.db"
    db_url = f"sqlite:///{db_file}"

    # Bootstrap do schema no MESMO arquivo antes do subprocess rodar.
    # O script exige 'flask db upgrade' prévio (#36); testes unitários
    # criam a tabela via SQLAlchemy para reproduzir o efeito do upgrade.
    from openm.config import Config
    from openm.app import create_app
    from openm.extensions import db

    class _TmpConfig(Config):
        SQLALCHEMY_DATABASE_URI = db_url

    bootstrap_app = create_app(_TmpConfig)
    with bootstrap_app.app_context():
        db.create_all()
        db.session.remove()

    # Subprocess precisa do path do projeto no PYTHONPATH pra encontrar openm.
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    # Garante que DATABASE_URL do ambiente não polua o teste.
    env.pop("DATABASE_URL", None)

    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH),
         "--email", "e2e@example.com",
         "--password", "senha-forte-123",
         "--database-url", db_url,
         "--no-color"],
        capture_output=True, text=True, timeout=15, env=env,
    )
    assert result.returncode == 0, (
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "criado" in result.stdout.lower()

    # Roda de novo sem --force → deve falhar (duplicado)
    result2 = subprocess.run(
        [sys.executable, str(SCRIPT_PATH),
         "--email", "e2e@example.com",
         "--password", "outra-senha-456",
         "--database-url", db_url,
         "--no-color"],
        capture_output=True, text=True, timeout=15, env=env,
    )
    assert result2.returncode == 1
    assert "já existe" in result2.stderr.lower()


# ===================== Cobertura de linhas do argparse / main =====================

def test_main_with_no_color_does_not_set_ansi(shared_sqlite_env, monkeypatch, capsys):
    """--no-color desativa códigos ANSI no output."""
    from scripts import create_admin
    from openm.config import Config
    from openm.app import create_app
    from openm.extensions import db

    db_file = shared_sqlite_env

    # Bootstrap do schema antes do main() rodar.
    app = create_app(Config)
    with app.app_context():
        db.create_all()
        db.session.remove()

    monkeypatch.setattr(sys, "argv", [
        "create_admin.py",
        "--email", "nocolor@example.com",
        "--password", "senha-forte-123",
        "--database-url", f"sqlite:///{db_file}",
        "--no-color",
    ])
    monkeypatch.delenv("DATABASE_URL", raising=False)

    rc = create_admin.main()
    assert rc == 0

    captured = capsys.readouterr()
    # Sem códigos ANSI quando --no-color é passado.
    assert "\033[" not in captured.out


def test_main_returns_2_for_short_password(monkeypatch, capsys):
    from scripts import create_admin

    monkeypatch.setattr(sys, "argv", [
        "create_admin.py",
        "--email", "x@example.com",
        "--password", "123",
    ])
    rc = create_admin.main()
    assert rc == 2
    assert "8 caracteres" in capsys.readouterr().err


def test_main_returns_2_for_missing_email(monkeypatch, capsys):
    """argparse chama SystemExit(2) quando --email falta."""
    from scripts import create_admin

    monkeypatch.setattr(sys, "argv", [
        "create_admin.py",
        "--password", "senha-forte-123",
    ])

    # argparse.error → SystemExit(2). Capturamos e verificamos.
    with pytest.raises(SystemExit) as exc_info:
        create_admin.main()
    assert exc_info.value.code == 2


def test_main_database_url_override_sets_env(shared_sqlite_env, monkeypatch):
    """--database-url sobrescreve DATABASE_URL no ambiente."""
    from scripts import create_admin
    from openm.config import Config
    from openm.app import create_app
    from openm.extensions import db

    db_file = shared_sqlite_env

    # Bootstrap do schema antes do main() rodar.
    app = create_app(Config)
    with app.app_context():
        db.create_all()
        db.session.remove()

    monkeypatch.setattr(sys, "argv", [
        "create_admin.py",
        "--email", "override@example.com",
        "--password", "senha-forte-123",
        "--database-url", f"sqlite:///{db_file}",
        "--no-color",
    ])
    monkeypatch.delenv("DATABASE_URL", raising=False)

    rc = create_admin.main()
    assert rc == 0
    assert os.environ.get("DATABASE_URL") == f"sqlite:///{db_file}"


def test_main_falls_back_to_postgres_when_openm_missing(monkeypatch, tmp_path, capsys):
    """Quando openm não está disponível, usa estratégia B (postgres direto)."""
    from scripts import create_admin

    monkeypatch.setattr(sys, "argv", [
        "create_admin.py",
        "--email", "fallback@example.com",
        "--password", "senha-forte-123",
        "--database-url", "sqlite:///unused.db",  # psycopg2 ignora
        "--no-color",
    ])

    # Força estratégia A falhar com a string que dispara o fallback.
    monkeypatch.setattr(
        create_admin, "_try_via_openm",
        lambda *a, **kw: (False, "pacote openm não disponível (simulado)"),
    )

    # Mock psycopg2.connect pra falhar (assim confirmamos que foi tentado).
    fake_psycopg2 = MagicMock()
    fake_psycopg2.connect.side_effect = Exception("simulated psycopg2 failure")
    with patch.dict(sys.modules, {"psycopg2": fake_psycopg2}):
        rc = create_admin.main()

    assert rc == 1
    captured = capsys.readouterr()
    # Mensagem de "tentando via Postgres direto" deve aparecer.
    combined = captured.out + captured.err
    assert "postgres direto" in combined.lower() or "tentando" in combined.lower()
