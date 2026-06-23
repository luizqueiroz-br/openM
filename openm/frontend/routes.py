"""
Rotas de páginas HTML (autenticação UI).

Serve as telas de login/registro e o handler server-side de logout.
As páginas autenticadas (/) ficam no próprio ``app.py`` pois usam o
helper ``login_required_page`` que vive em ``core.auth``.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

from openm.core.auth import _clear_auth_cookies, decode_token, revoke_refresh_token
from datetime import datetime, timezone

frontend_bp = Blueprint("frontend", __name__)


def _is_registration_allowed() -> bool:
    return bool(current_app.config.get("ALLOW_REGISTRATION", False))


@frontend_bp.route("/login", methods=["GET"])
def login_page():
    """Tela de login. Pública."""
    return render_template(
        "login.html",
        allow_registration=_is_registration_allowed(),
    )


@frontend_bp.route("/register", methods=["GET"])
def register_page():
    """Tela de registro. Pública, mas escondida quando ALLOW_REGISTRATION=false."""
    if not _is_registration_allowed():
        return render_template(
            "login.html",
            allow_registration=False,
        ), 403
    return render_template("register.html", allow_registration=True)


@frontend_bp.route("/logout", methods=["GET"])
def logout_page():
    """
    Handler server-side de logout.

    - Lê o refresh token do cookie (se houver) e revoga na blacklist.
    - Limpa os cookies httpOnly de access + refresh.
    - Redireciona pra /login.
    """
    from openm.core.auth import _cookie_refresh_name

    response = make_response(redirect(url_for("frontend.login_page")))

    refresh_token = request.cookies.get(_cookie_refresh_name())
    if refresh_token:
        try:
            claims = decode_token(refresh_token, expected_type="refresh")
            revoke_refresh_token(
                jti=claims["jti"],
                user_id=int(claims["sub"]),
                expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
            )
        except Exception:  # noqa: BLE001 — idempotente: ignora tokens inválidos
            pass

    _clear_auth_cookies(response)
    return response