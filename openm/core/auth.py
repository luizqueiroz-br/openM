"""
Núcleo de autenticação: hash de senha, encode/decode JWT, blacklist e decorator.

Decisões:
- bcrypt (passlib) para hash de senha (rounds=12).
- PyJWT com algoritmo HS256, claims iss/aud/iat/exp/jti + sub.
- Access tokens são stateless (TTL curto).
- Refresh tokens vivem em blacklist (tabela ``revoked_tokens``).
- Token rotation: cada ``/refresh`` emite novo par e revoga o jti apresentado.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable

import jwt
from flask import current_app, g, jsonify, request
from passlib.context import CryptContext

from openm.extensions import db
from openm.models.revoked_token import RevokedToken
from openm.models.user import User, VALID_ROLES

# Contexto único do passlib para todo o app. rounds=12 é o padrão seguro em 2025.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ===================== Senha =====================

def hash_password(plain: str) -> str:
    """Gera hash bcrypt da senha em texto puro."""
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Compara senha em texto puro com hash armazenado. Constante no tempo."""
    try:
        return _pwd_context.verify(plain, hashed)
    except (ValueError, TypeError):
        return False


# ===================== JWT =====================

class TokenError(Exception):
    """Erro genérico de token. Mensagens são neutras para o cliente."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _config(key: str, default: Any = None) -> Any:
    return current_app.config.get(key, default)


def encode_token(
    *,
    user: User,
    token_type: str,
    ttl: timedelta,
    jti: str | None = None,
) -> tuple[str, str, datetime]:
    """
    Codifica um JWT (access ou refresh).

    Retorna ``(token, jti, expires_at)``.
    """
    jti = jti or uuid.uuid4().hex
    now = _now()
    exp = now + ttl
    payload: dict[str, Any] = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "type": token_type,
        "iss": _config("JWT_ISSUER", "openm"),
        "aud": _config("JWT_AUDIENCE", "openm-api"),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
    }
    token = jwt.encode(
        payload,
        _config("JWT_SECRET"),
        algorithm=_config("JWT_ALGORITHM", "HS256"),
    )
    return token, jti, exp


def decode_token(token: str, *, expected_type: str) -> dict[str, Any]:
    """
    Decodifica e valida um JWT.

    Lança ``TokenError`` em qualquer falha (expirado, assinatura inválida,
    audience/issuer errado, tipo errado).
    """
    try:
        payload = jwt.decode(
            token,
            _config("JWT_SECRET"),
            algorithms=[_config("JWT_ALGORITHM", "HS256")],
            audience=_config("JWT_AUDIENCE", "openm-api"),
            issuer=_config("JWT_ISSUER", "openm"),
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid token") from exc

    if payload.get("type") != expected_type:
        raise TokenError("wrong token type")
    return payload


# ===================== Blacklist (refresh) =====================

def revoke_refresh_token(jti: str, user_id: int | None, expires_at: datetime) -> None:
    """Insere o jti na blacklist. Idempotente (UNIQUE em jti)."""
    if RevokedToken.query.filter_by(jti=jti).first():
        return
    db.session.add(
        RevokedToken(jti=jti, user_id=user_id, expires_at=expires_at)
    )
    db.session.commit()


def is_refresh_revoked(jti: str) -> bool:
    """Verifica se um jti de refresh está na blacklist."""
    return db.session.query(
        RevokedToken.query.filter_by(jti=jti).exists()
    ).scalar()


# ===================== Cookies (issue #13) =====================
#
# O frontend usa cookies httpOnly em vez de localStorage, evitando XSS.
# Tokens continuam disponíveis também no JSON de resposta (header Bearer)
# para integrações externas e testes.
#
# - Access cookie: SameSite=Lax (acompanha navegação top-level).
# - Refresh cookie: SameSite=Strict (só first-party, mais conservador).
# - Em produção (JWT_COOKIE_SECURE=true), ambos exigem HTTPS.

def _cookie_access_name() -> str:
    return _config("JWT_COOKIE_ACCESS_NAME", "openm_access")


def _cookie_refresh_name() -> str:
    return _config("JWT_COOKIE_REFRESH_NAME", "openm_refresh")


def _cookie_secure() -> bool:
    return bool(_config("JWT_COOKIE_SECURE", False))


def _cookie_domain() -> str | None:
    return _config("JWT_COOKIE_DOMAIN", None)


def _set_auth_cookies(
    response: Any,
    *,
    access_token: str,
    refresh_token: str,
    refresh_expires_at: datetime,
) -> None:
    """Seta os cookies httpOnly de access + refresh na response."""
    access_ttl = int(_config("JWT_ACCESS_TTL_MINUTES", 15)) * 60  # em segundos
    refresh_ttl = int((refresh_expires_at - _now()).total_seconds())

    common = dict(
        httponly=True,
        secure=_cookie_secure(),
        domain=_cookie_domain(),
    )
    response.set_cookie(
        _cookie_access_name(),
        access_token,
        max_age=access_ttl,
        samesite="Lax",
        path="/",
        **common,
    )
    response.set_cookie(
        _cookie_refresh_name(),
        refresh_token,
        max_age=max(refresh_ttl, 0),
        samesite="Strict",
        path="/",
        **common,
    )


def _clear_auth_cookies(response: Any) -> None:
    """Remove os cookies de auth da response (usado em /logout)."""
    common = dict(
        secure=_cookie_secure(),
        domain=_cookie_domain(),
        path="/",
    )
    response.delete_cookie(_cookie_access_name(), **common)
    response.delete_cookie(_cookie_refresh_name(), **common)


def _read_cookie_token(name: str) -> str | None:
    """Lê um valor de cookie pelo nome. Retorna None se ausente ou vazio."""
    value = request.cookies.get(name)
    if not value:
        return None
    return value


def _get_refresh_token_from_request() -> str | None:
    """
    Resolve o refresh token a partir de (em ordem):
    1. body JSON ``{"refresh_token": "..."}`` (uso externo / testes)
    2. cookie httpOnly ``openm_refresh`` (uso do frontend)
    """
    data = request.get_json(silent=True) or {}
    token = data.get("refresh_token")
    if token:
        return token
    return _read_cookie_token(_cookie_refresh_name())


# ===================== Decorator =====================

def _extract_bearer() -> str | None:
    """
    Extrai o access token de:
    1. Header ``Authorization: Bearer <token>`` (uso externo / API)
    2. Cookie httpOnly ``openm_access`` (uso do frontend)
    """
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return token
    return _read_cookie_token(_cookie_access_name())


def require_auth(fn: Callable) -> Callable:
    """
    Decorator que valida o access token e injeta ``g.user`` (User) e ``g.role``.

    Resposta em caso de falha: 401 com ``{"error": "..."}``.
    """

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        token = _extract_bearer()
        if not token:
            return jsonify({"error": "missing bearer token"}), 401
        try:
            payload = decode_token(token, expected_type="access")
        except TokenError as exc:
            return jsonify({"error": str(exc)}), 401

        user = db.session.get(User, int(payload["sub"]))
        if user is None or not user.is_active:
            return jsonify({"error": "user not found or inactive"}), 401

        g.user = user
        g.role = user.role
        return fn(*args, **kwargs)

    return wrapper


def require_role(*allowed: str) -> Callable:
    """
    Decorator que exige um dos papéis (após ``@require_auth``).

    Uso:
        @investigations_bp.route(...)
        @require_auth
        @require_role("admin", "analyst")
        def ...
    """
    invalid = [r for r in allowed if r not in VALID_ROLES]
    if invalid:
        raise ValueError(f"Unknown roles: {invalid}")

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            if not hasattr(g, "user"):
                return jsonify({"error": "auth required"}), 401
            if g.role not in allowed:
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ===================== Decorator de páginas HTML =====================

def login_required_page(fn: Callable) -> Callable:
    """
    Decorator para views que servem páginas HTML (não API).

    Lê o access token do header ``Authorization: Bearer`` ou do cookie
    httpOnly ``openm_access``. Se ausente/inválido → redireciona pra
    ``/login``. Se válido → popula ``g.user`` e ``g.role``.

    Diferente de ``@require_auth`` (que retorna JSON 401), este decorator
    faz redirect 302 — comportamento esperado para navegação de browser.
    """
    from flask import redirect, url_for

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        token = _extract_bearer()
        if not token:
            return redirect(url_for("frontend.login_page"))
        try:
            payload = decode_token(token, expected_type="access")
        except TokenError:
            return redirect(url_for("frontend.login_page"))

        user = db.session.get(User, int(payload["sub"]))
        if user is None or not user.is_active:
            return redirect(url_for("frontend.login_page"))

        g.user = user
        g.role = user.role
        return fn(*args, **kwargs)

    return wrapper


# ===================== API pública (helpers reexportados) =====================
#
# Helpers internos usados pelos endpoints em ``openm.api.auth`` para
# setar/limpar cookies httpOnly e resolver o refresh token a partir
# do body ou do cookie.

__all__ = [
    "TokenError",
    "hash_password",
    "verify_password",
    "encode_token",
    "decode_token",
    "revoke_refresh_token",
    "is_refresh_revoked",
    "require_auth",
    "require_role",
    "login_required_page",
    "_set_auth_cookies",
    "_clear_auth_cookies",
    "_get_refresh_token_from_request",
]
