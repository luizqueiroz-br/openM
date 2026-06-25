"""
Blueprint de autenticação: /api/auth/*

Endpoints:
- POST /api/auth/register  (opcional, gated por ALLOW_REGISTRATION)
- POST /api/auth/login
- POST /api/auth/refresh
- POST /api/auth/logout
- GET  /api/auth/me
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from email_validator import EmailNotValidError, validate_email
from flask import Blueprint, current_app, jsonify, request
from pydantic import BaseModel, Field, ValidationError

from openm.core.auth import (
    TokenError,
    _clear_auth_cookies,
    _get_refresh_token_from_request,
    _set_auth_cookies,
    decode_token,
    encode_token,
    hash_password,
    is_refresh_revoked,
    require_auth,
    revoke_refresh_token,
    verify_password,
)
from openm.core.audit import (
    log_action,
    ACTION_LOGIN_FAILED,
    ACTION_LOGIN_SUCCESS,
    ACTION_LOGOUT,
    ACTION_REGISTER,
)
from openm.extensions import db, limiter
from openm.models.user import User, VALID_ROLES

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# ================ Payloads ================

class RegisterPayload(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=128)
    role: str = "analyst"


class LoginPayload(BaseModel):
    email: str
    password: str


# ================ Helpers ================

def _normalize_email(raw: str) -> str:
    """Valida e normaliza (lower + gmail-style dots). Levanta ValueError."""
    try:
        info = validate_email(raw, check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValueError(str(exc)) from exc
    return info.normalized


def _is_registration_allowed() -> bool:
    return bool(current_app.config.get("ALLOW_REGISTRATION", False))


def _issue_token_pair(user: User) -> dict:
    """Emite access (15min) + refresh (7d). Devolve dict pronto pra JSON."""
    access_ttl = timedelta(minutes=current_app.config["JWT_ACCESS_TTL_MINUTES"])
    refresh_ttl = timedelta(days=current_app.config["JWT_REFRESH_TTL_DAYS"])

    access, _, _ = encode_token(user=user, token_type="access", ttl=access_ttl)
    refresh, refresh_jti, refresh_exp = encode_token(
        user=user, token_type="refresh", ttl=refresh_ttl
    )

    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": int(access_ttl.total_seconds()),
        "refresh_expires_at": refresh_exp.isoformat(),
        "refresh_jti": refresh_jti,  # útil para testes
        "user": user.to_dict(),
    }


def _attach_auth_cookies(response, token_pair: dict) -> None:
    """Atalho: seta cookies httpOnly a partir do dict retornado por _issue_token_pair."""
    _set_auth_cookies(
        response,
        access_token=token_pair["access_token"],
        refresh_token=token_pair["refresh_token"],
        refresh_expires_at=datetime.fromisoformat(token_pair["refresh_expires_at"]),
    )


# ================ Endpoints ================

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("3 per hour")
def register():
    """
    POST /api/auth/register

    Cria um novo usuário. Bloqueado se ``ALLOW_REGISTRATION=false`` (padrão prod).
    """
    if not _is_registration_allowed():
        return jsonify({"error": "registration disabled"}), 403

    data = request.get_json(silent=True) or {}
    try:
        payload = RegisterPayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    try:
        email = _normalize_email(payload.email)
    except ValueError as exc:
        return jsonify({"error": f"invalid email: {exc}"}), 400

    if payload.role not in VALID_ROLES:
        return jsonify({"error": f"role must be one of {list(VALID_ROLES)}"}), 400

    if User.query.filter_by(email=email).first():
        # Mensagem genérica para não revelar quais emails já existem.
        return jsonify({"error": "could not register"}), 409

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.session.add(user)
    db.session.commit()
    # Auditoria: registrar criação de usuário. metadata SEM password (sanitização
    # já remove, mas explicitamente não passamos o payload original).
    log_action(
        action=ACTION_REGISTER,
        target_type="user",
        target_id=str(user.id),
        metadata={"email": email, "role": payload.role},
        user_id=user.id,
    )
    return jsonify({"user": user.to_dict()}), 201


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    """
    POST /api/auth/login

    Body: ``{"email": "...", "password": "..."}``
    Retorna access + refresh tokens.
    """
    data = request.get_json(silent=True) or {}
    try:
        payload = LoginPayload(**data)
    except ValidationError as exc:
        # Body malformado — também auditado como falha (sem email válido,
        # então metadata.email_attempted fica como o que o usuário mandou,
        # ou None se não houver campo).
        log_action(
            action=ACTION_LOGIN_FAILED,
            target_type="user",
            metadata={
                "reason": "invalid_payload",
                "email_attempted": (data.get("email") if isinstance(data, dict) else None),
            },
        )
        return jsonify({"error": exc.errors()}), 400

    try:
        email = _normalize_email(payload.email)
    except ValueError:
        # Email inválido — não conseguimos nem normalizar, então não há
        # alvo definido. Audit genérico.
        log_action(
            action=ACTION_LOGIN_FAILED,
            target_type="user",
            metadata={"reason": "invalid_email_format"},
        )
        return jsonify({"error": "invalid credentials"}), 401

    user = User.query.filter_by(email=email).first()
    # Mesma resposta para "não existe" e "senha errada" — anti-enumeração.
    if user is None or not user.is_active or not verify_password(
        payload.password, user.password_hash
    ):
        # Não distinguimos os motivos no metadata (anti-enumeração).
        # Registramos apenas o email tentado (não revela se existe) e
        # o IP. target_id fica None quando o usuário não existe.
        log_action(
            action=ACTION_LOGIN_FAILED,
            target_type="user",
            target_id=str(user.id) if user is not None else None,
            user_id=user.id if user is not None else None,
            metadata={
                "reason": "invalid_credentials",
                "email_attempted": email,
            },
        )
        return jsonify({"error": "invalid credentials"}), 401

    token_pair = _issue_token_pair(user)
    response = jsonify(token_pair)
    _attach_auth_cookies(response, token_pair)
    # Auditoria: login bem-sucedido. Não logamos tokens nem IP sensível
    # além do que o helper já captura.
    log_action(
        action=ACTION_LOGIN_SUCCESS,
        target_type="user",
        target_id=str(user.id),
        user_id=user.id,
    )
    return response, 200


@auth_bp.route("/refresh", methods=["POST"])
@limiter.limit("30 per minute")
def refresh():
    """
    POST /api/auth/refresh

    Body: ``{"refresh_token": "..."}`` OU cookie httpOnly ``openm_refresh``.
    Rotaciona o refresh token: o antigo vai pra blacklist, um novo par é emitido.
    """
    refresh_token = _get_refresh_token_from_request()
    if not refresh_token:
        return jsonify({"error": "refresh_token required (body or cookie)"}), 400

    try:
        claims = decode_token(refresh_token, expected_type="refresh")
    except TokenError as exc:
        return jsonify({"error": str(exc)}), 401

    jti = claims["jti"]
    if is_refresh_revoked(jti):
        return jsonify({"error": "token revoked"}), 401

    user = db.session.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        return jsonify({"error": "user not found or inactive"}), 401

    # Revoga o refresh apresentado (rotação).
    revoke_refresh_token(
        jti=jti,
        user_id=user.id,
        expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
    )

    token_pair = _issue_token_pair(user)
    response = jsonify(token_pair)
    _attach_auth_cookies(response, token_pair)
    return response, 200


@auth_bp.route("/logout", methods=["POST"])
@limiter.limit("30 per minute")
def logout():
    """
    POST /api/auth/logout

    Body: ``{"refresh_token": "..."}`` OU cookie httpOnly ``openm_refresh``.
    Revoga o refresh token e limpa os cookies. Idempotente.
    """
    refresh_token = _get_refresh_token_from_request()
    response = jsonify({"status": "logged out"})

    logged_out_user_id: int | None = None
    if refresh_token:
        try:
            claims = decode_token(refresh_token, expected_type="refresh")
        except TokenError:
            # Idempotente: logout de token já inválido é sucesso silencioso.
            _clear_auth_cookies(response)
            log_action(
                action=ACTION_LOGOUT,
                target_type="user",
                metadata={"reason": "invalid_token"},
            )
            return response, 200

        revoke_refresh_token(
            jti=claims["jti"],
            user_id=int(claims["sub"]),
            expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
        )
        logged_out_user_id = int(claims["sub"])

    _clear_auth_cookies(response)
    # Auditoria: logout bem-sucedido (com user_id quando temos o token válido).
    log_action(
        action=ACTION_LOGOUT,
        target_type="user",
        user_id=logged_out_user_id,
    )
    return response, 200


@auth_bp.route("/me", methods=["GET"])
@require_auth
def me():
    """GET /api/auth/me — perfil do usuário autenticado."""
    from flask import g

    return jsonify({"user": g.user.to_dict()}), 200
