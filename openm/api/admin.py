"""
Admin API (issue #3): gestão de usuários e papéis.

Endpoints (todos exigem ``@require_role("admin")``):
- GET    /api/admin/users              — listar usuários
- PATCH  /api/admin/users/<id>/role    — alterar role
- PATCH  /api/admin/users/<id>/active  — ativar / desativar conta

Regras de proteção:
- Nenhum admin pode rebaixar/desativar a si mesmo (evita lock-out total).
- Não é permitido remover o último admin ativo do sistema.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, ValidationError
from flask import Blueprint, g, jsonify, request

from openm.core.auth import require_auth, require_role
from openm.core.audit import (
    log_action,
    ACTION_USER_ACTIVE_CHANGE,
    ACTION_USER_ROLE_CHANGE,
)
from openm.extensions import db
from openm.models.user import User, VALID_ROLES


admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


# ===================== Payloads =====================

class UpdateRolePayload(BaseModel):
    role: str = Field(..., min_length=1)


class UpdateActivePayload(BaseModel):
    is_active: bool


# ===================== Helpers =====================

def _count_active_admins() -> int:
    """Conta quantos usuários estão ativos com role='admin'."""
    return (
        User.query
        .filter(User.role == "admin", User.is_active.is_(True))
        .count()
    )


# ===================== GET /api/admin/users =====================

@admin_bp.route("/users", methods=["GET"])
@require_auth
@require_role("admin")
def list_users():
    """
    GET /api/admin/users

    Lista todos os usuários (apenas admin).
    """
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"users": [u.to_dict() for u in users]})


# ===================== PATCH /api/admin/users/<id>/role =====================

@admin_bp.route("/users/<int:user_id>/role", methods=["PATCH"])
@require_auth
@require_role("admin")
def update_user_role(user_id: int):
    """
    PATCH /api/admin/users/<id>/role

    Body: ``{"role": "admin" | "analyst" | "viewer"}``

    Proteções:
    - Admin não pode rebaixar a si mesmo.
    - Não é permitido rebaixar o último admin ativo.
    """
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({"error": "user not found"}), 404

    data = request.get_json(silent=True) or {}
    try:
        payload = UpdateRolePayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    if payload.role not in VALID_ROLES:
        return jsonify({"error": f"role must be one of {list(VALID_ROLES)}"}), 400

    is_self = target.id == g.user.id
    old_role = target.role
    was_admin = old_role == "admin"
    becomes_non_admin = payload.role != "admin"

    if is_self and was_admin and becomes_non_admin:
        return jsonify({
            "error": "admin cannot demote themselves"
        }), 409

    if was_admin and becomes_non_admin and target.is_active:
        # Garantir que ainda reste pelo menos 1 admin ativo após a operação.
        if _count_active_admins() <= 1:
            return jsonify({
                "error": "cannot demote the last active admin"
            }), 409

    target.role = payload.role
    db.session.commit()
    # Auditoria: registra mudança de role. Capturamos old_role ANTES da
    # mutação para ter o valor original.
    log_action(
        action=ACTION_USER_ROLE_CHANGE,
        target_type="user",
        target_id=str(target.id),
        user_id=g.user.id,
        metadata={
            "old_role": old_role,
            "new_role": payload.role,
            "target_email": target.email,
        },
    )
    return jsonify({"user": target.to_dict()}), 200


# ===================== PATCH /api/admin/users/<id>/active =====================

@admin_bp.route("/users/<int:user_id>/active", methods=["PATCH"])
@require_auth
@require_role("admin")
def update_user_active(user_id: int):
    """
    PATCH /api/admin/users/<id>/active

    Body: ``{"is_active": true | false}``

    Proteções:
    - Admin não pode desativar a si mesmo.
    - Desativar o último admin ativo é bloqueado.
    """
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({"error": "user not found"}), 404

    data = request.get_json(silent=True) or {}
    try:
        payload = UpdateActivePayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    is_self = target.id == g.user.id
    is_currently_admin = target.role == "admin"
    is_currently_active = target.is_active

    if is_self and is_currently_admin and is_currently_active and not payload.is_active:
        return jsonify({
            "error": "admin cannot deactivate themselves"
        }), 409

    if (
        is_currently_admin
        and is_currently_active
        and not payload.is_active
        and _count_active_admins() <= 1
    ):
        return jsonify({
            "error": "cannot deactivate the last active admin"
        }), 409

    target.is_active = payload.is_active
    db.session.commit()
    # Auditoria: registra ativação/desativação de conta.
    log_action(
        action=ACTION_USER_ACTIVE_CHANGE,
        target_type="user",
        target_id=str(target.id),
        user_id=g.user.id,
        metadata={
            "old_is_active": is_currently_active,
            "new_is_active": payload.is_active,
            "target_email": target.email,
        },
    )
    return jsonify({"user": target.to_dict()}), 200
