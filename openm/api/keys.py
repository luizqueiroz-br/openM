from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, Field, ValidationError

from openm.core.auth import require_auth, require_role
from openm.core.audit import (
    log_action,
    ACTION_APIKEY_CREATE,
    ACTION_APIKEY_UPDATE,
    ACTION_APIKEY_DELETE,
)
from openm.extensions import db
from openm.models.api_key import ApiKey

keys_bp = Blueprint("keys", __name__, url_prefix="/api")


class ApiKeyPayload(BaseModel):
    """Payload para cadastro/edição de API key."""

    service_name: str = Field(..., min_length=1, max_length=64)
    key_value: str = Field(..., min_length=1)
    key_type: str = Field(default="free", pattern="^(free|paid)$")
    is_active: bool = True
    rate_limit_per_day: int | None = None


@keys_bp.route("/keys", methods=["GET"])
@require_auth
def list_keys():
    """
    GET /api/keys

    Lista chaves cadastradas com valores mascarados.
    """
    keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    return jsonify({"keys": [k.to_dict(secure=False) for k in keys]})


@keys_bp.route("/keys", methods=["POST"])
@require_auth
@require_role("admin", "analyst")
def create_or_update_key():
    """
    POST /api/keys

    Cadastra uma nova chave ou atualiza uma existente para o mesmo serviço.
    """
    data = request.get_json(silent=True) or {}
    try:
        payload = ApiKeyPayload(**data)
    except ValidationError as exc:
        return jsonify({"error": exc.errors()}), 400

    existing = ApiKey.query.filter_by(service_name=payload.service_name).first()
    if existing:
        existing.key_value = payload.key_value
        existing.key_type = payload.key_type
        existing.is_active = payload.is_active
        existing.rate_limit_per_day = payload.rate_limit_per_day
        db.session.commit()
        # Auditoria: atualização de chave (defesa em profundidade — mesmo
        # que alguém passe key_value no metadata, a sanitização remove).
        log_action(
            action=ACTION_APIKEY_UPDATE,
            target_type="apikey",
            target_id=str(existing.id),
            user_id=g.user.id,
            metadata={
                "service_name": existing.service_name,
                "key_type": existing.key_type,
            },
        )
        return jsonify({"key": existing.to_dict(secure=False)}), 200

    key = ApiKey(
        service_name=payload.service_name,
        key_value=payload.key_value,
        key_type=payload.key_type,
        is_active=payload.is_active,
        rate_limit_per_day=payload.rate_limit_per_day,
    )
    db.session.add(key)
    db.session.commit()
    log_action(
        action=ACTION_APIKEY_CREATE,
        target_type="apikey",
        target_id=str(key.id),
        user_id=g.user.id,
        metadata={
            "service_name": key.service_name,
            "key_type": key.key_type,
        },
    )
    return jsonify({"key": key.to_dict(secure=False)}), 201


@keys_bp.route("/keys/<int:key_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "analyst")
def delete_key(key_id: int):
    """
    DELETE /api/keys/<id>

    Remove uma chave cadastrada.
    """
    key = ApiKey.query.get_or_404(key_id)
    # Captura ANTES do delete — depois do delete o objeto é detached.
    service_name = key.service_name
    db.session.delete(key)
    db.session.commit()
    # Auditoria: deleção de chave.
    log_action(
        action=ACTION_APIKEY_DELETE,
        target_type="apikey",
        target_id=str(key_id),
        user_id=g.user.id,
        metadata={"service_name": service_name},
    )
    return jsonify({"message": "Chave removida com sucesso"}), 200
