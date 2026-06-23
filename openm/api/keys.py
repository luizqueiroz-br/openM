from flask import Blueprint, jsonify, request
from pydantic import BaseModel, Field, ValidationError

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
def list_keys():
    """
    GET /api/keys

    Lista chaves cadastradas com valores mascarados.
    """
    keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    return jsonify({"keys": [k.to_dict(secure=False) for k in keys]})


@keys_bp.route("/keys", methods=["POST"])
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
    return jsonify({"key": key.to_dict(secure=False)}), 201


@keys_bp.route("/keys/<int:key_id>", methods=["DELETE"])
def delete_key(key_id: int):
    """
    DELETE /api/keys/<id>

    Remove uma chave cadastrada.
    """
    key = ApiKey.query.get_or_404(key_id)
    db.session.delete(key)
    db.session.commit()
    return jsonify({"message": "Chave removida com sucesso"}), 200
