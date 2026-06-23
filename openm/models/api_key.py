from datetime import datetime, timezone
from openm.extensions import db


class ApiKey(db.Model):
    """
    Armazena chaves de API para serviços de OSINT/Threat Intel.

    Permite cadastrar chaves free e paid, ativar/desativar e
    acompanhar uso. O valor real é devolvido apenas para uso
    interno; a API de listagem mascara parcialmente a chave.
    """

    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(64), nullable=False, index=True)
    key_value = db.Column(db.Text, nullable=False)
    key_type = db.Column(db.String(16), nullable=False, default="free")
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    rate_limit_per_day = db.Column(db.Integer, nullable=True)
    usage_count = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def masked_key(self) -> str:
        """Retorna a chave mascarada para exibição segura."""
        if len(self.key_value) <= 8:
            return "****"
        return f"{self.key_value[:4]}****{self.key_value[-4:]}"

    def to_dict(self, secure: bool = False):
        data = {
            "id": self.id,
            "service_name": self.service_name,
            "key_type": self.key_type,
            "is_active": self.is_active,
            "rate_limit_per_day": self.rate_limit_per_day,
            "usage_count": self.usage_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if secure:
            data["key_value"] = self.key_value
        else:
            data["masked_key"] = self.masked_key()
        return data
