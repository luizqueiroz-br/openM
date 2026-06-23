"""Modelo SQLAlchemy para tokens de refresh revogados."""

from datetime import datetime, timezone

from openm.extensions import db


class RevokedToken(db.Model):
    """
    Refresh tokens revogados (logout / rotação).

    Access tokens são stateless (TTL curto), por isso não entram aqui.
    Apenas refresh tokens precisam de blacklist porque vivem 7 dias.
    """

    __tablename__ = "revoked_tokens"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    revoked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)

    def to_dict(self) -> dict:  # pragma: no cover - debug
        return {
            "id": self.id,
            "jti": self.jti,
            "user_id": self.user_id,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
