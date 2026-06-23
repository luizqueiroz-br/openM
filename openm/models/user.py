"""Modelo SQLAlchemy para usuários."""

from datetime import datetime, timezone

from openm.extensions import db


# Papéis disponíveis. Mantemos como string (não Enum) para evitar migração
# caso adicionemos um novo papel depois — só precisamos atualizar este set.
VALID_ROLES = ("admin", "analyst", "viewer")


class User(db.Model):
    """
    Usuário da plataforma OpenM.

    A senha nunca é armazenada em texto puro: ``password_hash`` guarda o
    digest bcrypt. A comparação acontece em ``core.auth.verify_password``.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False, default="analyst")
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default="true")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict:
        """Serialização pública — nunca inclui o hash."""
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug
        return f"<User id={self.id} email={self.email!r} role={self.role!r}>"
