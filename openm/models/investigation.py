from datetime import datetime, timezone
from openm.extensions import db


class Investigation(db.Model):
    """
    Modelo SQLAlchemy para investigações.

    Metadados da investigação (título, descrição, entidade raiz)
    ficam no PostgreSQL, enquanto o grafo em si fica no Neo4j.
    """

    __tablename__ = "investigations"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    root_entity_id = db.Column(db.String(36), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "root_entity_id": self.root_entity_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
