from datetime import datetime, timezone
from openm.extensions import db


class Investigation(db.Model):
    """
    Modelo SQLAlchemy para investigações.

    Metadados da investigação (título, descrição, entidade raiz)
    ficam no PostgreSQL, enquanto o grafo em si fica no Neo4j.

    Multi-usuário (issue #2): cada investigação pertence a um User
    (FK user_id). Endpoints filtram por dono automaticamente — user A
    não vê, edita nem deleta investigações de user B.

    v2 (issue #25): cada investigation tem um status ('active' ou
    'archived'), um snapshot JSON completo do grafo (source of truth
    pra reabrir) e tracking de auto-save.

    v3 (issue #37): coluna ``version`` para optimistic locking. PUT
    incrementa a versão atomicamente; clientes enviam ``If-Match``
    e recebem 409 se mudou. Archive/unarchive/delete NÃO mexem nela
    (são idempotentes).
    """

    __tablename__ = "investigations"

    # Status permitidos
    STATUS_ACTIVE = "active"
    STATUS_ARCHIVED = "archived"
    VALID_STATUSES = (STATUS_ACTIVE, STATUS_ARCHIVED)

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    root_entity_id = db.Column(db.String(36), nullable=True, index=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,  # nullable=True pra permitir investigations antigas (criadas antes da #2)
        index=True,
    )
    status = db.Column(
        db.String(16),
        nullable=False,
        default=STATUS_ACTIVE,
        server_default=STATUS_ACTIVE,
        index=True,
    )
    # Optimistic locking (issue #37). Incrementado pelo PUT (não por
    # archive/unarchive/delete — são idempotentes). Clientes enviam
    # ``If-Match: "<version>"`` para detectar conflitos; mismatch → 409.
    version = db.Column(
        db.Integer,
        nullable=False,
        default=1,
        server_default="1",
    )
    archived_at = db.Column(db.DateTime, nullable=True)
    graph_snapshot = db.Column(db.JSON, nullable=True)
    # Estrutura esperada: { nodes: [...], edges: [...] } — Cytoscape normalizado
    # Nullable pra investigations legadas (criadas antes desta v2).
    last_auto_save_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationship — permite acessar user via inv.user
    user = db.relationship("User", backref=db.backref("investigations", lazy="dynamic"))

    def archive(self) -> None:
        """Marca a investigação como arquivada."""
        self.status = self.STATUS_ARCHIVED
        self.archived_at = datetime.now(timezone.utc)

    def unarchive(self) -> None:
        """Restaura a investigação para o estado ativo."""
        self.status = self.STATUS_ACTIVE
        self.archived_at = None

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "root_entity_id": self.root_entity_id,
            "user_id": self.user_id,
            "status": self.status,
            "version": self.version,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
            "last_auto_save_at": (
                self.last_auto_save_at.isoformat() if self.last_auto_save_at else None
            ),
            "graph_snapshot": self.graph_snapshot,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
