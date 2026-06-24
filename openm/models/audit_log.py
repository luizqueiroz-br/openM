"""
Modelo SQLAlchemy para a tabela ``audit_log`` (issue #4).

Decisões de design:

- ``user_id`` é **nullable** para acomodar ações anônimas (ex.: tentativa
  de login com email inexistente) onde ainda não sabemos quem é o ator.
- ``metadata`` usa ``db.JSON`` (portável: vira JSONB no Postgres, TEXT
  em SQLite para os testes).
- ``ip_address`` usa ``db.String(45)`` (tamanho máximo de um IPv6
  comprimido, ex.: ``::ffff:192.0.2.128``) — mais simples e portátil
  que ``INET`` do Postgres, e suficiente para auditoria.
- Índices em ``created_at`` (range queries / retenção), ``user_id``
  (filtros) e ``action`` (filtros). Não criamos índice composto: o
  tráfego esperado é baixo e queries compostas se beneficiam mais do
  filtro por created_at.

**Importante**: o helper ``openm.core.audit.log_action`` é responsável
por sanitizar ``metadata`` antes de gravar (remover ``password``,
``token``, ``api_key``, etc.). Esta camada model NÃO confia no caller.
"""

from __future__ import annotations

from datetime import datetime, timezone

from openm.extensions import db


class AuditLog(db.Model):
    """
    Registro de auditoria para ações sensíveis.

    Cada linha representa **um evento** (não agregação). Eventos típicos:

    - ``user.login.success``
    - ``user.login.failed``
    - ``user.logout``
    - ``user.register``
    - ``user.role.change``
    - ``user.active.change``
    - ``entity.create`` / ``entity.update`` / ``entity.delete``
    - ``transform.run``
    - ``investigation.create`` / ``investigation.update`` /
      ``investigation.archive`` / ``investigation.unarchive``
    - ``apikey.create`` / ``apikey.update`` / ``apikey.delete``

    Esta classe não deve ser usada diretamente pelo código de aplicação:
    sempre prefira ``openm.core.audit.log_action``.
    """

    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)

    # Nullable: ações anônimas (login falhado antes de identificar o user)
    # precisam ser registradas sem FK.
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Nome da ação em dotted notation (ex.: "user.login.success").
    # Mantemos VARCHAR(64) conforme spec da issue.
    action = db.Column(db.String(64), nullable=False, index=True)

    # Tipo do recurso afetado (ex.: "user", "entity", "investigation").
    target_type = db.Column(db.String(32), nullable=True)
    # ID do recurso (string para acomodar tanto IDs numéricos quanto
    # UUIDs / slugs do Neo4j).
    target_id = db.Column(db.String(64), nullable=True)

    # Metadados adicionais da ação (request_id, ip extraído de X-Forwarded-For,
    # diffs, motivo de falha etc.). JSONB no Postgres.
    meta = db.Column("metadata", db.JSON, nullable=True)

    # IP de origem (X-Forwarded-For se presente, senão remote_addr).
    # VARCHAR(45) acomoda IPv6 comprimido (max "::ffff:255.255.255.255" = 45 chars).
    ip_address = db.Column(db.String(45), nullable=True)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationship opcional — útil para queries que já carregam o user.
    user = db.relationship("User", backref=db.backref("audit_events", lazy="dynamic"))

    def to_dict(self) -> dict:
        """Serialização para a API de leitura (admin)."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "metadata": self.meta,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug
        return (
            f"<AuditLog id={self.id} action={self.action!r} "
            f"user_id={self.user_id} target={self.target_type}:{self.target_id}>"
        )
