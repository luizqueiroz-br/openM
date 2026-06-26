-- DEPRECATED: superseded by Alembic migration in migrations/versions/.
-- Kept for one release per issue #36. Safe to delete after next deploy.
--
-- Migration v2: Investigations v2 (issues #25 e #29)
-- Adiciona: status, archived_at, graph_snapshot, last_auto_save_at
-- Idempotente: pode rodar múltiplas vezes sem erro.

ALTER TABLE investigations
  ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS graph_snapshot JSON,
  ADD COLUMN IF NOT EXISTS last_auto_save_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS ix_investigations_status ON investigations(status);

-- Backfill defensivo: garante status='active' em qualquer linha legada
-- (não estritamente necessário por causa do DEFAULT, mas explícito é melhor)
UPDATE investigations SET status = 'active' WHERE status IS NULL;
