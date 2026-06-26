-- Migration: Investigation versioning (issue #37)
-- Adiciona coluna version para optimistic locking.
-- Idempotente: pode rodar múltiplas vezes sem erro.

ALTER TABLE investigations
  ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;

-- Backfill defensivo: garante version=1 em qualquer linha legada.
-- (Não é estritamente necessário por causa do DEFAULT, mas explícito
-- é melhor — protege contra linhas que poderiam ter ficado com NULL
-- se alguém rodasse a migration antes do DEFAULT estar em vigor.)
UPDATE investigations SET version = 1 WHERE version IS NULL;
