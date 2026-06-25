-- Migration: audit_log (issue #4)
-- Cria a tabela de auditoria de ações sensíveis.
-- Idempotente: pode rodar múltiplas vezes sem erro.

CREATE TABLE IF NOT EXISTS audit_log (
  id           SERIAL PRIMARY KEY,
  user_id      INT REFERENCES users(id) ON DELETE SET NULL,
  action       VARCHAR(64) NOT NULL,
  target_type  VARCHAR(32),
  target_id    VARCHAR(64),
  metadata     JSONB,
  ip_address   VARCHAR(45),  -- comporta IPv6 comprimido (max 45 chars)
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Índices: criados após a tabela (CREATE INDEX IF NOT EXISTS é seguro repetir).
-- created_at: range queries + retenção ("logs dos últimos N dias")
-- user_id:   filtro "ações do usuário X"
-- action:    filtro "todos os logins falhados" (queries frequentes p/ SOC)
CREATE INDEX IF NOT EXISTS ix_audit_log_created_at ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_log_user_id    ON audit_log (user_id);
CREATE INDEX IF NOT EXISTS ix_audit_log_action     ON audit_log (action);