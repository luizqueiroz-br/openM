"""
Cache SQLite simples com TTL para respostas de APIs externas.

Pensado para free tiers com quota apertada (ex.: Hunter.io 50 req/mês).
Não é para hot-path performance — é para evitar re-consultas repetidas.

Schema:
    CREATE TABLE cache (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,        -- JSON serializado
        expires_at INTEGER NOT NULL  -- unix timestamp
    );

Localização do arquivo: configurável via env ``OPENM_CACHE_DB``
(default: ``/tmp/openm_cache.db``). Cada serviço pode passar um path
próprio (ex.: Hunter usa ``HUNTER_CACHE_PATH``).
"""

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Optional


class SqliteCache:
    """Cache SQLite com TTL.

    Auto-cria o schema na inicialização (idempotente). Suporta get/set
    com TTL explícito ou default, delete, clear_expired e clear_all.
    """

    DEFAULT_DB_PATH = "/tmp/openm_cache.db"

    def __init__(
        self,
        db_path: Optional[str] = None,
        default_ttl: int = 7 * 24 * 3600,
    ):
        self.db_path = db_path or os.environ.get(
            "OPENM_CACHE_DB", self.DEFAULT_DB_PATH
        )
        self.default_ttl = default_ttl
        self._ensure_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self):
        """Cria tabela e índice se não existirem."""
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)"
            )

    def get(self, key: str) -> Optional[Any]:
        """Retorna valor cacheado ou None se ausente/expirado.

        Entradas expiradas NÃO são removidas eagerly — use
        ``clear_expired()`` periodicamente (ou faça via cron).

        ``expires_at`` é armazenado como float (não int) para evitar
        race conditions de truncamento quando set e get caem no mesmo
        tick de segundo.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return None
        if row["expires_at"] <= time.time():
            return None
        try:
            return json.loads(row["value"])
        except (ValueError, TypeError):
            # Payload corrompido — apaga e retorna None
            self.delete(key)
            return None

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None):
        """Armazena valor com TTL (default: self.default_ttl).

        Sobrescreve silenciosamente se a chave já existir.

        ``expires_at`` é float (``time.time() + ttl``) para evitar
        flakiness de sub-segundo.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = time.time() + ttl
        payload = json.dumps(value)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO cache(key, value, expires_at)
                VALUES(?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    expires_at=excluded.expires_at
                """,
                (key, payload, expires_at),
            )

    def delete(self, key: str) -> None:
        """Remove entrada específica."""
        with self._conn() as conn:
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))

    def clear_expired(self) -> int:
        """Remove entradas expiradas. Retorna count removido."""
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM cache WHERE expires_at <= ?", (time.time(),)
            )
            return cur.rowcount

    def clear_all(self) -> int:
        """Limpa TUDO. Retorna count removido."""
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM cache")
            return cur.rowcount
