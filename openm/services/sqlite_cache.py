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
import threading
import time
from contextlib import contextmanager
from typing import Any, Optional


class SqliteCache:
    """Cache SQLite com TTL.

    Auto-cria o schema na inicialização (idempotente). Suporta get/set
    com TTL explícito ou default, delete, clear_expired e clear_all.

    Thread-safety (issue #87):
        A classe usa UMA conexão persistente aberta com
        ``check_same_thread=False`` e ``PRAGMA journal_mode=WAL``
        para permitir leituras concorrentes. Um ``threading.Lock``
        serializa as operações (``get``/``set``/``delete``) para
        evitar ``SQLITE_MISUSE`` quando várias threads usam a mesma
        conexão. Cada chamada individual é curta e protegida pelo
        lock — throughput agregado é suficiente para a carga
        esperada (batch transforms paralelos, max ~50 workers).
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
        # Conexão persistente + cross-thread (issue #87: batch
        # transforms paralelos). WAL mode permite leituras
        # concorrentes e o lock serializa writes e protege o
        # estado de cursors entre threads. Atributo nomeado
        # ``_persist_conn`` para não conflitar com o context
        # manager ``_conn()`` (mantido por compat — testes externos
        # o invocam).
        self._op_lock = threading.Lock()
        self._persist_conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=5.0,
        )
        self._persist_conn.row_factory = sqlite3.Row
        self._persist_conn.execute("PRAGMA journal_mode=WAL")
        self._persist_conn.execute("PRAGMA busy_timeout=5000")
        self._ensure_schema()

    @contextmanager
    def _conn(self):
        """Abre uma conexão AVULSA (não a persistente). Mantido por
        compatibilidade — testes externos (``test_sqlite_cache``,
        ``test_hunter_service``) invocam ``cache._conn()`` para
        inspecionar o DB diretamente. Prefira os métodos ``get``/
        ``set``/``delete`` em código de produção."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self):
        """Cria tabela e índice se não existirem (thread-safe via lock)."""
        with self._op_lock:
            self._persist_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )
            self._persist_conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)"
            )
            self._persist_conn.commit()

    def get(self, key: str) -> Optional[Any]:
        """Retorna valor cacheado ou None se ausente/expirado.

        Entradas expiradas NÃO são removidas eagerly — use
        ``clear_expired()`` periodicamente (ou faça via cron).

        ``expires_at`` é armazenado como float (não int) para evitar
        race conditions de truncamento quando set e get caem no mesmo
        tick de segundo.

        Thread-safe: serializado por ``self._op_lock`` (issue #87).
        """
        with self._op_lock:
            row = self._persist_conn.execute(
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

        Thread-safe: serializado por ``self._op_lock`` (issue #87).
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = time.time() + ttl
        payload = json.dumps(value)
        with self._op_lock:
            self._persist_conn.execute(
                """
                INSERT INTO cache(key, value, expires_at)
                VALUES(?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    expires_at=excluded.expires_at
                """,
                (key, payload, expires_at),
            )
            self._persist_conn.commit()

    def delete(self, key: str) -> None:
        """Remove entrada específica. Thread-safe (issue #87)."""
        with self._op_lock:
            self._persist_conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self._persist_conn.commit()

    def clear_expired(self) -> int:
        """Remove entradas expiradas. Retorna count removido. Thread-safe."""
        with self._op_lock:
            cur = self._persist_conn.execute(
                "DELETE FROM cache WHERE expires_at <= ?", (time.time(),)
            )
            removed = cur.rowcount
            self._persist_conn.commit()
        return removed

    def clear_all(self) -> int:
        """Limpa TUDO. Retorna count removido. Thread-safe."""
        with self._op_lock:
            cur = self._persist_conn.execute("DELETE FROM cache")
            removed = cur.rowcount
            self._persist_conn.commit()
        return removed
