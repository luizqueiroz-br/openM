"""Cobertura do helper SqliteCache (usado por HunterService e futuro).

Garante:
- get/set com serialização JSON correta
- expiração por TTL
- clear_expired e clear_all
- persistência entre instâncias (mesmo arquivo)
- idempotência do schema (chamar 2x não falha)
"""

import os
import time

from openm.services.sqlite_cache import SqliteCache


class TestSqliteCache:
    def test_set_and_get(self, tmp_path):
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        cache.set("k1", {"a": 1, "b": [1, 2]})
        assert cache.get("k1") == {"a": 1, "b": [1, 2]}

    def test_get_missing_returns_none(self, tmp_path):
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        assert cache.get("missing") is None

    def test_ttl_expiry(self, tmp_path):
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        cache.set("k1", "value", ttl_seconds=1)
        assert cache.get("k1") == "value"
        time.sleep(1.2)
        assert cache.get("k1") is None

    def test_set_overwrites_existing(self, tmp_path):
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        cache.set("k1", "old")
        cache.set("k1", "new")
        assert cache.get("k1") == "new"

    def test_clear_expired(self, tmp_path):
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        cache.set("k1", "v1", ttl_seconds=1)
        cache.set("k2", "v2", ttl_seconds=1000)
        time.sleep(1.2)
        removed = cache.clear_expired()
        assert removed >= 1
        assert cache.get("k1") is None
        assert cache.get("k2") == "v2"

    def test_clear_all(self, tmp_path):
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        cache.set("k1", "v1")
        cache.set("k2", "v2")
        assert cache.clear_all() == 2
        assert cache.get("k1") is None
        assert cache.get("k2") is None

    def test_complex_value(self, tmp_path):
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        complex_value = {
            "list": [1, 2, 3],
            "nested": {"a": {"b": "c"}},
            "unicode": "ação中文",
        }
        cache.set("k1", complex_value)
        assert cache.get("k1") == complex_value

    def test_delete(self, tmp_path):
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        cache.set("k1", "v1")
        cache.delete("k1")
        assert cache.get("k1") is None

    def test_delete_missing_no_error(self, tmp_path):
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        cache.delete("never-existed")  # não pode levantar exceção

    def test_persistence_across_instances(self, tmp_path):
        path = str(tmp_path / "cache.db")
        c1 = SqliteCache(db_path=path)
        c1.set("k1", "persisted")
        c2 = SqliteCache(db_path=path)
        assert c2.get("k1") == "persisted"

    def test_schema_creation_idempotent(self, tmp_path):
        path = str(tmp_path / "cache.db")
        SqliteCache(db_path=path)
        SqliteCache(db_path=path)  # segunda vez não pode falhar
        # Se chegamos aqui sem exception, está ok

    def test_default_ttl_override(self, tmp_path):
        """default_ttl passado no construtor sobrescreve o default de classe."""
        cache = SqliteCache(
            db_path=str(tmp_path / "cache.db"),
            default_ttl=2,
        )
        cache.set("k1", "v")
        assert cache.default_ttl == 2
        time.sleep(2.2)
        assert cache.get("k1") is None

    def test_env_var_used_when_no_path(self, tmp_path, monkeypatch):
        """Se nenhum db_path é passado, usa OPENM_CACHE_DB do ambiente."""
        path = str(tmp_path / "envcache.db")
        monkeypatch.setenv("OPENM_CACHE_DB", path)
        cache = SqliteCache()
        try:
            cache.set("k1", "env")
            assert cache.get("k1") == "env"
            assert cache.db_path == path
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_corrupted_payload_returns_none_and_deletes(self, tmp_path):
        """Se o JSON estiver corrompido, get retorna None e apaga a entrada."""
        cache = SqliteCache(db_path=str(tmp_path / "cache.db"))
        # Inserimos manualmente uma entrada com JSON inválido
        with cache._conn() as conn:
            conn.execute(
                "INSERT INTO cache(key, value, expires_at) VALUES(?, ?, ?)",
                ("bad", "{not-valid-json", time.time() + 3600),
            )
        # get deve tratar o erro e apagar
        assert cache.get("bad") is None
        # Confirma que foi removida
        with cache._conn() as conn:
            row = conn.execute(
                "SELECT key FROM cache WHERE key = ?", ("bad",)
            ).fetchone()
        assert row is None
