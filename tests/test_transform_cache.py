"""
Testes para o cache de resultados de transform (issue #84).

Cobre:
- make_cache_key: normalização
- get/set/clear no cache (wrapper sobre SqliteCache)
- Integração: API /api/run_transform consulta cache antes de executar,
  retorna X-Cache: HIT em HIT, salva em MISS, BYPASS com force=true.
"""


# ====================================================================
# transform_cache — unit tests
# ====================================================================


def test_make_cache_key_basic():
    from openm.core.transform_cache import make_cache_key

    key = make_cache_key("whois_lookup", "Domain", "example.com")
    assert key == "whois_lookup:Domain:example.com"


def test_make_cache_key_normalizes_value():
    """Valor é normalizado para lowercase + strip."""
    from openm.core.transform_cache import make_cache_key

    assert make_cache_key("whois", "Domain", "EXAMPLE.COM") == "whois:Domain:example.com"
    assert make_cache_key("whois", "Domain", "  example.com  ") == "whois:Domain:example.com"


def test_make_cache_key_normalizes_transform_name():
    """Transform name também é normalizado."""
    from openm.core.transform_cache import make_cache_key

    assert make_cache_key("WHOIS_LOOKUP", "Domain", "x.com") == "whois_lookup:Domain:x.com"


def test_make_cache_key_different_values_different_keys():
    """Valores diferentes produzem chaves diferentes."""
    from openm.core.transform_cache import make_cache_key

    a = make_cache_key("whois", "Domain", "example.com")
    b = make_cache_key("whois", "Domain", "other.com")
    assert a != b


def test_set_and_get_cached_result(tmp_path, monkeypatch):
    """set + get round-trip funciona."""
    from openm.core import transform_cache as tc

    db = str(tmp_path / "cache.db")
    monkeypatch.setattr(tc, "_default_cache", None)
    monkeypatch.setenv("OPENM_CACHE_DB", db)

    payload = {
        "input": {"id": "x", "type": "Domain", "value": "example.com"},
        "entities": [{"id": "y", "type": "Domain", "value": "sub.example.com"}],
        "relationships": [],
    }
    tc.set_cached_result("whois", "Domain", "example.com", payload, ttl_seconds=60)

    result = tc.get_cached_result("whois", "Domain", "example.com")
    assert result == payload


def test_set_cached_result_zero_ttl_is_noop(tmp_path, monkeypatch):
    """TTL=0 não persiste nada."""
    from openm.core import transform_cache as tc

    db = str(tmp_path / "cache.db")
    monkeypatch.setattr(tc, "_default_cache", None)
    monkeypatch.setenv("OPENM_CACHE_DB", db)

    tc.set_cached_result("whois", "Domain", "x.com", {"a": 1}, ttl_seconds=0)

    assert tc.get_cached_result("whois", "Domain", "x.com") is None


def test_get_cached_result_returns_none_when_absent(tmp_path, monkeypatch):
    from openm.core import transform_cache as tc

    db = str(tmp_path / "cache.db")
    monkeypatch.setattr(tc, "_default_cache", None)
    monkeypatch.setenv("OPENM_CACHE_DB", db)

    assert tc.get_cached_result("nope", "Domain", "missing.com") is None


def test_clear_cache_for_removes_entry(tmp_path, monkeypatch):
    from openm.core import transform_cache as tc

    db = str(tmp_path / "cache.db")
    monkeypatch.setattr(tc, "_default_cache", None)
    monkeypatch.setenv("OPENM_CACHE_DB", db)

    tc.set_cached_result("whois", "Domain", "x.com", {"a": 1}, ttl_seconds=60)
    assert tc.get_cached_result("whois", "Domain", "x.com") is not None

    tc.clear_cache_for("whois", "Domain", "x.com")
    assert tc.get_cached_result("whois", "Domain", "x.com") is None


def test_cache_survives_module_reload(tmp_path, monkeypatch):
    """Cache persistido é recuperado após reload do módulo.

    Simula um reload resetando o singleton — o cache no disco
    (apontado por OPENM_CACHE_DB) deve continuar acessível.
    """
    from openm.core import transform_cache as tc

    db = str(tmp_path / "cache.db")
    # IMPORTANTE: resetar o singleton ANTES de set/get para garantir
    # que o cache seja criado lendo o env var (tmp_path). Sem isso,
    # set/get usaria o singleton ja inicializado de um teste anterior.
    monkeypatch.setattr(tc, "_default_cache", None)
    monkeypatch.setenv("OPENM_CACHE_DB", db)

    tc.set_cached_result("whois", "Domain", "x.com", {"a": 1}, ttl_seconds=60)
    # Simula reload: zera o singleton. _get_cache() recriara lendo o
    # env var (mesmo path), mas o conteudo persistido em disco continua.
    monkeypatch.setattr(tc, "_default_cache", None)

    result = tc.get_cached_result("whois", "Domain", "x.com")
    assert result == {"a": 1}


# ====================================================================
# Transform base class — cache_ttl_seconds default
# ====================================================================


def test_transform_default_cache_ttl_is_zero():
    """Transform base tem cache_ttl_seconds=0 por padrão (opt-in)."""
    from openm.core.transform import Transform

    # Pega o valor default da classe base
    assert Transform.cache_ttl_seconds == 0


def test_each_transform_declares_its_ttl():
    """Cada transform declara um TTL > 0 exceto email_to_domain."""
    from openm.core.transform import TransformRegistry

    expected = {
        "resolve_ip": 3600,
        "reverse_dns": 3600,
        "whois_lookup": 86400,
        "geoip_lookup": 604800,
        "crtsh_lookup": 86400,
        "check_fraud_email": 3600,
        "hunter_domain_search": 21600,
        "hunter_email_verifier": 21600,
        "shodan_lookup": 21600,
        "virustotal_lookup": 21600,
        "email_to_domain": 0,
    }

    for name, expected_ttl in expected.items():
        cls = TransformRegistry.get(name)
        assert cls is not None, f"{name} nao registrado"
        assert cls.cache_ttl_seconds == expected_ttl, (
            f"{name} tem TTL={cls.cache_ttl_seconds}, esperado {expected_ttl}"
        )


# ====================================================================
# API /api/run_transform — caching behavior
# ====================================================================


class TestRunTransformCache:
    """Cobertura do cache no endpoint /api/run_transform."""

    def test_cache_miss_returns_x_cache_miss_header(
        self, app, auth_client, monkeypatch, tmp_path
    ):
        """Primeira execução sem cache → X-Cache: MISS."""
        from openm.core import transform_cache as tc

        db = str(tmp_path / "cache.db")
        monkeypatch.setattr(tc, "_default_cache", None)
        monkeypatch.setenv("OPENM_CACHE_DB", db)

        # whois_lookup tem TTL=86400 e é Domain
        resp = auth_client.post(
            "/api/run_transform",
            json={
                "transform_name": "whois_lookup",
                "entity_type": "Domain",
                "value": "miss-cache-test.com",
            },
        )
        assert resp.status_code == 200
        assert resp.headers.get("X-Cache") == "MISS"

    def test_cache_hit_returns_x_cache_hit_header(
        self, app, auth_client, monkeypatch, tmp_path
    ):
        """Segunda execução com mesmo value → X-Cache: HIT."""
        from openm.core import transform_cache as tc

        db = str(tmp_path / "cache.db")
        monkeypatch.setattr(tc, "_default_cache", None)
        monkeypatch.setenv("OPENM_CACHE_DB", db)

        payload = {
            "transform_name": "whois_lookup",
            "entity_type": "Domain",
            "value": "hit-cache-test.com",
        }

        # Primeira execução → MISS
        r1 = auth_client.post("/api/run_transform", json=payload)
        assert r1.headers.get("X-Cache") == "MISS"

        # Segunda execução com mesmo value → HIT
        r2 = auth_client.post("/api/run_transform", json=payload)
        assert r2.headers.get("X-Cache") == "HIT"
        # Conteúdo igual
        assert r1.get_json() == r2.get_json()

    def test_force_true_bypasses_cache(
        self, app, auth_client, monkeypatch, tmp_path
    ):
        """force=true bypassa o cache → X-Cache: BYPASS."""
        from openm.core import transform_cache as tc

        db = str(tmp_path / "cache.db")
        monkeypatch.setattr(tc, "_default_cache", None)
        monkeypatch.setenv("OPENM_CACHE_DB", db)

        payload = {
            "transform_name": "whois_lookup",
            "entity_type": "Domain",
            "value": "bypass-cache-test.com",
        }

        # Pre-popula o cache
        r1 = auth_client.post("/api/run_transform", json=payload)
        assert r1.headers.get("X-Cache") == "MISS"

        # Sem force → HIT
        r2 = auth_client.post("/api/run_transform", json=payload)
        assert r2.headers.get("X-Cache") == "HIT"

        # Com force via body → BYPASS
        payload["force"] = True
        r3 = auth_client.post("/api/run_transform", json=payload)
        assert r3.headers.get("X-Cache") == "BYPASS"

    def test_force_query_param_bypasses_cache(
        self, app, auth_client, monkeypatch, tmp_path
    ):
        """force=true como query param também bypassa."""
        from openm.core import transform_cache as tc

        db = str(tmp_path / "cache.db")
        monkeypatch.setattr(tc, "_default_cache", None)
        monkeypatch.setenv("OPENM_CACHE_DB", db)

        payload = {
            "transform_name": "whois_lookup",
            "entity_type": "Domain",
            "value": "bypass-qparam-test.com",
        }

        # Pre-popula
        r1 = auth_client.post("/api/run_transform", json=payload)
        assert r1.headers.get("X-Cache") == "MISS"

        # Query param
        r2 = auth_client.post("/api/run_transform?force=true", json=payload)
        assert r2.headers.get("X-Cache") == "BYPASS"

    def test_cache_disabled_when_ttl_zero(
        self, app, auth_client, monkeypatch, tmp_path
    ):
        """Transform com TTL=0 (email_to_domain) → sempre MISS, sem HIT."""
        from openm.core import transform_cache as tc

        db = str(tmp_path / "cache.db")
        monkeypatch.setattr(tc, "_default_cache", None)
        monkeypatch.setenv("OPENM_CACHE_DB", db)

        payload = {
            "transform_name": "email_to_domain",
            "entity_type": "Email",
            "value": "user@no-cache-test.com",
        }

        r1 = auth_client.post("/api/run_transform", json=payload)
        assert r1.headers.get("X-Cache") == "MISS"

        r2 = auth_client.post("/api/run_transform", json=payload)
        # TTL=0 → não cacheia → MISS novamente
        assert r2.headers.get("X-Cache") == "MISS"

    def test_cache_normalizes_value_case(
        self, app, auth_client, monkeypatch, tmp_path
    ):
        """Email/domínio em maiúsculas bate no cache da versão lowercase."""
        from openm.core import transform_cache as tc

        db = str(tmp_path / "cache.db")
        monkeypatch.setattr(tc, "_default_cache", None)
        monkeypatch.setenv("OPENM_CACHE_DB", db)

        r1 = auth_client.post(
            "/api/run_transform",
            json={
                "transform_name": "whois_lookup",
                "entity_type": "Domain",
                "value": "Case-Test.com",
            },
        )
        assert r1.headers.get("X-Cache") == "MISS"

        r2 = auth_client.post(
            "/api/run_transform",
            json={
                "transform_name": "whois_lookup",
                "entity_type": "Domain",
                "value": "case-test.com",
            },
        )
        # Mesma chave (lowercase normalizado) → HIT
        assert r2.headers.get("X-Cache") == "HIT"
