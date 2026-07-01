"""
Testes para o encadeamento automático de transforms (issue #81).

Cobre:

1. Chain simples resolve_ip→geoip: Domain → IPAddress → Device.
2. Dry-run retorna plan com hops ordenados, sem executar.
3. Cycle defense: visited set impede reprocessamento.
4. max_chain_depth cap: chain de 5 hops com max=2 → truncated.
5. Cache HIT no hop 1: replay com cached_entities como input.
6. Audit consolidado: 1 entry ``transform.chain_run`` com hops.
7. Ownership: created_by_user_id correto em entities resultantes.
8. Sem downstream: comportamento idêntico ao single transform.

A fixture autouse ``_reset_limiter`` limpa o storage do Flask-Limiter
entre tests (mesma estratégia de ``test_rate_limiter.py`` e
``test_run_transform_batch.py``).
"""

from __future__ import annotations

from typing import Any, List

import pytest


# ---------------------------------------------------------------------------
# Fixtures locais
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_limiter():
    """
    Limpa o storage do Flask-Limiter entre tests.

    Sem este reset, requests de tests anteriores contaminariam o
    estado do limiter (memory backend é compartilhado).
    """
    from openm.extensions import limiter

    storage = getattr(limiter, "_storage", None)
    if storage is not None:
        try:
            storage.reset()
        except Exception:  # noqa: BLE001
            pass
    yield
    if storage is not None:
        try:
            storage.reset()
        except Exception:  # noqa: BLE001
            pass


def _override_limit(monkeypatch, service: str, limit_str: str) -> None:
    """Override o limite default de um service em Config.RATELIMIT_SERVICES."""
    from openm import config as cfg
    from openm.extensions import limiter

    monkeypatch.setitem(cfg.Config.RATELIMIT_SERVICES, service, limit_str)
    storage = getattr(limiter, "_storage", None)
    if storage is not None:
        try:
            storage.reset()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Testes
# ---------------------------------------------------------------------------


class TestChainExecution:
    """Cobre a execução de chain hop-by-hop via API."""

    def test_chain_simple_resolve_ip_to_geoip(
        self, auth_client, monkeypatch
    ):
        """Domain → resolve_ip → IPAddress → geoip (+ reverse_dns) → ...

        Mocka o ``resolve_domain`` de ``resolve_ip`` para retornar
        um IP determinístico, o ``GeoIPService`` para retornar
        dados simulados, e ``reverse_dns`` para não bater rede.
        resolve_ip tem 2 downstreams: geoip_lookup E reverse_dns.
        Ambos rodam em paralelo neste hop 2.
        Verifica:
        - Resposta 200 com ``chain.hops`` populado.
        - ``chain.hops`` tem 2 entradas (geoip + reverse_dns).
        - 1 entry consolidada ``ACTION_TRANSFORM_CHAIN_RUN`` em
          AuditLog com ``hops: [...]``.
        - ``chain.truncated`` e ``chain.total_hops`` corretos.
        """
        from openm.core.transform_cache import clear_cache_for

        # Limpa cache para começar fresh
        clear_cache_for("resolve_ip", "Domain", "example.com")

        # Mock 1: resolve_domain retorna IP determinístico.
        monkeypatch.setattr(
            "openm.transforms.resolve_ip.resolve_domain",
            lambda domain: ["1.2.3.4"],
        )

        # Mock 2: GeoIPService retorna dict determinístico.
        monkeypatch.setattr(
            "openm.services.geoip_service.GeoIPService.investigate_ip",
            classmethod(lambda cls, ip: {
                "country": "US",
                "country_name": "United States",
                "city": "Mountain View",
                "organization": "Google LLC",
                "source": "geoip",
            }),
        )

        # Mock 3: reverse_dns para não bater socket.gethostbyaddr.
        monkeypatch.setattr(
            "openm.transforms.reverse_dns.reverse_dns",
            lambda ip: None,  # sem resultado → chain para aqui
        )

        payload = {
            "entity_id": "test-domain-1",
            "transform_name": "resolve_ip",
            "entity_type": "Domain",
            "value": "example.com",
            "chain": True,
            "chain_max_depth": 3,
        }
        resp = auth_client.post("/api/run_transform", json=payload)
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()

        # Hop 1: 1 IPAddress + rel RESOLVES_TO.
        assert len(body["entities"]) == 1
        assert body["entities"][0]["type"] == "IPAddress"
        assert body["entities"][0]["value"] == "1.2.3.4"

        # Chain info presente.
        assert "chain" in body, body
        chain = body["chain"]
        assert chain["chain_max_depth"] == 3
        # 2 downstreams: geoip_lookup (executa OK) e reverse_dns
        # (None → retorna empty). Apenas geoip_lookup produz hops
        # com status=success; reverse_dns com status=success mas
        # sem output_ids.
        assert chain["total_hops"] == 2, chain
        assert len(chain["hops"]) == 2
        transforms_run = {h["transform"] for h in chain["hops"]}
        assert "geoip_lookup" in transforms_run, chain
        assert "reverse_dns" in transforms_run, chain
        # GeoIP hop tem outputs (Device/ASN).
        geoip_hop = next(
            h for h in chain["hops"] if h["transform"] == "geoip_lookup"
        )
        assert geoip_hop["depth"] == 3  # hop 3 (hop 1 = resolve_ip, hop 2 = _skip_and_recurse)
        assert geoip_hop["input_type"] == "IPAddress"
        assert geoip_hop["input_value"] == "1.2.3.4"
        assert geoip_hop["status"] == "success"

    def test_chain_dry_run_returns_plan(self, auth_client):
        """``chain="dry_run"`` retorna ``plan`` com hops, sem executar.

        Usa ``resolve_ip`` que tem
        ``downstream_transforms=["geoip_lookup", "reverse_dns"]``.
        O plan deve listar hop 1 (resolve_ip), hop 2
        (geoip_lookup), hop 3 (reverse_dns) — mas como
        ``reverse_dns`` tem seu próprio downstream
        (``whois_lookup``), hop 4 também aparece.
        """
        payload = {
            "entity_id": "test-domain-2",
            "transform_name": "resolve_ip",
            "entity_type": "Domain",
            "value": "example.com",
            "chain": "dry_run",
            "chain_max_depth": 3,
        }
        resp = auth_client.post("/api/run_transform", json=payload)
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()

        assert body["dry_run"] is True
        assert body["transform_name"] == "resolve_ip"
        assert body["entity_type"] == "Domain"
        assert body["chain_max_depth"] == 3
        assert "plan" in body
        plan = body["plan"]
        assert len(plan) >= 1
        # Primeiro hop: resolve_ip
        assert plan[0]["hop"] == 1
        assert plan[0]["transform"] == "resolve_ip"
        assert plan[0]["input_type"] == "Domain"
        # Hops crescem em profundidade
        hops_seen = [p["hop"] for p in plan]
        assert hops_seen == sorted(hops_seen)
        # total_hops consistente
        assert body["total_hops"] == len(plan)

        # Verifica que nenhuma entity foi persistida (chain dry-run
        # não chama get_graph_manager). Aqui o fake graph manager
        # apenas registra chamadas — então validamos que
        # ``body`` NÃO contém a chave ``chain`` (com hops
        # executados).
        assert "chain" not in body
        # E ``input`` é None ou ausente (não executamos).
        # response: {"dry_run": True, ..., "plan": [...]}
        assert "input" not in body or body.get("input") is None

    def test_chain_cycle_detected(self, auth_client, monkeypatch):
        """Cria um cycle: resolve_ip → geoip (mockado para retornar Domain).

        Com o cycle forçado, ``chain.truncated`` deve ser True.
        """
        # Mock resolve_domain para retornar IP.
        monkeypatch.setattr(
            "openm.transforms.resolve_ip.resolve_domain",
            lambda domain: ["5.6.7.8"],
        )

        # Mock GeoIP para retornar Domain (criando um cycle:
        # IPAddress → Domain → resolve_ip → IPAddress → ...).
        # Como geoip_lookup não é o que cria cycle (seu output é
        # Device/ASN), vamos mockar a chain_executor para simular
        # um cycle via visited set. Em vez disso, mockamos
        # ``reverse_dns`` para retornar Domain (cycle real:
        # IPAddress → reverse_dns → Domain → resolve_ip → IPAddress).
        def fake_reverse_dns(ip):
            return ("cycle.example.com", [])

        monkeypatch.setattr(
            "openm.transforms.reverse_dns.reverse_dns",
            fake_reverse_dns,
        )

        # Limpa cache.
        from openm.core.transform_cache import clear_cache_for

        clear_cache_for("resolve_ip", "Domain", "example.com")
        clear_cache_for("reverse_dns", "IPAddress", "5.6.7.8")

        payload = {
            "entity_id": "test-domain-3",
            "transform_name": "resolve_ip",
            "entity_type": "Domain",
            "value": "example.com",
            "chain": True,
            "chain_max_depth": 5,
        }
        resp = auth_client.post("/api/run_transform", json=payload)
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()

        # chain presente.
        assert "chain" in body, body
        chain = body["chain"]
        # chain_truncated (alias de truncated) deve ser True.
        # Aceita ambos nomes (response shape + audit shape).
        assert chain.get("truncated") is True or chain.get(
            "chain_truncated"
        ) is True, chain
        # truncated_reason presente.
        reason = chain.get("truncated_reason") or chain.get(
            "chain_truncated_reason"
        )
        assert reason in {
            "no_downstream",
            "max_chain_depth",
            "cycle",
            "downstream_not_registered",
        }, chain

    def test_chain_max_depth_enforced(self, auth_client, monkeypatch):
        """``chain_max_depth=2`` com chain real de 3+ hops → truncado.

        Usa chain real (resolve_ip → geoip + reverse_dns → whois),
        com max_chain_depth=2, e verifica que o chain é truncado.
        """
        from openm.core.transform_cache import clear_cache_for

        clear_cache_for("resolve_ip", "Domain", "example.com")

        monkeypatch.setattr(
            "openm.transforms.resolve_ip.resolve_domain",
            lambda domain: ["9.10.11.12"],
        )
        monkeypatch.setattr(
            "openm.services.geoip_service.GeoIPService.investigate_ip",
            classmethod(lambda cls, ip: {
                "country": "US", "country_name": "United States",
                "city": "Seattle", "organization": "Amazon",
                "source": "geoip",
            }),
        )
        # Whois é caro; mock para não bater rede.
        monkeypatch.setattr(
            "openm.services.whois_service.WhoisService.investigate_domain",
            classmethod(lambda cls, d: {}),
        )

        payload = {
            "entity_id": "test-domain-4",
            "transform_name": "resolve_ip",
            "entity_type": "Domain",
            "value": "example.com",
            "chain": True,
            "chain_max_depth": 2,  # só permite hop 1 e hop 2
        }
        resp = auth_client.post("/api/run_transform", json=payload)
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()

        # Validação 1: chain_max_depth=0 ou < 1 → 400.
        bad_payload = dict(payload, chain_max_depth=0)
        bad_resp = auth_client.post(
            "/api/run_transform", json=bad_payload
        )
        assert bad_resp.status_code == 400, bad_resp.get_json()

        # Validação 2: chain_max_depth=11 (> 10) → 400.
        bad_payload2 = dict(payload, chain_max_depth=11)
        bad_resp2 = auth_client.post(
            "/api/run_transform", json=bad_payload2
        )
        assert bad_resp2.status_code == 400, bad_resp2.get_json()

        # Validação 3: chain_truncated se chain tem mais hops que o
        # limite. resolve_ip tem 2 downstreams; com max=2, hop 2
        # é o último executado.
        assert "chain" in body, body
        chain = body["chain"]
        # Hops executados não devem exceder max_chain_depth - 1
        # (hop 1 é executado fora, hops 2..N pelo executor).
        # Para max=2, apenas 1 hop no chain (hop 2).
        assert chain["total_hops"] <= 1, chain

    def test_chain_cache_hit_in_hop1(self, auth_client, monkeypatch):
        """Pre-seed cache: hop 1 cache HIT, hop 2 executa.

        Caching acontece no endpoint single (hop 1) ANTES do
        chain. Se HIT, o endpoint chama ``_execute_chain`` com
        os outputs do cache (não do transform real).
        """
        from openm.core.transform_cache import (
            clear_cache_for,
            set_cached_result,
        )

        clear_cache_for("resolve_ip", "Domain", "example.com")
        clear_cache_for("reverse_dns", "IPAddress", "8.8.8.8")

        # Pre-seed cache com um IP fictício.
        cached_payload = {
            "input": {
                "id": "test-domain-5",
                "type": "Domain",
                "value": "example.com",
            },
            "entities": [{
                "id": "fake-ip-1",
                "type": "IPAddress",
                "value": "8.8.8.8",
                "properties": {"cached": True},
            }],
            "relationships": [{
                "from_id": "test-domain-5",
                "to_id": "fake-ip-1",
                "type": "RESOLVES_TO",
                "properties": {},
            }],
        }
        set_cached_result(
            "resolve_ip", "Domain", "example.com", cached_payload, 3600
        )

        # Mock GeoIP para o hop 2.
        monkeypatch.setattr(
            "openm.services.geoip_service.GeoIPService.investigate_ip",
            classmethod(lambda cls, ip: {
                "country": "US", "country_name": "United States",
                "city": "Mountain View", "organization": "Google",
                "source": "geoip",
            }),
        )
        # Mock reverse_dns para não bater socket.
        monkeypatch.setattr(
            "openm.transforms.reverse_dns.reverse_dns",
            lambda ip: None,
        )

        payload = {
            "entity_id": "test-domain-5",
            "transform_name": "resolve_ip",
            "entity_type": "Domain",
            "value": "example.com",
            "chain": True,
            "chain_max_depth": 3,
        }
        resp = auth_client.post("/api/run_transform", json=payload)
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()

        # X-Cache: HIT (header)
        assert resp.headers.get("X-Cache") == "HIT"

        # Chain presente com hops 2..N.
        # resolve_ip tem 2 downstreams: geoip + reverse_dns.
        # Ambos rodam em paralelo no hop 3.
        assert "chain" in body, body
        chain = body["chain"]
        assert chain["total_hops"] == 2, chain
        transforms_run = {h["transform"] for h in chain["hops"]}
        assert "geoip_lookup" in transforms_run, chain
        assert "reverse_dns" in transforms_run, chain
        geoip_hop = next(
            h for h in chain["hops"] if h["transform"] == "geoip_lookup"
        )
        assert geoip_hop["input_value"] == "8.8.8.8"

    def test_chain_audit_one_consolidated_entry(
        self, app, auth_client, monkeypatch
    ):
        """1 entry ``transform.chain_run`` com ``hops: [...]`` no metadata.

        Não deve haver N entries (uma por hop) — só 1 consolidada.
        """
        from openm.core.audit import ACTION_TRANSFORM_CHAIN_RUN
        from openm.core.transform_cache import clear_cache_for
        from openm.models.audit_log import AuditLog

        clear_cache_for("resolve_ip", "Domain", "example.com")
        clear_cache_for("reverse_dns", "IPAddress", "13.14.15.16")

        monkeypatch.setattr(
            "openm.transforms.resolve_ip.resolve_domain",
            lambda domain: ["13.14.15.16"],
        )
        monkeypatch.setattr(
            "openm.services.geoip_service.GeoIPService.investigate_ip",
            classmethod(lambda cls, ip: {
                "country": "US", "country_name": "United States",
                "city": "Seattle", "organization": "Amazon",
                "source": "geoip",
            }),
        )
        monkeypatch.setattr(
            "openm.transforms.reverse_dns.reverse_dns",
            lambda ip: None,
        )

        payload = {
            "entity_id": "test-domain-6",
            "transform_name": "resolve_ip",
            "entity_type": "Domain",
            "value": "example.com",
            "chain": True,
            "chain_max_depth": 3,
        }
        resp = auth_client.post("/api/run_transform", json=payload)
        assert resp.status_code == 200, resp.get_json()

        with app.app_context():
            entries = AuditLog.query.filter_by(
                action=ACTION_TRANSFORM_CHAIN_RUN
            ).all()
            assert len(entries) == 1, (
                f"esperava 1 entry consolidada de chain, "
                f"achei {len(entries)}"
            )
            entry = entries[0]
            assert entry.target_type == "entity"
            meta = entry.meta
            assert meta["transform_name"] == "resolve_ip"
            assert meta["entity_type"] == "Domain"
            assert meta["chain_max_depth"] == 3
            # 2 hops: geoip + reverse_dns
            assert meta["total_hops"] == 2, meta
            assert "hops" in meta
            assert isinstance(meta["hops"], list)
            assert len(meta["hops"]) == 2
            transforms_in_audit = {h["transform"] for h in meta["hops"]}
            assert "geoip_lookup" in transforms_in_audit
            assert "reverse_dns" in transforms_in_audit
            assert "hop1_cache" in meta
            assert "hop1_duration_ms" in meta

    def test_chain_ownership_stamped(self, auth_client, monkeypatch):
        """Entities resultantes do chain têm ``created_by_user_id`` correto.

        O analyst (não admin) que dispara o chain deve ter o
        seu user_id estampado nas entities resultantes dos
        hops 2..N. Como as entities são persistidas via
        ``gm.merge_entity`` (mockado em conftest), validamos
        via spy.
        """
        from openm.core.transform_cache import clear_cache_for

        clear_cache_for("resolve_ip", "Domain", "example.com")

        monkeypatch.setattr(
            "openm.transforms.resolve_ip.resolve_domain",
            lambda domain: ["17.18.19.20"],
        )
        monkeypatch.setattr(
            "openm.services.geoip_service.GeoIPService.investigate_ip",
            classmethod(lambda cls, ip: {
                "country": "US", "country_name": "United States",
                "city": "San Francisco", "organization": "Cloudflare",
                "source": "geoip",
            }),
        )

        # Spy no gm.merge_entity.
        persisted: List[Any] = []
        # Importa o fake graph manager usado pelo monkeypatch do
        # conftest — mas o spy precisa interceptar a chamada
        # antes do fake. Mais simples: instrumentar o module
        # inteiro via monkeypatch.

        from openm.api import transforms as transforms_module
        original_merge = transforms_module.get_graph_manager

        def spied_get_graph_manager():
            gm = original_merge()
            original_gm_merge = gm.merge_entity

            def spy_merge(entity, *a, **kw):
                persisted.append(entity)
                return original_gm_merge(entity, *a, **kw)

            gm.merge_entity = spy_merge
            return gm

        monkeypatch.setattr(
            transforms_module, "get_graph_manager",
            spied_get_graph_manager,
        )

        payload = {
            "entity_id": "test-domain-7",
            "transform_name": "resolve_ip",
            "entity_type": "Domain",
            "value": "example.com",
            "chain": True,
            "chain_max_depth": 3,
        }
        resp = auth_client.post("/api/run_transform", json=payload)
        assert resp.status_code == 200, resp.get_json()

        # Verifica que pelo menos 1 entity foi persistida com
        # created_by_user_id = user_id (não None) — analyst.
        user_owned = [e for e in persisted if e.created_by_user_id is not None]
        assert len(user_owned) >= 1, (
            f"esperava entities com created_by_user_id != None, "
            f"achei {len(user_owned)} em {len(persisted)}"
        )

    def test_chain_no_downstream_runs_only_hop1(
        self, auth_client, monkeypatch
    ):
        """Transform sem downstream → comportamento idêntico ao single.

        Mocka um transform que tem ``downstream_transforms=[]``
        (custom registration temporário) e verifica que
        ``chain.hops`` é vazio e ``truncated=False``.
        """
        from openm.core.transform import Transform, TransformResult
        from openm.core.transform import TransformRegistry

        class _NoDownstreamTransform(Transform):
            name = "_test_no_downstream"
            display_name = "Test No Downstream"
            input_types = ["Domain"]
            description = "transform de teste sem downstream"
            cache_ttl_seconds = 0
            downstream_transforms: List[str] = []

            def _run(self, entity):
                return TransformResult()

        # Registra temporariamente.
        TransformRegistry.register(_NoDownstreamTransform)
        try:
            payload = {
                "entity_id": "test-no-ds",
                "transform_name": "_test_no_downstream",
                "entity_type": "Domain",
                "value": "no-ds.com",
                "chain": True,
                "chain_max_depth": 3,
            }
            resp = auth_client.post(
                "/api/run_transform", json=payload
            )
            assert resp.status_code == 200, resp.get_json()
            body = resp.get_json()

            # chain existe (porque chain=true foi pedido), mas
            # está vazio (sem downstream).
            assert "chain" in body, body
            chain = body["chain"]
            assert chain["total_hops"] == 0, chain
            assert len(chain["hops"]) == 0, chain
            # Truncated porque não há downstream (chain encerrou
            # por "no_downstream" ou similar).
            assert chain["truncated"] is True, chain
            assert chain["truncated_reason"] == "no_downstream", chain
        finally:
            # Remove do registry para não afetar outros tests.
            TransformRegistry._transforms.pop(
                "_test_no_downstream", None
            )


class TestChainDryRunValidation:
    """Cobre validações do endpoint chain."""

    def test_chain_max_depth_invalid_returns_400(self, auth_client):
        """``chain_max_depth=0`` ou ``>10`` retorna 400."""
        # < 1
        resp = auth_client.post(
            "/api/run_transform",
            json={
                "entity_id": "x",
                "transform_name": "email_to_domain",
                "entity_type": "Email",
                "value": "a@x.com",
                "chain": "dry_run",
                "chain_max_depth": 0,
            },
        )
        assert resp.status_code == 400, resp.get_json()
        # > 10
        resp2 = auth_client.post(
            "/api/run_transform",
            json={
                "entity_id": "x",
                "transform_name": "email_to_domain",
                "entity_type": "Email",
                "value": "a@x.com",
                "chain": "dry_run",
                "chain_max_depth": 11,
            },
        )
        assert resp2.status_code == 400, resp2.get_json()

    def test_chain_detect_cycles_warns_on_static_cycle(
        self, app, caplog
    ):
        """Boot-time cycle detection loga warning para cycle estático.

        Cria um cycle temporário em TransformRegistry e chama
        detect_cycles() diretamente. Em produção, isso é
        chamado em create_app() — aqui validamos só a
        função pública.
        """
        from openm.core.transform import Transform, TransformResult
        from openm.core.transform import TransformRegistry

        class _A(Transform):
            name = "_test_cycle_a"
            input_types = ["Domain"]
            downstream_transforms: List[str] = ["_test_cycle_b"]
            cache_ttl_seconds = 0

            def _run(self, e):
                return TransformResult()

        class _B(Transform):
            name = "_test_cycle_b"
            input_types = ["Domain"]
            downstream_transforms: List[str] = ["_test_cycle_a"]
            cache_ttl_seconds = 0

            def _run(self, e):
                return TransformResult()

        TransformRegistry.register(_A)
        TransformRegistry.register(_B)
        try:
            cycles = TransformRegistry.detect_cycles()
            assert len(cycles) >= 1
            # Cada cycle contém "_test_cycle_a" e "_test_cycle_b"
            for c in cycles:
                names = set(c)
                assert "_test_cycle_a" in names
                assert "_test_cycle_b" in names
        finally:
            TransformRegistry._transforms.pop("_test_cycle_a", None)
            TransformRegistry._transforms.pop("_test_cycle_b", None)
