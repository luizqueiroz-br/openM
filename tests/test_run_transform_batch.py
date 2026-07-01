"""
Testes para o endpoint bulk/batch ``/api/run_transform_batch`` (issue #87).

Cobre:

1. Paralelismo: 5 entities com transform lento (sleep 0.5s) executam em
   batch < 1.0s (não ~2.5s sequencial).
2. Resiliência a erro por entity: 1 entity com erro → 2 success + 1 error.
3. Hard cap: 101 entities → 413 Payload Too Large.
4. Empty list: 0 entities → 400.
5. Audit log consolidado: 1 entry ``transform.batch_run`` por batch.
6. Rate limit conta 1 por batch (não 1 por entity) — 3 batches em
   ``__internal__=2/minute`` → 3º = 429.
7. Cache HIT replay: 2ª execução com mesma entity é cache HIT.
8. Preserva contagem: 10 entities → 10 results (mesmo se 2 falharem).

A fixture autouse ``_reset_limiter`` limpa o storage do Flask-Limiter
entre tests para isolar contadores (mesma estratégia de
``test_rate_limiter.py``).
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures locais
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_limiter():
    """
    Limpa o storage do Flask-Limiter entre tests.

    Sem este reset, requests de tests anteriores contaminariam o estado
    do limiter (memory backend é compartilhado entre tests no mesmo
    processo). Mesmo padrão de test_rate_limiter.py.
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


def _batch_payload(transform_name="email_to_domain",
                   entity_type="Email",
                   values=("a@x.com", "b@x.com", "c@x.com")):
    """Payload mínimo para POST /api/run_transform_batch."""
    return {
        "transform_name": transform_name,
        "entity_type": entity_type,
        "entities": [{"value": v} for v in values],
    }


def _override_limit(monkeypatch, service: str, limit_str: str) -> None:
    """Override o limite default de um service em Config.RATELIMIT_SERVICES.

    Usado em testes de rate limit para apertar o bucket
    ``__internal__`` e forçar 429 em poucos requests.
    """
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


class TestBatchParallelism:
    """Cobre a execução paralela do batch via ThreadPoolExecutor."""

    def test_batch_runs_in_parallel(self, auth_client, monkeypatch):
        """5 entities com transform que dorme 0.5s cada → batch < 1.0s.

        Se as 5 entities rodassem SEQUENCIAIS, seriam ~2.5s. Em
        paralelo com max_workers=5 default, devem completar em
        ~0.5s + overhead. Limiar conservador de 1.5s acomoda
        overhead de criação de threads, app_context, cache, etc.
        """
        from openm.transforms.email_to_domain import (
            EmailToDomainTransform,
            _extract_domain,
        )
        from openm.core.entity import Domain
        from openm.core.transform import TransformResult

        def _real_run(self, entity):
            """Réplica do _run original de EmailToDomainTransform.

            Implementada localmente (em vez de chamar o original)
            para isolar o teste de qualquer mudança futura no
            transform real.
            """
            from datetime import datetime, timezone

            domain_value = _extract_domain(entity.value)
            if not domain_value:
                return TransformResult()
            checked_at = datetime.now(timezone.utc).isoformat()
            domain_entity = Domain(
                value=domain_value,
                properties={
                    "extracted_from_email": entity.value,
                    "source": "email_parse",
                    "discovered_at": checked_at,
                },
            )
            return TransformResult(
                entities=[domain_entity],
                relationships=[{
                    "from_id": entity.id,
                    "to_id": domain_entity.id,
                    "type": "BELONGS_TO",
                    "properties": {
                        "source": "email_parse",
                        "discovered_at": checked_at,
                    },
                }],
            )

        def slow_run(self, entity):
            time.sleep(0.5)
            return _real_run(self, entity)

        monkeypatch.setattr(EmailToDomainTransform, "_run", slow_run)

        payload = _batch_payload(values=("a@x.com",) * 5)
        t0 = time.perf_counter()
        resp = auth_client.post("/api/run_transform_batch", json=payload)
        elapsed = time.perf_counter() - t0

        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()
        assert body["summary"]["batch_size"] == 5
        assert body["summary"]["success_count"] == 5
        assert body["summary"]["error_count"] == 0
        # 5 entities * 0.5s = 2.5s sequencial. Paralelo com 5
        # workers = ~0.5s. Threshold de 1.5s acomoda overhead.
        assert elapsed < 1.5, (
            f"batch demorou {elapsed:.2f}s — parece sequencial "
            f"(esperado < 1.5s com paralelismo)"
        )


class TestBatchErrorHandling:
    """Cobre resiliência: erro em 1 entity não aborta o batch."""

    def test_batch_continues_on_entity_error(self, auth_client, monkeypatch):
        """2 entities OK + 1 com erro → 2 success, 1 error, 0 abort."""
        from openm.transforms.email_to_domain import EmailToDomainTransform

        # Captura o _run ORIGINAL antes de monkeypatchar — sem
        # isso, EmailToDomainTransform._run abaixo chamaria a versão
        # patched (recursão infinita ou comportamento errado).
        original_run = EmailToDomainTransform._run

        def selective_run(self, entity):
            if entity.value == "bad@":
                # Força erro (em produção, o _extract_domain
                # retornaria "" silenciosamente — aqui queremos
                # testar o path de exceção).
                raise RuntimeError("forced failure for test")
            return original_run(self, entity)

        monkeypatch.setattr(EmailToDomainTransform, "_run", selective_run)

        payload = _batch_payload(
            values=("ok1@x.com", "bad@", "ok2@x.com"),
        )
        resp = auth_client.post("/api/run_transform_batch", json=payload)
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()
        assert body["summary"]["batch_size"] == 3
        assert body["summary"]["success_count"] == 2
        assert body["summary"]["error_count"] == 1
        assert body["summary"]["timeout_count"] == 0

        # Verifica que cada result tem o status correto.
        # O result com erro vem do worker (status="error" + error_type).
        # Os success vêm com cache=MISS (não há TTL no email_to_domain).
        error_results = [r for r in body["results"] if r.get("status") == "error"]
        assert len(error_results) == 1
        assert "forced failure for test" in error_results[0]["error"]


class TestBatchPayloadLimits:
    """Cobre validação de payload e hard cap."""

    def test_batch_respects_max_entities(self, auth_client, monkeypatch):
        """101 entities (default cap = 100) → 413 Payload Too Large."""
        # BATCH_MAX_ENTITIES default = 100; mandamos 101.
        payload = _batch_payload(values=tuple(f"a{i}@x.com" for i in range(101)))
        resp = auth_client.post("/api/run_transform_batch", json=payload)
        assert resp.status_code == 413
        body = resp.get_json()
        assert body["error"] == "batch_exceeds_max"
        assert body["max_entities"] == 100
        assert body["received"] == 101

    def test_batch_respects_empty(self, auth_client):
        """0 entities → 400 ValidationError."""
        payload = _batch_payload(values=())
        resp = auth_client.post("/api/run_transform_batch", json=payload)
        assert resp.status_code == 400
        body = resp.get_json()
        assert "vazia" in body["error"] or "empty" in body["error"].lower()


class TestBatchAuditLog:
    """Cobre o audit log consolidado (1 entry por batch, não N)."""

    def test_batch_audit_is_consolidated(self, app, auth_client):
        """1 entry em AuditLog com action='transform.batch_run'."""
        from openm.core.audit import ACTION_TRANSFORM_BATCH_RUN
        from openm.models.audit_log import AuditLog

        payload = _batch_payload(values=("a@x.com", "b@x.com", "c@x.com"))
        resp = auth_client.post("/api/run_transform_batch", json=payload)
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()
        assert body["summary"]["batch_size"] == 3

        with app.app_context():
            entries = AuditLog.query.filter_by(
                action=ACTION_TRANSFORM_BATCH_RUN
            ).all()
            assert len(entries) == 1, (
                f"esperava 1 entry consolidada, achei {len(entries)}"
            )
            entry = entries[0]
            assert entry.target_type == "batch"
            assert entry.meta is not None
            assert entry.meta["batch_size"] == 3
            assert entry.meta["transform_name"] == "email_to_domain"
            assert entry.meta["entity_type"] == "Email"
            assert entry.meta["success_count"] == 3
            assert entry.meta["error_count"] == 0
            assert entry.meta["status"] == "success"
            assert entry.meta["duration_ms"] >= 0
            assert "total_api_calls" in entry.meta
            assert "cache_hit_count" in entry.meta


class TestBatchRateLimit:
    """Cobre que rate limit conta 1 por batch, não 1 por entity."""

    def test_batch_rate_limit_single_count(
        self, auth_client, monkeypatch
    ):
        """3 batches com __internal__=2/minute → 3º request = 429."""
        # Limita o bucket __internal__ a 2/minute (email_to_domain
        # não tem service_name declarado → cai no bucket __internal__).
        _override_limit(monkeypatch, "__internal__", "2/minute")

        payload = _batch_payload(values=("a@x.com", "b@x.com"))
        # 2 requests OK
        r1 = auth_client.post("/api/run_transform_batch", json=payload)
        r2 = auth_client.post("/api/run_transform_batch", json=payload)
        assert r1.status_code == 200, r1.get_json()
        assert r2.status_code == 200, r2.get_json()
        # 3º request → 429
        r3 = auth_client.post("/api/run_transform_batch", json=payload)
        assert r3.status_code == 429
        body = r3.get_json()
        assert body["error"] == "rate_limit_exceeded"
        assert "retry_after" in body


class TestBatchCacheReplay:
    """Cobre cache HIT replay em batch."""

    def test_batch_cache_hit_replay(self, auth_client, monkeypatch):
        """1ª execução popula cache; 2ª execução (mesma entity) é cache HIT.

        Usa ``resolve_ip`` (cache_ttl_seconds=3600) com
        ``resolve_domain`` mocked para evitar DNS real.
        """
        from openm.core.transform_cache import clear_cache_for

        # Limpa entrada de cache potencialmente existente de runs
        # anteriores (o cache SQLite é persistente em /tmp).
        clear_cache_for("resolve_ip", "Domain", "example.com")

        # Mocka o resolver DNS para algo determinístico.
        with patch(
            "openm.transforms.resolve_ip.resolve_domain",
            return_value=["93.184.216.34"],
        ):
            payload = {
                "transform_name": "resolve_ip",
                "entity_type": "Domain",
                "entities": [{"value": "example.com"}],
            }
            # 1ª execução → cache MISS, popula cache.
            r1 = auth_client.post("/api/run_transform_batch", json=payload)
            assert r1.status_code == 200, r1.get_json()
            body1 = r1.get_json()
            assert body1["summary"]["cache_hit_count"] == 0
            assert body1["results"][0]["status"] == "success"
            assert body1["results"][0]["cache"] == "MISS"

            # 2ª execução (mesma entity) → cache HIT.
            r2 = auth_client.post("/api/run_transform_batch", json=payload)
            assert r2.status_code == 200, r2.get_json()
            body2 = r2.get_json()
            assert body2["summary"]["cache_hit_count"] == 1
            assert body2["results"][0]["status"] == "success"
            assert body2["results"][0]["cache"] == "HIT"


class TestBatchResultCount:
    """Cobre que ``results`` contém 1 entry por entity, mesmo com erros."""

    def test_batch_preserves_result_count(self, auth_client, monkeypatch):
        """10 entities (2 falham) → 10 results no array."""
        from openm.transforms.email_to_domain import EmailToDomainTransform

        original_run = EmailToDomainTransform._run

        def fail_on_bad_values(self, entity):
            if entity.value in ("err1@", "err2@"):
                raise RuntimeError("simulated error")
            return original_run(self, entity)

        monkeypatch.setattr(EmailToDomainTransform, "_run", fail_on_bad_values)

        values = tuple(
            f"ok{i}@x.com" if i not in (2, 5) else f"err{1 if i == 2 else 2}@"
            for i in range(10)
        )
        payload = _batch_payload(values=values)
        resp = auth_client.post("/api/run_transform_batch", json=payload)
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()
        # 10 results, 8 success, 2 error.
        assert len(body["results"]) == 10
        assert body["summary"]["batch_size"] == 10
        assert body["summary"]["success_count"] == 8
        assert body["summary"]["error_count"] == 2
