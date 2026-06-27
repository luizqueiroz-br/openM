"""
Testes de metricas de execucao de transforms (issue #80).

Cobertura:
- Transform.run() anexa TransformMetrics em TransformResult
- run_transform loga metricas no audit_log
- Endpoint GET /api/transforms/metrics (admin-only) agrega dados
- Contador de chamadas externas (api_calls) via services HTTP
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.audit import ACTION_TRANSFORM_RUN, log_action
from openm.core.auth import hash_password
from openm.core.entity import Domain, Email
from openm.core.transform import (
    increment_api_call_counter,
    Transform,
    TransformMetrics,
    TransformRegistry,
    TransformResult,
)
from openm.extensions import db
from openm.models.audit_log import AuditLog
from openm.models.user import User


class MetricsTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


@pytest.fixture
def metrics_app():
    app = create_app(MetricsTestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def metrics_client(metrics_app):
    return metrics_app.test_client()


@pytest.fixture(autouse=True)
def mock_graph_manager(monkeypatch):
    class FakeGraphManager:
        def __init__(self):
            self.merged = []
            self.rels = []

        def merge_entity(self, entity):
            self.merged.append(entity)

        def create_relationship(self, **kwargs):
            self.rels.append(kwargs)
            return True

    fake = FakeGraphManager()
    monkeypatch.setattr(
        "openm.utils.neo4j_client.get_graph_manager",
        lambda: fake,
    )
    return fake


def _create_user(app, email, role="analyst"):
    with app.app_context():
        u = User(
            email=email,
            password_hash=hash_password("test-password-123"),
            role=role,
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        return u.id


def _login(client, email):
    resp = client.post(
        "/api/auth/login",
        json={"email": email, "password": "test-password-123"},
    )
    assert resp.status_code == 200
    return resp.get_json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _all_events(app):
    with app.app_context():
        return AuditLog.query.order_by(AuditLog.id.asc()).all()


# ========================================================================
# Transform.run() metrics
# ========================================================================


class DummyTransform(Transform):
    name = "dummy_metrics"
    display_name = "Dummy Metrics"
    input_types = ["Domain"]

    def _run(self, entity):
        time.sleep(0.005)
        return TransformResult(
            entities=[Domain(value="result.example.com")],
            relationships=[{"type": "TEST"}],
        )


class ErrorTransform(Transform):
    name = "dummy_error"
    display_name = "Dummy Error"
    input_types = ["Domain"]

    def _run(self, entity):
        raise ValueError("boom")


class TimeoutTransform(Transform):
    name = "dummy_timeout"
    display_name = "Dummy Timeout"
    input_types = ["Domain"]

    def _run(self, entity):
        raise TimeoutError("slow")


class ApiCallTransform(Transform):
    name = "dummy_api_calls"
    display_name = "Dummy API Calls"
    input_types = ["Domain"]

    def _run(self, entity):
        increment_api_call_counter()
        increment_api_call_counter()
        return TransformResult(entities=[Domain(value="api.example.com")])


def test_transform_run_attaches_metrics():
    """run() anexa TransformMetrics no resultado."""
    transform = DummyTransform()
    entity = Domain(value="example.com")
    result = transform.run(entity)

    metrics = getattr(result, "_metrics", None)
    assert metrics is not None
    assert isinstance(metrics, TransformMetrics)
    assert metrics.status == "success"
    assert metrics.entities_created == 1
    assert metrics.relationships_created == 1
    assert metrics.duration_ms >= 0
    assert metrics.api_calls == 0


def test_transform_run_error_status():
    """_run que levanta excecao -> status=error."""
    transform = ErrorTransform()
    entity = Domain(value="example.com")
    result = transform.run(entity)

    assert result.entities == []
    assert result.relationships == []
    metrics = result._metrics
    assert metrics.status == "error"
    assert metrics.error_message == "boom"
    assert metrics.duration_ms >= 0


def test_transform_run_timeout_status():
    """TimeoutError -> status=timeout."""
    transform = TimeoutTransform()
    entity = Domain(value="example.com")
    result = transform.run(entity)

    metrics = result._metrics
    assert metrics.status == "timeout"
    assert metrics.error_message == "slow"


def test_transform_run_counts_api_calls():
    """Services podem incrementar api_calls durante run()."""
    transform = ApiCallTransform()
    entity = Domain(value="example.com")
    result = transform.run(entity)

    metrics = result._metrics
    assert metrics.api_calls == 2
    assert metrics.status == "success"


def test_transform_run_skips_invalid_input_without_metrics():
    """Entrada nao suportada retorna result vazio sem metricas."""
    transform = DummyTransform()
    entity = Email(value="a@b.com")
    result = transform.run(entity)

    assert result.entities == []
    assert result.relationships == []
    assert getattr(result, "_metrics", None) is None


def test_transform_metrics_defaults():
    """TransformMetrics default values."""
    m = TransformMetrics()
    assert m.duration_ms == 0.0
    assert m.status == "success"
    assert m.entities_created == 0
    assert m.relationships_created == 0
    assert m.api_calls == 0
    assert m.cache_hit is False
    assert m.error_message is None


# ========================================================================
# API run_transform audit enrichment
# ========================================================================


def test_run_transform_logs_metrics_in_audit(metrics_app, metrics_client, mock_graph_manager):
    """run_transform inclui duration_ms, status e api_calls no audit."""
    _create_user(metrics_app, "metrics-tester@example.com")
    token = _login(metrics_client, "metrics-tester@example.com")

    with patch(
        "openm.api.transforms.TransformRegistry.get",
        return_value=ApiCallTransform,
    ):
        resp = metrics_client.post(
            "/api/run_transform",
            json={
                "transform_name": "dummy_api_calls",
                "entity_type": "Domain",
                "value": "example.com",
            },
            headers=_bearer(token),
        )

    assert resp.status_code == 200
    data = resp.get_json()
    assert "entities" in data

    events = _all_events(metrics_app)
    runs = [e for e in events if e.action == ACTION_TRANSFORM_RUN]
    assert len(runs) == 1
    meta = runs[0].meta
    assert meta["transform_name"] == "dummy_api_calls"
    assert meta["status"] == "success"
    assert meta["api_calls"] == 2
    assert "duration_ms" in meta
    assert meta["duration_ms"] >= 0
    assert meta["new_entities_count"] == 1
    assert meta["new_relationships_count"] == 0


def test_run_transform_error_logs_status_and_message(metrics_app, metrics_client, mock_graph_manager):
    """Quando _run falha, audit recebe status=error e mensagem."""
    _create_user(metrics_app, "error-tester@example.com")
    token = _login(metrics_client, "error-tester@example.com")

    with patch(
        "openm.api.transforms.TransformRegistry.get",
        return_value=ErrorTransform,
    ):
        resp = metrics_client.post(
            "/api/run_transform",
            json={
                "transform_name": "dummy_error",
                "entity_type": "Domain",
                "value": "example.com",
            },
            headers=_bearer(token),
        )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["entities"] == []

    events = _all_events(metrics_app)
    runs = [e for e in events if e.action == ACTION_TRANSFORM_RUN]
    assert len(runs) == 1
    meta = runs[0].meta
    assert meta["status"] == "error"
    assert meta["error_message"] == "boom"
    assert meta["new_entities_count"] == 0


# ========================================================================
# GET /api/transforms/metrics endpoint
# ========================================================================


def test_metrics_endpoint_requires_auth(metrics_client):
    """Endpoint sem autenticacao -> 401."""
    resp = metrics_client.get("/api/transforms/metrics")
    assert resp.status_code == 401


def test_metrics_endpoint_admin_only(metrics_app, metrics_client):
    """Apenas admin pode acessar."""
    _create_user(metrics_app, "analyst-metrics@example.com", role="analyst")
    token = _login(metrics_client, "analyst-metrics@example.com")

    resp = metrics_client.get(
        "/api/transforms/metrics",
        headers=_bearer(token),
    )
    assert resp.status_code == 403


def test_metrics_endpoint_returns_summary(metrics_app, metrics_client):
    """Admin recebe summary e by_transform agregados."""
    admin_id = _create_user(metrics_app, "admin-metrics@example.com", role="admin")
    token = _login(metrics_client, "admin-metrics@example.com")

    # Seed com eventos de transform run
    with metrics_app.app_context():
        log_action(
            ACTION_TRANSFORM_RUN,
            target_type="entity",
            target_id="1",
            user_id=admin_id,
            metadata={
                "transform_name": "resolve_ip",
                "entity_type": "Domain",
                "status": "success",
                "cache": "MISS",
                "duration_ms": 100.0,
                "api_calls": 1,
                "new_entities_count": 1,
                "new_relationships_count": 1,
            },
        )
        log_action(
            ACTION_TRANSFORM_RUN,
            target_type="entity",
            target_id="2",
            user_id=admin_id,
            metadata={
                "transform_name": "resolve_ip",
                "entity_type": "Domain",
                "status": "success",
                "cache": "HIT",
                "duration_ms": 50.0,
                "api_calls": 0,
                "new_entities_count": 1,
                "new_relationships_count": 1,
            },
        )
        log_action(
            ACTION_TRANSFORM_RUN,
            target_type="entity",
            target_id="3",
            user_id=admin_id,
            metadata={
                "transform_name": "shodan_lookup",
                "entity_type": "IPAddress",
                "status": "error",
                "cache": "MISS",
                "duration_ms": 200.0,
                "api_calls": 0,
                "new_entities_count": 0,
                "new_relationships_count": 0,
                "error_message": "timeout",
            },
        )

    resp = metrics_client.get(
        "/api/transforms/metrics",
        headers=_bearer(token),
    )
    assert resp.status_code == 200
    data = resp.get_json()

    summary = data["summary"]
    assert summary["total_runs"] == 3
    assert summary["success_count"] == 2
    assert summary["error_count"] == 1
    assert summary["cache_hit_count"] == 1
    assert summary["total_api_calls"] == 1
    assert summary["avg_duration_ms"] == 116.67  # (100+50+200)/3

    by_transform = data["by_transform"]
    assert len(by_transform) == 2
    resolve = [b for b in by_transform if b["transform_name"] == "resolve_ip"][0]
    assert resolve["total_runs"] == 2
    assert resolve["success_count"] == 2
    assert resolve["avg_duration_ms"] == 75.0


def test_metrics_endpoint_filter_by_transform(metrics_app, metrics_client):
    """Filtro ?transform_name= limita resultados."""
    admin_id = _create_user(metrics_app, "admin-filter@example.com", role="admin")
    token = _login(metrics_client, "admin-filter@example.com")

    with metrics_app.app_context():
        log_action(
            ACTION_TRANSFORM_RUN,
            target_type="entity",
            target_id="1",
            user_id=admin_id,
            metadata={"transform_name": "a", "status": "success", "duration_ms": 10.0, "api_calls": 0},
        )
        log_action(
            ACTION_TRANSFORM_RUN,
            target_type="entity",
            target_id="2",
            user_id=admin_id,
            metadata={"transform_name": "b", "status": "success", "duration_ms": 20.0, "api_calls": 0},
        )

    resp = metrics_client.get(
        "/api/transforms/metrics?transform_name=a",
        headers=_bearer(token),
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["summary"]["total_runs"] == 1
    assert data["by_transform"][0]["transform_name"] == "a"


def test_metrics_endpoint_filter_by_period(metrics_app, metrics_client):
    """Filtro ?period_days= exclui eventos antigos."""
    admin_id = _create_user(metrics_app, "admin-period@example.com", role="admin")
    token = _login(metrics_client, "admin-period@example.com")

    from datetime import datetime, timezone, timedelta

    with metrics_app.app_context():
        # Evento antigo (fora do default 7 dias)
        old = AuditLog(
            user_id=admin_id,
            action=ACTION_TRANSFORM_RUN,
            meta={
                "transform_name": "old",
                "status": "success",
                "duration_ms": 1.0,
                "api_calls": 0,
            },
            created_at=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db.session.add(old)
        # Evento recente
        log_action(
            ACTION_TRANSFORM_RUN,
            target_type="entity",
            target_id="1",
            user_id=admin_id,
            metadata={"transform_name": "new", "status": "success", "duration_ms": 5.0, "api_calls": 0},
        )

    resp = metrics_client.get(
        "/api/transforms/metrics?period_days=7",
        headers=_bearer(token),
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["summary"]["total_runs"] == 1
    assert data["by_transform"][0]["transform_name"] == "new"


# Evita poluir o registry entre testes
@pytest.fixture(autouse=True)
def cleanup_registry():
    before = dict(TransformRegistry._transforms)
    yield
    TransformRegistry._transforms.clear()
    TransformRegistry._transforms.update(before)
