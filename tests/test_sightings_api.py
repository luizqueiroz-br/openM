"""Testes do endpoint /api/sightings (issue #129)."""
from openm.core.audit import ACTION_TRANSFORM_RUN, ACTION_ENTITY_UPDATE
from openm.extensions import db
from openm.models.audit_log import AuditLog


def test_sightings_requires_entity_id(auth_client):
    """Sem entity_id, retorna 400 com mensagem explícita."""
    rv = auth_client.get("/api/sightings")
    assert rv.status_code == 400
    body = rv.get_json()
    assert "entity_id" in body["error"]


def test_sightings_invalid_category(auth_client):
    """Category fora do whitelist retorna 400."""
    rv = auth_client.get("/api/sightings?entity_id=x&category=foo")
    assert rv.status_code == 400
    body = rv.get_json()
    assert "category" in body["error"]


def test_sightings_returns_transforms(auth_client, app):
    """Evento transform.run aparece no filtro category=transforms."""
    with app.app_context():
        log = AuditLog(
            user_id=None,
            action=ACTION_TRANSFORM_RUN,
            target_type="entity",
            target_id="test-entity-1",
            meta={"transform_name": "resolve_ip", "duration_ms": 120},
        )
        db.session.add(log)
        db.session.commit()

    rv = auth_client.get(
        "/api/sightings?entity_id=test-entity-1&category=transforms"
    )
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["count"] == 1
    assert data["entity_id"] == "test-entity-1"
    assert data["category"] == "transforms"
    s = data["sightings"][0]
    assert s["type"] == "transform"
    assert s["action"] == ACTION_TRANSFORM_RUN
    assert s["title"] == "resolve_ip"
    assert s["metadata"]["transform_name"] == "resolve_ip"
    assert s["metadata"]["duration_ms"] == 120


def test_sightings_omits_ip_address(auth_client, app):
    """Resposta NÃO deve expor ip_address (campo sensível)."""
    with app.app_context():
        log = AuditLog(
            user_id=None,
            action=ACTION_TRANSFORM_RUN,
            target_type="entity",
            target_id="test-entity-2",
            meta={"transform_name": "x"},
            ip_address="10.0.0.1",
        )
        db.session.add(log)
        db.session.commit()

    rv = auth_client.get("/api/sightings?entity_id=test-entity-2")
    assert rv.status_code == 200
    s = rv.get_json()["sightings"][0]
    assert "ip_address" not in s
    assert "ip_address" not in s.get("metadata", {})


def test_sightings_viewer_forbidden(viewer_client):
    """Viewer NÃO tem acesso (apenas admin + analyst)."""
    rv = viewer_client.get("/api/sightings?entity_id=x")
    assert rv.status_code in (403, 401)


def test_sightings_manual_excludes_transform_triggered(auth_client, app):
    """Category=manual: entity.* sem transform_name em meta entra;
    entity.* COM transform_name (disparado por transform) é excluído."""
    with app.app_context():
        # Manual: entity.update sem transform_name
        db.session.add(AuditLog(
            user_id=None,
            action=ACTION_ENTITY_UPDATE,
            target_type="entity",
            target_id="test-entity-3",
            meta={"property_keys": ["email"]},
        ))
        # Disparado por transform: entity.update com transform_name
        db.session.add(AuditLog(
            user_id=None,
            action=ACTION_ENTITY_UPDATE,
            target_type="entity",
            target_id="test-entity-3",
            meta={"property_keys": ["ip"], "transform_name": "resolve_ip"},
        ))
        db.session.commit()

    rv = auth_client.get(
        "/api/sightings?entity_id=test-entity-3&category=manual"
    )
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["count"] == 1
    assert data["sightings"][0]["metadata"]["property_keys"] == ["email"]
