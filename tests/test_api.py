from openm.core.entity import ENTITY_CLASSES


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_create_entity(auth_client):
    resp = auth_client.post(
        "/api/entity",
        json={"type": "Domain", "value": "example.com", "notes": "teste"},
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["entity"]["type"] == "Domain"
    assert data["entity"]["value"] == "example.com"
    assert data["entity"]["properties"]["notes"] == "teste"


def test_create_entity_invalid_type(auth_client):
    resp = auth_client.post(
        "/api/entity",
        json={"type": "UnknownType", "value": "x"},
    )
    assert resp.status_code == 400


def test_list_transforms(auth_client):
    resp = auth_client.get("/api/transforms/Domain")
    assert resp.status_code == 200
    data = resp.get_json()
    assert any(t["name"] == "resolve_ip" for t in data["transforms"])


def test_investigation_crud(auth_client):
    resp = auth_client.post(
        "/api/investigations",
        json={"title": "Caso 1", "description": "Descrição", "root_entity_id": None},
    )
    assert resp.status_code == 201
    inv_id = resp.get_json()["investigation"]["id"]

    resp = auth_client.get(f"/api/investigations/{inv_id}")
    assert resp.status_code == 200
    assert resp.get_json()["investigation"]["title"] == "Caso 1"

    resp = auth_client.get("/api/investigations")
    assert resp.status_code == 200
    assert len(resp.get_json()["investigations"]) >= 1


def test_api_key_crud(auth_client):
    resp = auth_client.post(
        "/api/keys",
        json={
            "service_name": "emailrep",
            "key_value": "supersecret12345",
            "key_type": "free",
        },
    )
    assert resp.status_code == 201
    key_id = resp.get_json()["key"]["id"]

    resp = auth_client.get("/api/keys")
    assert resp.status_code == 200
    keys = resp.get_json()["keys"]
    assert any(k["id"] == key_id for k in keys)
    assert all("masked_key" in k for k in keys)

    resp = auth_client.delete(f"/api/keys/{key_id}")
    assert resp.status_code == 200
