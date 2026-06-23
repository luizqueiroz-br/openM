"""
Testes da API Investigations v2 (issue #26).

Cobre:
- PUT (atualização parcial + graph_snapshot + last_auto_save_at)
- Archive/Unarchive endpoints
- Filtros: status, search, sort
- Isolamento multi-user mantido
"""

from __future__ import annotations

import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.investigation import Investigation
from openm.models.user import User


class ApiV2TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


@pytest.fixture
def api_app():
    app = create_app(ApiV2TestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(api_app):
    return api_app.test_client()


def _create_user(api_app, email, password="pass-12345678"):
    with api_app.app_context():
        u = User(
            email=email,
            password_hash=hash_password(password),
            role="analyst",
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        return u.id


def _login(client, email, password="pass-12345678"):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    return r.get_json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ============ PUT (atualização) ============

class TestUpdateInvestigation:
    def test_put_updates_title(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        # Cria
        r = client.post("/api/investigations", json={"title": "Old"},
                        headers=_bearer(token))
        inv_id = r.get_json()["investigation"]["id"]

        # PUT novo título
        r = client.put(f"/api/investigations/{inv_id}",
                       json={"title": "New"},
                       headers=_bearer(token))
        assert r.status_code == 200
        assert r.get_json()["investigation"]["title"] == "New"

    def test_put_with_graph_snapshot_updates_last_auto_save(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        r = client.post("/api/investigations", json={"title": "X"},
                        headers=_bearer(token))
        inv_id = r.get_json()["investigation"]["id"]
        assert r.get_json()["investigation"]["last_auto_save_at"] is None

        # PUT com snapshot
        snapshot = {"nodes": [{"data": {"id": "n1", "label": "A"}}], "edges": []}
        r = client.put(f"/api/investigations/{inv_id}",
                       json={"graph_snapshot": snapshot},
                       headers=_bearer(token))
        assert r.status_code == 200
        body = r.get_json()
        assert body["investigation"]["graph_snapshot"] == snapshot
        assert body["investigation"]["last_auto_save_at"] is not None
        assert body["saved_at"] is not None

    def test_put_without_snapshot_does_not_update_auto_save(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        r = client.post("/api/investigations", json={"title": "X"},
                        headers=_bearer(token))
        inv_id = r.get_json()["investigation"]["id"]

        r = client.put(f"/api/investigations/{inv_id}",
                       json={"description": "new desc"},
                       headers=_bearer(token))
        assert r.status_code == 200
        assert r.get_json()["investigation"]["last_auto_save_at"] is None
        assert r.get_json()["saved_at"] is None

    def test_put_validates_graph_snapshot_structure(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        r = client.post("/api/investigations", json={"title": "X"},
                        headers=_bearer(token))
        inv_id = r.get_json()["investigation"]["id"]

        # Falta edges
        r = client.put(f"/api/investigations/{inv_id}",
                       json={"graph_snapshot": {"nodes": []}},
                       headers=_bearer(token))
        assert r.status_code == 400
        assert "nodes" in r.get_json()["error"] and "edges" in r.get_json()["error"]

    def test_put_cross_user_returns_404(self, api_app, client):
        """Isolamento multi-user: PUT em inv de outro user → 404 (anti-enumeração)."""
        _create_user(api_app, "alice@t.com")
        _create_user(api_app, "bob@t.com")
        token_a = _login(client, "alice@t.com")
        token_b = _login(client, "bob@t.com")

        r = client.post("/api/investigations", json={"title": "Alice's"},
                        headers=_bearer(token_a))
        inv_id = r.get_json()["investigation"]["id"]

        r = client.put(f"/api/investigations/{inv_id}",
                       json={"title": "hacked"},
                       headers=_bearer(token_b))
        assert r.status_code == 404


# ============ Archive / Unarchive ============

class TestArchiveEndpoints:
    def test_archive_endpoint(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        r = client.post("/api/investigations", json={"title": "X"},
                        headers=_bearer(token))
        inv_id = r.get_json()["investigation"]["id"]

        r = client.post(f"/api/investigations/{inv_id}/archive",
                        headers=_bearer(token))
        assert r.status_code == 200
        body = r.get_json()
        assert body["investigation"]["status"] == "archived"
        assert body["investigation"]["archived_at"] is not None

    def test_unarchive_endpoint(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        r = client.post("/api/investigations", json={"title": "X"},
                        headers=_bearer(token))
        inv_id = r.get_json()["investigation"]["id"]
        client.post(f"/api/investigations/{inv_id}/archive", headers=_bearer(token))

        r = client.post(f"/api/investigations/{inv_id}/unarchive",
                        headers=_bearer(token))
        assert r.status_code == 200
        body = r.get_json()
        assert body["investigation"]["status"] == "active"
        assert body["investigation"]["archived_at"] is None

    def test_archived_hides_from_default_list(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        for t in ["A1", "A2", "A3"]:
            r = client.post("/api/investigations", json={"title": t},
                            headers=_bearer(token))
            if t == "A2":
                inv_id = r.get_json()["investigation"]["id"]
        client.post(f"/api/investigations/{inv_id}/archive", headers=_bearer(token))

        r = client.get("/api/investigations", headers=_bearer(token))
        titles = {i["title"] for i in r.get_json()["investigations"]}
        assert titles == {"A1", "A3"}

    def test_archived_shows_with_status_filter(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        r = client.post("/api/investigations", json={"title": "Active"},
                        headers=_bearer(token))
        r = client.post("/api/investigations", json={"title": "Archived"},
                        headers=_bearer(token))
        archived_id = r.get_json()["investigation"]["id"]
        client.post(f"/api/investigations/{archived_id}/archive", headers=_bearer(token))

        r = client.get("/api/investigations?status=archived", headers=_bearer(token))
        titles = {i["title"] for i in r.get_json()["investigations"]}
        assert titles == {"Archived"}

    def test_status_all_shows_everything(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        r = client.post("/api/investigations", json={"title": "Active"},
                        headers=_bearer(token))
        r = client.post("/api/investigations", json={"title": "Archived"},
                        headers=_bearer(token))
        archived_id = r.get_json()["investigation"]["id"]
        client.post(f"/api/investigations/{archived_id}/archive", headers=_bearer(token))

        r = client.get("/api/investigations?status=all", headers=_bearer(token))
        titles = {i["title"] for i in r.get_json()["investigations"]}
        assert titles == {"Active", "Archived"}


# ============ Filtros ============

class TestListFilters:
    def test_search_filter(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        for t in ["Fraud Investigation", "Phishing Case", "Fraud Alert"]:
            client.post("/api/investigations", json={"title": t},
                        headers=_bearer(token))

        r = client.get("/api/investigations?search=fraud", headers=_bearer(token))
        titles = {i["title"] for i in r.get_json()["investigations"]}
        assert titles == {"Fraud Investigation", "Fraud Alert"}

    def test_search_is_case_insensitive(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        client.post("/api/investigations", json={"title": "FRAUD"},
                    headers=_bearer(token))

        r = client.get("/api/investigations?search=fraud", headers=_bearer(token))
        assert len(r.get_json()["investigations"]) == 1

    def test_sort_by_title_asc(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        for t in ["Charlie", "Alpha", "Bravo"]:
            client.post("/api/investigations", json={"title": t},
                        headers=_bearer(token))

        r = client.get("/api/investigations?sort=title", headers=_bearer(token))
        titles = [i["title"] for i in r.get_json()["investigations"]]
        assert titles == ["Alpha", "Bravo", "Charlie"]

    def test_sort_by_title_desc(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        for t in ["Alpha", "Bravo", "Charlie"]:
            client.post("/api/investigations", json={"title": t},
                        headers=_bearer(token))

        r = client.get("/api/investigations?sort=-title", headers=_bearer(token))
        titles = [i["title"] for i in r.get_json()["investigations"]]
        assert titles == ["Charlie", "Bravo", "Alpha"]

    def test_invalid_sort_returns_400(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        r = client.get("/api/investigations?sort=password",
                       headers=_bearer(token))
        assert r.status_code == 400

    def test_invalid_status_returns_400(self, api_app, client):
        _create_user(api_app, "alice@t.com")
        token = _login(client, "alice@t.com")

        r = client.get("/api/investigations?status=invalid",
                       headers=_bearer(token))
        assert r.status_code == 400
