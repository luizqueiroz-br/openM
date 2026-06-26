"""
Testes de isolamento multi-usuário para entities e edges (issue #38).

Cenários cobertos:
- User A cria entity → owned por A
- User A cria edge → ok
- User B NÃO consegue PATCH/DELETE entity de A → 404 (anti-enumeração)
- User B NÃO consegue criar edge envolvendo só entities de A → 404
- User B NÃO consegue DELETE edge entre entities de A → 404
- Admin pode PATCH/DELETE qualquer entity (bypass)
- Legacy entities (sem owner) → acessíveis por qualquer user logado
- run_transform seta created_by_user_id do executor nas entidades resultantes
- is_owned_by no GraphManager (teste unitário direto)
"""

from __future__ import annotations

import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.core.graph_manager import GraphManager
from openm.extensions import db
from openm.models.user import User


# ===================== Config e fixtures =====================


class OwnershipTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


@pytest.fixture
def own_app():
    app = create_app(OwnershipTestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def own_client(own_app):
    return own_app.test_client()


@pytest.fixture(autouse=True)
def mock_graph(monkeypatch):
    """
    Mock do GraphManager com registro de owners explícito.

    API:
        mock.set_owner(entity_id, user_id)
            → marca owner
        mock.set_legacy(entity_id)
            → marca como legacy (sem owner)
        mock.is_owned_by(id, user_id)
            → checa
        mock.create_relationship(...)             → checa ownership das pontas
        mock.delete_relationship(...)             → idem
    """

    _OWNERS = {}  # entity_id -> user_id (int) ou None para legacy

    class _MockGraphManager:
        def __init__(self):
            self.merged = []
            self.rels = []
            self.deleted_entities = []
            self.deleted_rels = []

        # ===== API de configuração =====

        def set_owner(self, entity_id, user_id):
            _OWNERS[entity_id] = int(user_id)

        def set_legacy(self, entity_id):
            _OWNERS[entity_id] = None

        # ===== Implementação mockada =====

        def merge_entity(self, entity, *a, **k):
            if entity is not None and hasattr(entity, "id"):
                _OWNERS[entity.id] = getattr(
                    entity, "created_by_user_id", None
                )
            self.merged.append(entity)
            return None

        def get_entity(self, entity_id, *a, **k):
            if entity_id in _OWNERS:
                created_by_user_id = _OWNERS[entity_id]
                return {
                    "id": entity_id,
                    "created_by_user_id": created_by_user_id,
                }
            return None

        def is_owned_by(
            self, entity_id, user_id=None, is_admin=False, *a, **k
        ):
            if is_admin:
                return True
            if user_id is None:
                return False
            if entity_id not in _OWNERS:
                return False  # entity desconhecida → não-owner (404)
            owner = _OWNERS[entity_id]
            if owner is None:
                return True  # legacy
            return int(owner) == int(user_id)

        def create_relationship(
            self, from_id, to_id, rel_type,
            properties=None, user_id=None, is_admin=False, *a, **k
        ):
            if is_admin:
                self.rels.append((from_id, to_id))
                return True
            if user_id is None:
                self.rels.append((from_id, to_id))
                return True
            from_ok = self.is_owned_by(from_id, user_id)
            to_ok = self.is_owned_by(to_id, user_id)
            if from_ok or to_ok:
                self.rels.append((from_id, to_id))
                return True
            return False

        def delete_relationship(
            self, relationship_id, user_id=None, is_admin=False, *a, **k
        ):
            if is_admin:
                self.deleted_rels.append(relationship_id)
                return True
            if user_id is None:
                return False
            if not isinstance(relationship_id, str):
                return False
            if relationship_id.startswith("legacy-"):
                return True
            if relationship_id.startswith("owned-"):
                parts = relationship_id.split("-", 2)
                if len(parts) >= 2:
                    try:
                        owner = int(parts[1])
                        return owner == int(user_id)
                    except ValueError:
                        return False
            return False

        def update_entity_properties(
            self, entity_id, properties,
            user_id=None, is_admin=False, *a, **k
        ):
            return self.is_owned_by(entity_id, user_id, is_admin=is_admin)

        def delete_entity(
            self, entity_id, user_id=None, is_admin=False, *a, **k
        ):
            ok = self.is_owned_by(entity_id, user_id, is_admin=is_admin)
            if ok:
                self.deleted_entities.append(entity_id)
            return ok

        def get_subgraph(self, *a, **k):
            return {"elements": []}

    mock = _MockGraphManager()

    def fake(*a, **k):
        return mock

    modules = [
        "openm.utils.neo4j_client",
        "openm.api.graph",
        "openm.api.entities",
        "openm.api.transforms",
    ]
    for mod in modules:
        monkeypatch.setattr(f"{mod}.get_graph_manager", fake)

    return mock


def _create_user(app, email, password="pass-12345678", role="analyst"):
    with app.app_context():
        u = User(
            email=email,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        return u.id


def _login(client, email, password="pass-12345678"):
    resp = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ===================== Entity ownership =====================


class TestEntityOwnership:
    def test_create_entity_stamps_owner(
        self, own_app, own_client, mock_graph
    ):
        """POST /api/entity seta created_by_user_id no Entity."""
        alice_id = _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        resp = own_client.post(
            "/api/entity",
            json={"type": "Domain", "value": "example.com"},
            headers=_bearer(token),
        )
        assert resp.status_code == 201, resp.get_json()
        assert len(mock_graph.merged) == 1
        entity = mock_graph.merged[0]
        assert entity.created_by_user_id == alice_id

    def test_user_b_cannot_patch_user_a_entity(
        self, own_app, own_client, mock_graph
    ):
        """PATCH cross-user → 404 (anti-enumeração)."""
        alice_id = _create_user(own_app, "alice@x.com")
        _create_user(own_app, "bob@x.com")
        token_b = _login(own_client, "bob@x.com")

        mock_graph.set_owner("entity-x", alice_id)

        resp = own_client.patch(
            "/api/entity/entity-x",
            json={"properties": {"hack": "yes"}},
            headers=_bearer(token_b),
        )
        assert resp.status_code == 404
        assert "error" in resp.get_json()

    def test_user_b_cannot_delete_user_a_entity(
        self, own_app, own_client, mock_graph
    ):
        """DELETE cross-user → 404."""
        alice_id = _create_user(own_app, "alice@x.com")
        _create_user(own_app, "bob@x.com")
        token_b = _login(own_client, "bob@x.com")

        mock_graph.set_owner("entity-y", alice_id)

        resp = own_client.delete(
            "/api/entity/entity-y",
            headers=_bearer(token_b),
        )
        assert resp.status_code == 404

    def test_owner_can_patch_own_entity(
        self, own_app, own_client, mock_graph
    ):
        """PATCH da própria entity → 200."""
        alice_id = _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        mock_graph.set_owner("entity-z", alice_id)

        resp = own_client.patch(
            "/api/entity/entity-z",
            json={"properties": {"note": "updated"}},
            headers=_bearer(token),
        )
        assert resp.status_code == 200

    def test_owner_can_delete_own_entity(
        self, own_app, own_client, mock_graph
    ):
        """DELETE da própria entity → 200."""
        alice_id = _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        mock_graph.set_owner("entity-w", alice_id)

        resp = own_client.delete(
            "/api/entity/entity-w",
            headers=_bearer(token),
        )
        assert resp.status_code == 200
        assert "entity-w" in mock_graph.deleted_entities

    def test_legacy_entity_accessible_by_any_user(
        self, own_app, own_client, mock_graph
    ):
        """Entities legadas (sem owner) → qualquer user logado acessa."""
        _create_user(own_app, "bob@x.com")
        token = _login(own_client, "bob@x.com")

        mock_graph.set_legacy("legacy-old-1")

        resp = own_client.patch(
            "/api/entity/legacy-old-1",
            json={"properties": {"x": 1}},
            headers=_bearer(token),
        )
        assert resp.status_code == 200

    def test_unknown_entity_returns_404(
        self, own_app, own_client, mock_graph
    ):
        """Entity inexistente → 404 (não vaza existência)."""
        _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        resp = own_client.patch(
            "/api/entity/does-not-exist",
            json={"properties": {}},
            headers=_bearer(token),
        )
        assert resp.status_code == 404


# ===================== Admin bypass =====================


class TestAdminBypass:
    def test_admin_can_patch_any_entity(
        self, own_app, own_client, mock_graph
    ):
        """Admin role ignora ownership check."""
        _create_user(own_app, "admin@x.com", role="admin")
        token = _login(own_client, "admin@x.com")

        mock_graph.set_owner("alice-entity-1", 999)

        resp = own_client.patch(
            "/api/entity/alice-entity-1",
            json={"properties": {"admin": "yes"}},
            headers=_bearer(token),
        )
        assert resp.status_code == 200

    def test_admin_can_delete_any_entity(
        self, own_app, own_client, mock_graph
    ):
        _create_user(own_app, "admin@x.com", role="admin")
        token = _login(own_client, "admin@x.com")

        mock_graph.set_owner("bob-entity-2", 999)

        resp = own_client.delete(
            "/api/entity/bob-entity-2",
            headers=_bearer(token),
        )
        assert resp.status_code == 200

    def test_viewer_cannot_modify_entities(
        self, own_app, own_client, mock_graph
    ):
        """Viewer role → 403 antes de chegar no ownership check."""
        _create_user(own_app, "viewer@x.com", role="viewer")
        token = _login(own_client, "viewer@x.com")

        resp = own_client.patch(
            "/api/entity/some-entity",
            json={"properties": {}},
            headers=_bearer(token),
        )
        assert resp.status_code == 403


# ===================== Edge ownership =====================


class TestEdgeOwnership:
    def test_create_edge_with_owned_passes(
        self, own_app, own_client, mock_graph
    ):
        """Edge onde ambas pontas são do user → 201."""
        alice_id = _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        mock_graph.set_owner("from-1", alice_id)
        mock_graph.set_owner("to-1", alice_id)

        resp = own_client.post(
            "/api/edge",
            json={
                "from_id": "from-1",
                "to_id": "to-1",
                "rel_type": "related_to",
            },
            headers=_bearer(token),
        )
        assert resp.status_code == 201, resp.get_json()

    def test_create_edge_with_legacy_passes(
        self, own_app, own_client, mock_graph
    ):
        """Edge envolvendo entity legada → qualquer user pode criar."""
        bob_id = _create_user(own_app, "bob@x.com")
        token = _login(own_client, "bob@x.com")

        mock_graph.set_legacy("legacy-1")
        mock_graph.set_owner("own-2", bob_id)

        resp = own_client.post(
            "/api/edge",
            json={
                "from_id": "legacy-1",
                "to_id": "own-2",
                "rel_type": "related_to",
            },
            headers=_bearer(token),
        )
        assert resp.status_code == 201, resp.get_json()

    def test_create_edge_cross_user_blocked(
        self, own_app, own_client, mock_graph
    ):
        """Edge entre entities de users diferentes (não-legacy) → 404."""
        alice_id = _create_user(own_app, "alice@x.com")
        _create_user(own_app, "bob@x.com")
        token_b = _login(own_client, "bob@x.com")

        mock_graph.set_owner("alice-1", alice_id)
        mock_graph.set_owner("alice-2", alice_id)

        resp = own_client.post(
            "/api/edge",
            json={
                "from_id": "alice-1",
                "to_id": "alice-2",
                "rel_type": "hack",
            },
            headers=_bearer(token_b),
        )
        assert resp.status_code == 404, resp.get_json()

    def test_delete_edge_cross_user_blocked(
        self, own_app, own_client, mock_graph
    ):
        """DELETE edge cross-user → 404."""
        alice_id = _create_user(own_app, "alice@x.com")
        _create_user(own_app, "bob@x.com")
        token_b = _login(own_client, "bob@x.com")

        rel_id = f"owned-{alice_id}-abc123"

        resp = own_client.delete(
            f"/api/edge/{rel_id}",
            headers=_bearer(token_b),
        )
        assert resp.status_code == 404, resp.get_json()

    def test_owner_can_delete_own_edge(
        self, own_app, own_client, mock_graph
    ):
        alice_id = _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        rel_id = f"owned-{alice_id}-abc123"

        resp = own_client.delete(
            f"/api/edge/{rel_id}",
            headers=_bearer(token),
        )
        assert resp.status_code == 200

    def test_legacy_edge_accessible_by_anyone(
        self, own_app, own_client, mock_graph
    ):
        _create_user(own_app, "bob@x.com")
        token = _login(own_client, "bob@x.com")

        resp = own_client.delete(
            "/api/edge/legacy-edge-1",
            headers=_bearer(token),
        )
        assert resp.status_code == 200


# ===================== Transform ownership =====================


class TestTransformOwnership:
    def test_run_transform_stamps_owner_on_input_and_results(
        self, own_app, own_client, mock_graph
    ):
        """
        run_transform seta created_by_user_id no input entity e em cada
        new_entity retornada pelo transform.
        """
        alice_id = _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        from openm.core.entity import Domain
        from openm.core.transform import TransformResult, TransformRegistry

        class FakeTransform:
            def run(self, entity):
                sub = Domain(value="sub.example.com")
                return TransformResult(
                    entities=[sub],
                    relationships=[
                        {
                            "from_id": entity.id,
                            "to_id": sub.id,
                            "type": "resolves_to",
                            "properties": {},
                        }
                    ],
                )

        TransformRegistry.register(FakeTransform, name="fake_transform")
        try:
            resp = own_client.post(
                "/api/run_transform",
                json={
                    "transform_name": "fake_transform",
                    "entity_type": "Domain",
                    "value": "example.com",
                },
                headers=_bearer(token),
            )
            assert resp.status_code == 200, resp.get_json()

            assert len(mock_graph.merged) == 2
            input_entity = mock_graph.merged[0]
            sub_entity = mock_graph.merged[1]
            assert input_entity.created_by_user_id == alice_id
            assert sub_entity.created_by_user_id == alice_id
        finally:
            TransformRegistry._transforms.pop("fake_transform", None)


# ===================== Unit tests do GraphManager.is_owned_by
# =====================


_SENTINEL_NO_NODE = object()


class TestIsOwnedByUnit:
    """
    Testes diretos do método is_owned_by sem precisar de Flask.
    Usa stub do driver Neo4j pra simular o retorno do Cypher.
    """

    def _make_gm_with_node(self, owner_id):
        """Cria um GraphManager com driver mock que retorna um nó."""

        class _StubSession:
            def __init__(self, owner):
                self._owner = owner

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def run(self, query, **params):
                class _StubResult:
                    def __init__(self, owner):
                        self._owner = owner

                    def single(self):
                        if self._owner is _SENTINEL_NO_NODE:
                            return None
                        return {"owner_id": self._owner}

                return _StubResult(self._owner)

        class _StubDriver:
            def __init__(self, owner):
                self._owner = owner

            def session(self):
                return _StubSession(self._owner)

        gm = GraphManager.__new__(GraphManager)
        gm._available = True
        gm.driver = _StubDriver(owner_id)
        return gm

    def test_admin_always_passes(self):
        gm = self._make_gm_with_node(owner_id=1)
        assert gm.is_owned_by("any-id", user_id=99, is_admin=True) is True

    def test_owner_user_passes(self):
        gm = self._make_gm_with_node(owner_id=42)
        assert gm.is_owned_by("any-id", user_id=42) is True

    def test_other_user_blocked(self):
        gm = self._make_gm_with_node(owner_id=42)
        assert gm.is_owned_by("any-id", user_id=99) is False

    def test_legacy_entity_visible_to_anyone(self):
        gm = self._make_gm_with_node(owner_id=None)
        assert gm.is_owned_by("any-id", user_id=99) is True

    def test_missing_entity_returns_false(self):
        gm = self._make_gm_with_node(owner_id=_SENTINEL_NO_NODE)
        assert gm.is_owned_by("any-id", user_id=99) is False


# ===================== Validação de inputs =====================


class TestAuthRequirements:
    def test_patch_entity_without_auth_returns_401(
        self, own_app, own_client, mock_graph
    ):
        resp = own_client.patch(
            "/api/entity/some-entity",
            json={"properties": {}},
        )
        assert resp.status_code == 401

    def test_delete_entity_without_auth_returns_401(
        self, own_app, own_client, mock_graph
    ):
        resp = own_client.delete("/api/entity/some-entity")
        assert resp.status_code == 401

    def test_create_edge_without_auth_returns_401(
        self, own_app, own_client, mock_graph
    ):
        resp = own_client.post(
            "/api/edge",
            json={"from_id": "a", "to_id": "b", "rel_type": "r"},
        )
        assert resp.status_code == 401
