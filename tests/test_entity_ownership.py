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
from openm.core.entity import Domain
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

    def test_unavailable_driver_returns_false(self):
        """Quando Neo4j não está disponível, is_owned_by retorna False."""
        gm = self._make_gm_with_node(owner_id=42)
        gm._available = False
        assert gm.is_owned_by("any-id", user_id=42) is False
        assert gm.is_owned_by("any-id", user_id=42, is_admin=True) is False


# ===================== Unit tests do GraphManager: demais métodos
# =====================


class _RecordingSession:
    """Sessão Neo4j mockada que registra todas as queries executadas."""

    def __init__(self, response_value=None, single_value=None):
        self.queries = []
        self.params_list = []
        self._response = response_value
        self._single = single_value

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.queries.append(query)
        self.params_list.append(params)
        return self

    def single(self):
        return self._single


class _RecordingDriver:
    def __init__(self, single_value=None):
        self.single_value = single_value
        self.sessions = []

    def session(self):
        s = _RecordingSession(single_value=self.single_value)
        self.sessions.append(s)
        return s


def _make_gm_available(single_value=None):
    """Cria GraphManager disponível com driver que captura tudo."""
    gm = GraphManager.__new__(GraphManager)
    gm._available = True
    gm.driver = _RecordingDriver(single_value=single_value)
    return gm


class TestGraphManagerUnit:
    """Cobertura unitária dos métodos do GraphManager com driver stub."""

    # ----- merge_entity -----

    def test_merge_entity_writes_user_id(self):
        """merge_entity persiste created_by_user_id no SET Cypher."""
        gm = _make_gm_available()
        entity = Domain(
            value="x.com", properties={"k": "v"}, created_by_user_id=42
        )
        gm.merge_entity(entity)
        assert len(gm.driver.sessions) == 1
        sess = gm.driver.sessions[0]
        # Query contém o SET com user_id
        assert "n.created_by_user_id = $user_id" in sess.queries[0]
        assert sess.params_list[0]["user_id"] == 42
        assert sess.params_list[0]["id"] == entity.id

    def test_merge_entity_unavailable_skips(self):
        """Quando Neo4j indisponível, merge_entity é no-op silencioso."""
        gm = GraphManager.__new__(GraphManager)
        gm._available = False
        gm.driver = _RecordingDriver()
        gm.merge_entity(Domain(value="x.com", created_by_user_id=1))
        assert gm.driver.sessions == []

    # ----- create_relationship -----

    def test_create_relationship_admin_skips_ownership(self):
        """Admin bypassa o ownership check."""
        gm = _make_gm_available()
        ok = gm.create_relationship(
            "a", "b", "REL", user_id=1, is_admin=True
        )
        assert ok is True
        assert len(gm.driver.sessions) == 1

    def test_create_relationship_no_user_id_skips_ownership(self):
        """Sem user_id, ownership não é checado (compatibilidade)."""
        gm = _make_gm_available()
        ok = gm.create_relationship("a", "b", "REL")
        assert ok is True

    def test_create_relationship_blocked_when_neither_owned(self):
        """Se nenhuma ponta é do user, retorna False sem chamar Neo4j."""
        # _make_gm_with_node: from_id "alice-x" é owned by 1, "bob-y" por 2
        gm = _make_gm_available()
        ok = gm.create_relationship(
            "alice-x", "bob-y", "REL", user_id=99
        )
        assert ok is False
        # is_owned_by é chamado 2x (from + to), criando 2 sessões,
        # mas a query de MERGE nunca roda.
        assert len(gm.driver.sessions) == 2
        for sess in gm.driver.sessions:
            assert "created_by_user_id" in sess.queries[0]
        # Nenhuma das queries é o MERGE final
        all_queries = [q for s in gm.driver.sessions for q in s.queries]
        assert not any("MERGE" in q for q in all_queries)

    def test_create_relationship_unavailable_returns_true(self):
        """Compat: Neo4j indisponível → retorna True (não bloqueia)."""
        gm = GraphManager.__new__(GraphManager)
        gm._available = False
        gm.driver = _RecordingDriver()
        ok = gm.create_relationship(
            "a", "b", "REL", user_id=1, is_admin=False
        )
        assert ok is True
        assert gm.driver.sessions == []

    # ----- update_entity_properties -----

    def test_update_entity_properties_owner_passes(self):
        """Owner pode atualizar."""
        gm = _make_gm_available(single_value={"owner_id": 42})
        ok = gm.update_entity_properties(
            "e1", {"x": 1}, user_id=42
        )
        assert ok is True
        # Sessão 0 = is_owned_by lookup, sessão 1 = update real
        assert len(gm.driver.sessions) == 2
        assert "SET n += $props" in gm.driver.sessions[1].queries[0]

    def test_update_entity_properties_admin_bypasses(self):
        gm = _make_gm_available(single_value={"owner_id": 1})
        ok = gm.update_entity_properties(
            "e1", {"x": 1}, user_id=99, is_admin=True
        )
        assert ok is True
        # Admin bypassa is_owned_by → só 1 sessão (update direto)
        assert len(gm.driver.sessions) == 1
        assert "SET n += $props" in gm.driver.sessions[0].queries[0]

    def test_update_entity_properties_blocked_cross_user(self):
        """Cross-user → False antes de chamar Neo4j."""
        gm = _make_gm_available(single_value={"owner_id": 1})
        ok = gm.update_entity_properties(
            "e1", {"x": 1}, user_id=99
        )
        assert ok is False
        # is_owned_by foi chamado (1 sessão), update NÃO
        assert len(gm.driver.sessions) == 1
        assert "created_by_user_id" in gm.driver.sessions[0].queries[0]

    def test_update_entity_properties_missing_entity_returns_false(self):
        gm = _make_gm_available(single_value=None)
        ok = gm.update_entity_properties(
            "e1", {"x": 1}, user_id=99
        )
        assert ok is False
        assert len(gm.driver.sessions) == 1

    def test_update_entity_properties_unavailable_returns_true(self):
        gm = GraphManager.__new__(GraphManager)
        gm._available = False
        gm.driver = _RecordingDriver()
        ok = gm.update_entity_properties(
            "e1", {"x": 1}, user_id=99
        )
        assert ok is True
        assert gm.driver.sessions == []

    # ----- delete_entity -----

    def test_delete_entity_owner_passes(self):
        gm = _make_gm_available(single_value={"owner_id": 42})
        ok = gm.delete_entity("e1", user_id=42)
        assert ok is True
        # Sessão 0 = is_owned_by, sessão 1 = delete
        assert len(gm.driver.sessions) == 2
        assert "DETACH DELETE" in gm.driver.sessions[1].queries[0]

    def test_delete_entity_admin_bypasses(self):
        gm = _make_gm_available(single_value={"owner_id": 1})
        ok = gm.delete_entity("e1", user_id=99, is_admin=True)
        assert ok is True
        assert len(gm.driver.sessions) == 1
        assert "DETACH DELETE" in gm.driver.sessions[0].queries[0]

    def test_delete_entity_blocked_cross_user(self):
        gm = _make_gm_available(single_value={"owner_id": 1})
        ok = gm.delete_entity("e1", user_id=99)
        assert ok is False
        assert len(gm.driver.sessions) == 1
        assert "created_by_user_id" in gm.driver.sessions[0].queries[0]

    def test_delete_entity_missing_returns_false(self):
        gm = _make_gm_available(single_value=None)
        ok = gm.delete_entity("e1", user_id=99)
        assert ok is False
        assert len(gm.driver.sessions) == 1

    def test_delete_entity_unavailable_returns_true(self):
        gm = GraphManager.__new__(GraphManager)
        gm._available = False
        gm.driver = _RecordingDriver()
        ok = gm.delete_entity("e1", user_id=99)
        assert ok is True
        assert gm.driver.sessions == []

    # ----- delete_relationship -----

    def _make_gm_for_rel(self, from_id="a", to_id="b"):
        """Cria GM que retorna (from_id, to_id) na query de
        delete_relationship.
        """

        class _RelSession(_RecordingSession):
            def single(self):
                return {"from_id": from_id, "to_id": to_id}

        class _RelDriver:
            def __init__(self):
                self.sessions = []

            def session(self):
                s = _RelSession()
                self.sessions.append(s)
                return s

        gm = GraphManager.__new__(GraphManager)
        gm._available = True
        gm.driver = _RelDriver()
        return gm

    def test_delete_relationship_owner_passes(self):
        """Quando uma das pontas é do user, deletar passa."""
        gm = GraphManager.__new__(GraphManager)
        gm._available = True

        class _MultiSession:
            def __init__(self):
                self.queries = []
                self.last_query = None

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def run(self, query, **params):
                self.queries.append(query)
                self.last_query = query
                return self

            def single(self):
                # is_owned_by: legacy (None) → True
                if "created_by_user_id" in (self.last_query or ""):
                    return {"owner_id": None}
                # delete_relationship lookup: from_id/to_id
                return {"from_id": "legacy-1", "to_id": "legacy-2"}

        class _MultiDriver:
            def __init__(self):
                self.sessions = []

            def session(self):
                s = _MultiSession()
                self.sessions.append(s)
                return s

        gm.driver = _MultiDriver()
        ok = gm.delete_relationship("rel-123", user_id=42)
        assert ok is True
        # 3 sessões: is_owned_by(from_id) + is_owned_by(to_id) + delete
        # legacy-1 é owned por qualquer (None) → is_owned_by retorna True na 1ª
        # 2ª chamada (to_id=legacy-2): já bateu o `or`, mas o `or`
        # short-circuits, então pode haver 2 OU 3 sessões dependendo
        # da ordem.
        assert len(gm.driver.sessions) >= 2
        # Última sessão: DELETE r
        last = gm.driver.sessions[-1]
        assert "DELETE r" in last.queries[0]

    def test_delete_relationship_admin_bypasses(self):
        """Admin pode deletar sem checar ownership."""
        gm = _make_gm_available()
        ok = gm.delete_relationship("rel-123", user_id=99, is_admin=True)
        assert ok is True
        assert "DELETE r" in gm.driver.sessions[0].queries[0]

    def test_delete_relationship_blocked_cross_user(self):
        """Quando nenhuma ponta é do user, retorna False."""

        class _NoOwnershipSession:
            def __init__(self):
                self.queries = []

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def run(self, query, **params):
                self.queries.append(query)
                return self

            def single(self):
                # lookup from_id/to_id
                if "created_by_user_id" in (self.queries[-1] or ""):
                    return {"owner_id": 999}  # outro user
                return {"from_id": "alice-1", "to_id": "bob-1"}

        class _NoOwnershipDriver:
            def session(self):
                return _NoOwnershipSession()

        gm = GraphManager.__new__(GraphManager)
        gm._available = True
        gm.driver = _NoOwnershipDriver()
        ok = gm.delete_relationship("rel-123", user_id=42)
        assert ok is False

    def test_delete_relationship_missing_returns_false(self):
        """Quando lookup retorna None (edge não existe), retorna False."""

        class _MissingSession:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def run(self, query, **params):
                return self

            def single(self):
                return None

        class _MissingDriver:
            def session(self):
                return _MissingSession()

        gm = GraphManager.__new__(GraphManager)
        gm._available = True
        gm.driver = _MissingDriver()
        ok = gm.delete_relationship("rel-123", user_id=42)
        assert ok is False

    def test_delete_relationship_unavailable_returns_true(self):
        gm = GraphManager.__new__(GraphManager)
        gm._available = False
        gm.driver = _RecordingDriver()
        ok = gm.delete_relationship("rel-123", user_id=42)
        assert ok is True

    # ----- close -----

    def test_close_closes_driver(self):
        """close() delega para driver.close()."""
        gm = GraphManager.__new__(GraphManager)
        closed = []

        class _CloseableDriver:
            def close(self):
                closed.append(True)

        gm.driver = _CloseableDriver()
        gm.close()
        assert closed == [True]

    # ----- ensure_constraints -----

    def test_ensure_constraints_success_marks_available(self):
        """Quando Neo4j responde, seta _available=True."""
        gm = GraphManager.__new__(GraphManager)
        gm._available = False
        gm.driver = _RecordingDriver()
        gm.ensure_constraints()
        assert gm._available is True
        assert len(gm.driver.sessions) == 1
        assert "CREATE CONSTRAINT" in gm.driver.sessions[0].queries[0]

    def test_ensure_constraints_failure_marks_unavailable_and_raises(self):
        """Quando Neo4j falha, seta _available=False e propaga exceção."""

        class _FailingSession:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def run(self, query, **params):
                raise RuntimeError("Neo4j offline")

        class _FailingDriver:
            def session(self):
                return _FailingSession()

        gm = GraphManager.__new__(GraphManager)
        gm._available = True
        gm.driver = _FailingDriver()
        import pytest as _pytest
        with _pytest.raises(RuntimeError, match="Neo4j offline"):
            gm.ensure_constraints()
        assert gm._available is False

    # ----- get_entity -----

    def test_get_entity_returns_dict_when_found(self):
        """get_entity retorna _node_to_cytoscape quando nó existe."""

        class _Node:
            def get(self, key, default=None):
                data = {
                    "id": "e1", "value": "x.com", "type": "Domain",
                    "properties": '{"k": "v"}',
                }
                return data.get(key, default)

            def __getitem__(self, key):
                return self.get(key)

        class _GE_Session:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def run(self, query, **params):
                return self

            def single(self):
                return {"n": _Node()}

        class _GE_Driver:
            def session(self):
                return _GE_Session()

        gm = GraphManager.__new__(GraphManager)
        gm._available = True
        gm.driver = _GE_Driver()
        result = gm.get_entity("e1")
        assert result is not None
        assert result["data"]["id"] == "e1"

    def test_get_entity_returns_none_when_missing(self):
        """get_entity retorna None quando nó não existe."""

        class _Missing_Session:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def run(self, query, **params):
                return self

            def single(self):
                return None

        class _Missing_Driver:
            def session(self):
                return _Missing_Session()

        gm = GraphManager.__new__(GraphManager)
        gm._available = True
        gm.driver = _Missing_Driver()
        assert gm.get_entity("e1") is None

    def test_get_entity_unavailable_returns_none(self):
        gm = GraphManager.__new__(GraphManager)
        gm._available = False
        gm.driver = _RecordingDriver()
        assert gm.get_entity("e1") is None

    # ----- clear -----

    def test_clear_runs_detach_delete(self):
        gm = _make_gm_available()
        gm.clear()
        assert len(gm.driver.sessions) == 1
        assert "DETACH DELETE" in gm.driver.sessions[0].queries[0]

    def test_clear_unavailable_is_noop(self):
        gm = GraphManager.__new__(GraphManager)
        gm._available = False
        gm.driver = _RecordingDriver()
        gm.clear()
        assert gm.driver.sessions == []

    # ----- get_subgraph -----

    def test_get_subgraph_returns_elements(self):
        """get_subgraph parseia nodes/rels do Neo4j."""

        class _Node:
            def __init__(self, id_, value, type_):
                self._id = id_
                self._value = value
                self._type = type_

            def get(self, key, default=None):
                data = {
                    "id": self._id, "value": self._value, "type": self._type,
                    "properties": "{}",
                }
                return data.get(key, default)

            def __getitem__(self, key):
                return self.get(key)

        class _Rel:
            element_id = "e:1:abc"
            type = "RESOLVES_TO"

            def __init__(self, start, end):
                self.start_node = start
                self.end_node = end

            def items(self):
                return iter([("updated_at", "2025-01-01")])

        class _Sub_Session:
            def __init__(self):
                self.records = [
                    {
                        "center": _Node("c1", "example.com", "Domain"),
                        "nodes": [
                            _Node("c1", "example.com", "Domain"),
                            _Node("n1", "1.2.3.4", "IPAddress"),
                        ],
                        "rels": [_Rel(
                            _Node("c1", "example.com", "Domain"),
                            _Node("n1", "1.2.3.4", "IPAddress"),
                        )],
                    }
                ]

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def run(self, query, **params):
                return self

            def __iter__(self):
                return iter(self.records)

        class _Sub_Driver:
            def session(self):
                return _Sub_Session()

        gm = GraphManager.__new__(GraphManager)
        gm._available = True
        gm.driver = _Sub_Driver()
        result = gm.get_subgraph("example.com", depth=2)
        assert "elements" in result
        assert len(result["elements"]["nodes"]) == 2
        assert len(result["elements"]["edges"]) == 1
        assert result["elements"]["edges"][0]["data"]["label"] == "RESOLVES_TO"

    def test_get_subgraph_clamps_depth(self):
        """get_subgraph limita depth entre 1 e 5."""
        gm = GraphManager.__new__(GraphManager)

        class _Iter_Session:
            queries = []

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def run(self, query, **params):
                _Iter_Session.queries.append(query)
                return self

            def __iter__(self):
                return iter([])

        class _Iter_Driver:
            def session(self):
                return _Iter_Session()

        gm._available = True
        gm.driver = _Iter_Driver()
        _Iter_Session.queries = []

        # depth=0 → clamped to 1
        gm.get_subgraph("x", depth=0)
        assert "*1..1" in _Iter_Session.queries[-1]
        # depth=999 → clamped to 5
        gm.get_subgraph("x", depth=999)
        assert "*1..5" in _Iter_Session.queries[-1]

    # ----- _node_to_cytoscape / _rel_to_cytoscape -----

    def test_node_to_cytoscape_parses_json_properties(self):
        """_node_to_cytoscape deserializa properties JSON."""

        class _N:
            def get(self, key, default=None):
                data = {
                    "id": "e1", "value": "x.com", "type": "Domain",
                    "properties": '{"k": "v"}',
                }
                return data.get(key, default)

            def __getitem__(self, key):
                return self.get(key)

        result = GraphManager._node_to_cytoscape(_N())
        assert result["data"]["id"] == "e1"
        assert result["data"]["k"] == "v"

    def test_node_to_cytoscape_handles_invalid_json(self):
        """Quando properties JSON é inválido, retorna dict vazio."""

        class _N:
            def get(self, key, default=None):
                data = {
                    "id": "e1", "value": "x", "type": "Domain",
                    "properties": "not-json{",
                }
                return data.get(key, default)

            def __getitem__(self, key):
                return self.get(key)

        result = GraphManager._node_to_cytoscape(_N())
        # properties inválidas → {} (sem erro)
        assert result["data"]["id"] == "e1"
        assert "k" not in result["data"]

    def test_rel_to_cytoscape_strips_metadata(self):
        """_rel_to_cytoscape remove updated_at e outros metadados."""

        class _StartNode:
            def __getitem__(self, key):
                return "src"

        class _EndNode:
            def __getitem__(self, key):
                return "dst"

        class _R:
            element_id = "r:1:abc"
            type = "LINKS"
            start_node = _StartNode()
            end_node = _EndNode()

            def items(self):
                return iter([("updated_at", "x"), ("weight", 0.5)])

        result = GraphManager._rel_to_cytoscape(_R())
        assert result["data"]["id"] == "r:1:abc"
        assert result["data"]["label"] == "LINKS"
        assert result["data"]["weight"] == 0.5
        assert "updated_at" not in result["data"]


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


# ===================== Transform validation errors =====================


class TestTransformValidation:
    """Cobertura de erros 400 do run_transform."""

    def test_missing_transform_name_returns_400(
        self, own_app, own_client, mock_graph
    ):
        _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        resp = own_client.post(
            "/api/run_transform",
            json={
                "entity_type": "Domain",
                "value": "example.com",
            },
            headers=_bearer(token),
        )
        assert resp.status_code == 400
        assert "transform_name" in resp.get_json()["error"]

    def test_missing_entity_type_or_value_returns_400(
        self, own_app, own_client, mock_graph
    ):
        _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        # Falta entity_type
        resp = own_client.post(
            "/api/run_transform",
            json={"transform_name": "fake", "value": "x"},
            headers=_bearer(token),
        )
        assert resp.status_code == 400

        # Falta value
        resp = own_client.post(
            "/api/run_transform",
            json={"transform_name": "fake", "entity_type": "Domain"},
            headers=_bearer(token),
        )
        assert resp.status_code == 400

    def test_unknown_entity_type_returns_400(
        self, own_app, own_client, mock_graph
    ):
        _create_user(own_app, "alice@x.com")
        token = _login(own_client, "alice@x.com")

        resp = own_client.post(
            "/api/run_transform",
            json={
                "transform_name": "fake",
                "entity_type": "NonExistent",
                "value": "x",
            },
            headers=_bearer(token),
        )
        assert resp.status_code == 400
        assert "desconhecido" in resp.get_json()["error"].lower()
