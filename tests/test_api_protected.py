"""
Testes de proteção das APIs (issue #13, Bloco 4).

Garante que TODAS as rotas da API (exceto /api/auth/* e /health)
retornam 401 sem autenticação válida, e 200 com token válido.
"""

from __future__ import annotations

import time

import jwt
import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User


class ApiProtTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


@pytest.fixture
def api_prot_app():
    app = create_app(ApiProtTestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def api_prot_client(api_prot_app):
    return api_prot_app.test_client()


@pytest.fixture
def api_prot_token(api_prot_app):
    """Cria um user e devolve um access token válido."""
    with api_prot_app.app_context():
        user = User(
            email="api@example.com",
            password_hash=hash_password("api-password-123"),
            role="analyst",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    client = api_prot_app.test_client()
    resp = client.post(
        "/api/auth/login",
        json={"email": "api@example.com", "password": "api-password-123"},
    )
    return resp.get_json()["access_token"]


class _FakeGraphManager:
    """Stub do Neo4j manager pra testes que não precisam de DB real."""
    def get_subgraph(self, *args, **kwargs):
        return {"nodes": [], "edges": []}

    def get_entity(self, *args, **kwargs):
        return None

    def is_owned_by(self, *args, **kwargs):
        return False

    def create_relationship(self, *args, **kwargs):
        return True

    def delete_relationship(self, *args, **kwargs):
        return True

    def merge_entity(self, *args, **kwargs):
        return None

    def update_entity_properties(self, *args, **kwargs):
        return True

    def delete_entity(self, *args, **kwargs):
        return True


@pytest.fixture(autouse=True)
def mock_neo4j(monkeypatch):
    """
    Mocka get_graph_manager em todos os blueprints que usam Neo4j.

    Os blueprints importam a função diretamente, então precisamos patchar
    o nome em cada módulo consumidor.
    """
    def fake(*args, **kwargs):
        return _FakeGraphManager()

    modules = [
        "openm.utils.neo4j_client",
        "openm.api.graph",
        "openm.api.entities",
        "openm.api.transforms",
    ]
    for mod_name in modules:
        monkeypatch.setattr(f"{mod_name}.get_graph_manager", fake)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# Lista de rotas que DEVEM exigir auth.
# /api/auth/* são públicas (exceto /me), /health é público.
PROTECTED_ROUTES = [
    ("POST", "/api/entity", {"type": "Domain", "value": "x"}),
    ("PATCH", "/api/entity/abc", {"properties": {}}),
    ("DELETE", "/api/entity/abc", None),
    ("GET", "/api/transforms/Domain", None),
    ("POST", "/api/run_transform", {"transform_name": "x", "entity_type": "y", "value": "z"}),
    ("GET", "/api/subgraph/abc", None),
    ("POST", "/api/edge", {"from_id": "a", "to_id": "b", "rel_type": "r"}),
    ("DELETE", "/api/edge/abc", None),
    ("POST", "/api/investigations", {"title": "t"}),
    ("GET", "/api/investigations", None),
    ("GET", "/api/investigations/1", None),
    ("GET", "/api/keys", None),
    ("POST", "/api/keys", {"service_name": "s", "key_value": "k"}),
    ("DELETE", "/api/keys/1", None),
    ("GET", "/api/auth/me", None),
]


@pytest.mark.parametrize("method,path,payload", PROTECTED_ROUTES)
def test_protected_route_returns_401_without_auth(api_prot_client, method, path, payload):
    kwargs = {"json": payload} if payload is not None else {}
    resp = api_prot_client.open(method=method, path=path, **kwargs)
    assert resp.status_code == 401, f"{method} {path} deveria ser 401, veio {resp.status_code}"


@pytest.mark.parametrize("method,path,payload", PROTECTED_ROUTES)
def test_protected_route_returns_401_with_invalid_token(api_prot_client, method, path, payload):
    bad = jwt.encode(
        {"sub": "1", "type": "access", "exp": int(time.time()) + 60},
        "wrong-secret",
        algorithm="HS256",
    )
    kwargs = {"json": payload} if payload is not None else {}
    kwargs["headers"] = _bearer(bad)
    resp = api_prot_client.open(method=method, path=path, **kwargs)
    assert resp.status_code == 401, f"{method} {path} com token inválido deveria ser 401"


@pytest.mark.parametrize("method,path,payload", PROTECTED_ROUTES)
def test_protected_route_accepts_valid_token(api_prot_client, api_prot_token, method, path, payload):
    """
    Com token válido, a rota deve passar da barreira de auth (status != 401).

    Pode falhar por outras razões (404, 400) dependendo da rota, mas o que
    nos importa aqui é que NÃO é 401.
    """
    kwargs = {"headers": _bearer(api_prot_token)}
    if payload is not None:
        kwargs["json"] = payload
    resp = api_prot_client.open(method=method, path=path, **kwargs)
    assert resp.status_code != 401, f"{method} {path} deveria passar auth com token válido"


# ================ Rotas públicas ================
#
# /health: rota totalmente pública, sempre deve dar 2xx sem auth.
# /api/auth/*: rotas de auth usam 4xx como sinal de credenciais erradas.
#             O importante é que NUNCA exigem Authorization prévia.

HEALTH_ROUTES = [("GET", "/health", None)]


@pytest.mark.parametrize("method,path,payload", HEALTH_ROUTES)
def test_health_route_is_public(api_prot_client, method, path, payload):
    """Rota /health nunca deve exigir auth."""
    kwargs = {"json": payload} if payload else {}
    resp = api_prot_client.open(method=method, path=path, **kwargs)
    assert 200 <= resp.status_code < 300, f"{method} {path} deveria ser 2xx"


# Rotas de auth — validam que são acessíveis sem Authorization prévia.
# Status varia (200, 400, 401) dependendo do payload, mas nunca 401
# por falta de Bearer.
AUTH_PUBLIC_ROUTES = [
    ("POST", "/api/auth/login", {"email": "ghost@example.com", "password": "x"}),
    ("POST", "/api/auth/register", {"email": "x@x.com", "password": "short"}),
    ("POST", "/api/auth/refresh", {"refresh_token": "invalid"}),
    ("POST", "/api/auth/logout", {}),
]


@pytest.mark.parametrize("method,path,payload", AUTH_PUBLIC_ROUTES)
def test_auth_routes_do_not_require_bearer(api_prot_client, method, path, payload):
    """
    Rotas de auth não exigem Authorization prévia.

    401 aqui significa "credenciais inválidas" (correto), não "faltou Bearer".
    Aceitamos 4xx mas rejeitamos 403/5xx.
    """
    kwargs = {"json": payload} if payload else {}
    resp = api_prot_client.open(method=method, path=path, **kwargs)
    assert resp.status_code < 500, f"{method} {path} deu erro 5xx: {resp.status_code}"
    assert resp.status_code != 403, f"{method} {path} deu 403 (deveria ser 400/401)"
