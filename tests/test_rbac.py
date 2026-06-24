"""
Testes de RBAC — issue #3.

Cobre:
- Decorator @require_role (403 quando role não bate, 200/201 quando bate).
- Matriz de permissões aplicada em todos os blueprints.
- Blueprint /api/admin/* (listar/alterar role/ativar-desativar).
- Proteções do admin (auto-rebaixamento, último admin).
"""

import pytest

from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.api_key import ApiKey
from openm.models.user import User


@pytest.fixture(autouse=True)
def _seed_for_matrix(app, request):
    """
    Popula o DB com uma ApiKey de teste e expõe o id dela como
    ``rbac_key_id`` no ``request.node`` para o teste parametrizado usar.
    """
    with app.app_context():
        existing = ApiKey.query.filter_by(service_name="rbac-test").first()
        if not existing:
            db.session.add(ApiKey(
                service_name="rbac-test",
                key_value="dummy-key",
                key_type="free",
                is_active=True,
            ))
            db.session.commit()
            existing = ApiKey.query.filter_by(service_name="rbac-test").first()
        request.node.rbac_key_id = existing.id


# ===================== Matriz de permissões =====================
#
# (método, path_template, viewer_ok, analyst_ok, admin_ok)
# Onde _ok significa "esperamos status de sucesso (200/201/204)".
# Endpoints não listados (autenticação) seguem outra lógica.

_PERMISSION_MATRIX = [
    # Investigations — leitura liberada, escrita só admin+analyst
    ("GET",    "/api/investigations",             True,  True,  True),
    ("POST",   "/api/investigations",             False, True,  True),
    # Entities — escrita restrita
    ("POST",   "/api/entity",                     False, True,  True),
    ("PATCH",  "/api/entity/ok1",                 False, True,  True),
    ("DELETE", "/api/entity/ok1",                 False, True,  True),
    # Transforms — só execução é restrita
    ("POST",   "/api/run_transform",              False, True,  True),
    # Graph — escrita de edges restrita
    ("POST",   "/api/edge",                       False, True,  True),
    ("DELETE", "/api/edge/abc",                   False, True,  True),
    # Keys — escrita restrita (id preenchido em runtime via _seed_for_matrix)
    ("POST",   "/api/keys",                       False, True,  True),
    ("DELETE", "/api/keys/{key_id}",              False, True,  True),
    # Admin — exclusivo de admin
    ("GET",    "/api/admin/users",                False, False, True),
    ("PATCH",  "/api/admin/users/1/role",         False, False, True),
    ("PATCH",  "/api/admin/users/1/active",       False, False, True),
]


def _client_for(role: str, request):
    if role == "viewer":
        return request.getfixturevalue("viewer_client")
    if role == "admin":
        return request.getfixturevalue("admin_client")
    return request.getfixturevalue("auth_client")


@pytest.mark.parametrize("method,path,viewer_ok,analyst_ok,admin_ok", _PERMISSION_MATRIX)
def test_rbac_matrix(method, path, viewer_ok, analyst_ok, admin_ok, request, app):
    """
    Para cada (método, endpoint), valida que:
    - viewer recebe 403 quando viewer_ok=False, 2xx quando True.
    - analyst recebe 2xx quando analyst_ok=True.
    - admin recebe 2xx quando admin_ok=True.
    """
    # Resolve placeholder {key_id} com o id real da key seedada.
    if "{key_id}" in path:
        path = path.replace("{key_id}", str(request.node.rbac_key_id))

    for role, expected_ok in [
        ("viewer", viewer_ok),
        ("analyst", analyst_ok),
        ("admin", admin_ok),
    ]:
        # DELETE consome o recurso: recria a key antes de cada role testada.
        if method == "DELETE" and path.startswith("/api/keys/"):
            with app.app_context():
                old = ApiKey.query.filter_by(service_name="rbac-test").first()
                if old is not None:
                    db.session.delete(old)
                    db.session.commit()
                db.session.add(ApiKey(
                    service_name="rbac-test",
                    key_value="dummy-key",
                    key_type="free",
                    is_active=True,
                ))
                db.session.commit()
                new_key = ApiKey.query.filter_by(service_name="rbac-test").first()
                path = f"/api/keys/{new_key.id}"

        client = _client_for(role, request)
        body = {}
        if method in ("POST", "PATCH"):
            if path.endswith("/role"):
                body = {"role": "analyst"}
            elif path.endswith("/active"):
                body = {"is_active": True}
            elif path == "/api/investigations":
                body = {"title": "x"}
            elif path == "/api/entity":
                body = {"type": "Domain", "value": "x.com"}
            elif path.startswith("/api/entity/"):
                # PATCH /api/entity/<id> requer `properties`
                body = {"properties": {}}
            elif path == "/api/run_transform":
                body = {
                    "transform_name": "check_fraud_email",
                    "entity_type": "Email",
                    "value": "x@x.com",
                }
            elif path == "/api/edge":
                body = {"from_id": "a", "to_id": "b", "rel_type": "R"}
            elif path == "/api/keys":
                body = {"service_name": "x", "key_value": "y"}

        resp = client.open(path, method=method, json=body or None)

        if expected_ok:
            assert resp.status_code < 400, (
                f"[{role}] {method} {path} esperava sucesso, "
                f"veio {resp.status_code} {resp.get_data(as_text=True)}"
            )
        else:
            assert resp.status_code == 403, (
                f"[{role}] {method} {path} esperava 403, "
                f"veio {resp.status_code} {resp.get_data(as_text=True)}"
            )


# ===================== Decorator @require_role =====================

def test_require_role_without_auth_returns_401(client):
    """Sem token, 401 vem antes do 403 (auth precede autorização)."""
    resp = client.get("/api/admin/users")
    assert resp.status_code == 401


def test_require_role_forbidden_message_is_neutral(viewer_client):
    """Mensagem 403 não deve vazar qual role era necessário."""
    resp = viewer_client.get("/api/admin/users")
    assert resp.status_code == 403
    body = resp.get_json()
    assert body == {"error": "forbidden"}


# ===================== /api/auth/me expõe o role =====================

def test_auth_me_returns_role(auth_client):
    resp = auth_client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.get_json()["user"]["role"] == "analyst"


def test_auth_me_for_viewer_returns_viewer(viewer_client):
    resp = viewer_client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.get_json()["user"]["role"] == "viewer"


# ===================== Admin: listar usuários =====================

def test_admin_can_list_users(admin_client):
    resp = admin_client.get("/api/admin/users")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "users" in data
    assert any(u["email"] == "admin@example.com" for u in data["users"])


def test_admin_list_includes_role_and_is_active(admin_client):
    resp = admin_client.get("/api/admin/users")
    assert resp.status_code == 200
    for u in resp.get_json()["users"]:
        assert "role" in u
        assert "is_active" in u
        # Nunca exponha o hash:
        assert "password_hash" not in u


# ===================== Admin: alterar role =====================

def _create_user(app, *, email: str, role: str = "analyst", is_active: bool = True) -> int:
    """Cria um usuário direto via ORM e devolve o id."""
    with app.app_context():
        user = User(
            email=email,
            password_hash=hash_password("test-password-123"),
            role=role,
            is_active=is_active,
        )
        db.session.add(user)
        db.session.commit()
        return user.id


def test_admin_can_change_role(admin_client, app):
    target_id = _create_user(app, email="rbac-target@example.com")

    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/role",
        json={"role": "viewer"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["user"]["role"] == "viewer"


def test_admin_cannot_demote_self(admin_client):
    with admin_client.application.app_context():
        admin_id = User.query.filter_by(email="admin@example.com").first().id

    resp = admin_client.patch(
        f"/api/admin/users/{admin_id}/role",
        json={"role": "analyst"},
    )
    assert resp.status_code == 409
    assert "cannot demote" in resp.get_json()["error"]


def test_admin_cannot_remove_last_active_admin(admin_client, app, monkeypatch):
    """
    Defesa em profundidade contra race condition: se todos os outros admins
    forem desativados entre o login e a operação, o último admin não pode
    ser rebaixado. Mockamos o contador para simular esse cenário (sem ele,
    o require_auth impede o cenário de forma natural).
    """
    with app.app_context():
        target = User(
            email="other-admin@example.com",
            password_hash=hash_password("x-password-12"),
            role="admin",
            is_active=True,
        )
        db.session.add(target)
        db.session.commit()
        target_id = target.id

    # Simula o cenário em que SÓ o 'target' é admin ativo (a função retorna
    # 1 só para o target, indicando que rebaixá-lo zeraria admins ativos).
    import openm.api.admin as admin_module
    monkeypatch.setattr(admin_module, "_count_active_admins", lambda: 1)

    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/role",
        json={"role": "analyst"},
    )
    assert resp.status_code == 409
    assert "last active admin" in resp.get_json()["error"]


def test_admin_role_change_rejects_invalid_role(admin_client, app):
    target_id = _create_user(app, email="rbac-invalid@example.com")

    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/role",
        json={"role": "god"},
    )
    assert resp.status_code == 400


def test_admin_role_change_404_for_unknown_user(admin_client):
    resp = admin_client.patch(
        "/api/admin/users/99999/role",
        json={"role": "viewer"},
    )
    assert resp.status_code == 404


# ===================== Admin: ativar/desativar =====================

def test_admin_can_deactivate_user(admin_client, app):
    target_id = _create_user(app, email="rbac-deact@example.com")

    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/active",
        json={"is_active": False},
    )
    assert resp.status_code == 200
    assert resp.get_json()["user"]["is_active"] is False


def test_admin_cannot_deactivate_self(admin_client):
    with admin_client.application.app_context():
        admin_id = User.query.filter_by(email="admin@example.com").first().id

    resp = admin_client.patch(
        f"/api/admin/users/{admin_id}/active",
        json={"is_active": False},
    )
    assert resp.status_code == 409


def test_admin_cannot_deactivate_last_active_admin(admin_client, app, monkeypatch):
    """
    Defesa em profundidade: admin tentando desativar OUTRO admin que é o
    único admin ativo é bloqueado. Mockamos o contador para simular.
    """
    with app.app_context():
        target = User(
            email="last-admin-to-deact@example.com",
            password_hash=hash_password("x-password-12"),
            role="admin",
            is_active=True,
        )
        db.session.add(target)
        db.session.commit()
        target_id = target.id

    import openm.api.admin as admin_module
    monkeypatch.setattr(admin_module, "_count_active_admins", lambda: 1)

    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/active",
        json={"is_active": False},
    )
    assert resp.status_code == 409
    assert "last active admin" in resp.get_json()["error"]


# ===================== Cenários integrados =====================

def test_viewer_can_list_investigations(viewer_client, app):
    """Cenário 'apenas leitura': viewer pode listar investigations."""
    with app.app_context():
        from openm.models.investigation import Investigation
        db.session.add(Investigation(title="x", user_id=None))
        db.session.commit()

    resp = viewer_client.get("/api/investigations")
    assert resp.status_code == 200
    assert "investigations" in resp.get_json()


def test_viewer_cannot_create_investigation(viewer_client):
    resp = viewer_client.post(
        "/api/investigations",
        json={"title": "viewer trying"},
    )
    assert resp.status_code == 403


# ===================== Admin: payload validation =====================

def test_admin_role_change_invalid_payload_returns_400(admin_client, app):
    """PATCH /role com payload faltando o campo 'role' → 400 ValidationError."""
    target_id = _create_user(app, email="rbac-bad-payload@example.com")

    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/role",
        json={},  # sem o campo obrigatório 'role'
    )
    assert resp.status_code == 400


def test_admin_active_change_invalid_payload_returns_400(admin_client, app):
    """PATCH /active com payload faltando o campo 'is_active' → 400."""
    target_id = _create_user(app, email="rbac-bad-active@example.com")

    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/active",
        json={},  # sem o campo obrigatório 'is_active'
    )
    assert resp.status_code == 400


def test_admin_active_change_404_for_unknown_user(admin_client):
    """PATCH /active em user inexistente → 404 (linha 152 do admin.py)."""
    resp = admin_client.patch(
        "/api/admin/users/99999/active",
        json={"is_active": False},
    )
    assert resp.status_code == 404


# ===================== Admin: edge cases de role inválida =====================

def test_admin_role_change_empty_string_rejected(admin_client, app):
    """PATCH /role com role string vazia → 400 (não está em VALID_ROLES)."""
    target_id = _create_user(app, email="rbac-empty-role@example.com")

    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/role",
        json={"role": ""},
    )
    assert resp.status_code == 400


# ===================== Admin: list users edge cases =====================

def test_admin_list_users_empty_when_no_users(admin_client, app):
    """Lista vazia quando não há outros usuários (apenas o admin logado)."""
    # Limpa todos os usuários exceto o admin logado.
    with app.app_context():
        admin_email = "admin@example.com"
        User.query.filter(User.email != admin_email).delete()
        db.session.commit()

    resp = admin_client.get("/api/admin/users")
    assert resp.status_code == 200
    users = resp.get_json()["users"]
    # Pelo menos o admin logado está lá.
    assert any(u["email"] == "admin@example.com" for u in users)


def test_admin_list_users_includes_newly_created(admin_client, app):
    """Usuário criado via API aparece na listagem seguinte."""
    target_id = _create_user(app, email="rbac-listing@example.com", role="viewer")

    resp = admin_client.get("/api/admin/users")
    assert resp.status_code == 200
    users = resp.get_json()["users"]
    target = next(u for u in users if u["id"] == target_id)
    assert target["role"] == "viewer"
    assert target["is_active"] is True
