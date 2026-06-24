"""
Testes para a UI de admin (issue #42) — feature de frontend.

Valida indiretamente a integração entre o backend (issue #3) e o
frontend (este PR), garantindo:

- O blueprint /api/admin/* está registrado e operacional.
- Os 3 endpoints necessários para a UI existem:
  - GET    /api/admin/users
  - PATCH  /api/admin/users/<id>/role
  - PATCH  /api/admin/users/<id>/active
- O template index.html contém a seção "Administração" escondida
  via data-roles="admin".
- O JS da UI está registrado e usa os endpoints corretos.
- A API client expõe listUsers/setUserRole/setUserActive.
"""

from pathlib import Path

from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User


# ===================== Helpers =====================

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "openm" / "frontend"


def _read_file(path: Path) -> str:
    assert path.exists(), f"Arquivo esperado não encontrado: {path}"
    return path.read_text()


# ===================== Backend: endpoints =====================

def test_admin_endpoints_exist(admin_client):
    """Os 3 endpoints do admin blueprint estão registrados."""
    resp = admin_client.get("/api/admin/users")
    assert resp.status_code == 200

    resp = admin_client.patch(
        "/api/admin/users/1/role",
        json={"role": "viewer"},
    )
    # 200 (mudou) ou 409 (auto-modificação) — mas nunca 404 de rota.
    assert resp.status_code != 404

    resp = admin_client.patch(
        "/api/admin/users/1/active",
        json={"is_active": False},
    )
    assert resp.status_code != 404


def test_admin_section_hidden_from_non_admin(viewer_client, auth_client):
    """viewer e analyst não veem a seção (a UI esconde via data-roles)."""
    resp = viewer_client.get("/api/admin/users")
    assert resp.status_code == 403

    resp = auth_client.get("/api/admin/users")
    assert resp.status_code == 403


def test_admin_list_returns_users_with_required_fields(admin_client, app):
    """A lista de usuários retorna campos que a UI precisa (id, email,
    role, is_active, created_at)."""
    with app.app_context():
        User.query.filter(User.email != "admin@example.com").delete()
        db.session.commit()
        u = User(
            email="ui-target@example.com",
            password_hash=hash_password("senha-forte-123"),
            role="analyst",
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()

    resp = admin_client.get("/api/admin/users")
    assert resp.status_code == 200
    users = resp.get_json()["users"]
    target = next((u for u in users if u["email"] == "ui-target@example.com"), None)
    assert target is not None
    # Campos esperados pela UI:
    for field in ("id", "email", "role", "is_active", "created_at"):
        assert field in target, f"campo '{field}' faltando na resposta"


# ===================== Frontend: HTML =====================

def test_index_template_has_admin_section():
    """index.html contém a sidebar-section Administração."""
    html = _read_file(FRONTEND_DIR / "templates" / "index.html")
    assert 'id="admin-section"' in html
    assert 'data-roles="admin"' in html
    assert "Administração" in html


def test_index_template_registers_admin_js():
    """index.html carrega o js/admin.js."""
    html = _read_file(FRONTEND_DIR / "templates" / "index.html")
    assert "js/admin.js" in html


def test_admin_section_has_required_elements():
    """A seção admin contém os elementos esperados pela UI."""
    html = _read_file(FRONTEND_DIR / "templates" / "index.html")
    # Botão de refresh, área de erro, tabela com cabeçalho, tbody vazio.
    assert 'id="admin-refresh"' in html
    assert 'id="admin-error"' in html
    assert 'id="admin-users-tbody"' in html
    assert "<th>Email</th>" in html
    assert "<th>Role</th>" in html
    assert "<th>Ações</th>" in html


# ===================== Frontend: api.js =====================

def test_api_js_exposes_admin_methods():
    """js/api.js expõe listUsers, setUserRole, setUserActive."""
    api_js = _read_file(FRONTEND_DIR / "static" / "js" / "api.js")
    assert "listUsers:" in api_js
    assert "setUserRole:" in api_js
    assert "setUserActive:" in api_js

    # Verifica que cada método aponta para o endpoint correto.
    assert "/admin/users" in api_js
    assert "/admin/users/${userId}/role" in api_js
    assert "/admin/users/${userId}/active" in api_js


# ===================== Frontend: admin.js =====================

def test_admin_js_calls_endpoints():
    """js/admin.js consome OpenMAPI.listUsers/setUserRole/setUserActive."""
    admin_js = _read_file(FRONTEND_DIR / "static" / "js" / "admin.js")
    assert "OpenMAPI.listUsers" in admin_js
    assert "OpenMAPI.setUserRole" in admin_js
    assert "OpenMAPI.setUserActive" in admin_js


def test_admin_js_uses_confirm_for_destructive_actions():
    """A UI confirma antes de rebaixar/desativar."""
    admin_js = _read_file(FRONTEND_DIR / "static" / "js" / "admin.js")
    # window.confirm deve aparecer nas duas funções destrutivas.
    assert "confirm(" in admin_js
    # Defesas em camadas: desabilita controles no próprio usuário.
    assert "isSelf" in admin_js
    assert "disabled" in admin_js


def test_admin_js_renders_error_inline():
    """Erros do backend são exibidos em elemento #admin-error."""
    admin_js = _read_file(FRONTEND_DIR / "static" / "js" / "admin.js")
    assert "admin-error" in admin_js
    assert "setError" in admin_js


def test_admin_js_handles_self_protection():
    """UI desabilita controles quando user.id === currentUserId."""
    admin_js = _read_file(FRONTEND_DIR / "static" / "js" / "admin.js")
    # O renderRow deve receber currentUserId e marcar isSelf.
    assert "currentUserId" in admin_js
    assert "renderRow(user, currentUserId)" in admin_js or \
           "renderRow(u, currentUserId)" in admin_js


# ===================== Frontend: CSS =====================

def test_style_css_has_admin_section_styles():
    """style.css contém regras para #admin-section e tabela."""
    css = _read_file(FRONTEND_DIR / "static" / "css" / "style.css")
    assert "#admin-section" in css
    assert ".admin-table" in css
    # admin-error usa seletor de ID no CSS (id="admin-error" no HTML).
    assert "#admin-error" in css


# ===================== Integração frontend ↔ backend =====================

def test_admin_can_promote_then_demote_via_api(admin_client, app):
    """Fluxo completo que a UI executa: promover → reverter."""
    with app.app_context():
        u = User(
            email="roundtrip@example.com",
            password_hash=hash_password("senha-forte-123"),
            role="analyst",
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        target_id = u.id

    # Promote
    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/role",
        json={"role": "admin"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["user"]["role"] == "admin"

    # Demote de volta
    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/role",
        json={"role": "analyst"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["user"]["role"] == "analyst"


def test_admin_toggle_active_roundtrip(admin_client, app):
    """Ativa/desativa em sequência — a UI faz isso."""
    with app.app_context():
        u = User(
            email="toggle@example.com",
            password_hash=hash_password("senha-forte-123"),
            role="analyst",
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        target_id = u.id

    # Desativar
    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/active",
        json={"is_active": False},
    )
    assert resp.status_code == 200
    assert resp.get_json()["user"]["is_active"] is False

    # Reativar
    resp = admin_client.patch(
        f"/api/admin/users/{target_id}/active",
        json={"is_active": True},
    )
    assert resp.status_code == 200
    assert resp.get_json()["user"]["is_active"] is True


def test_admin_self_modification_blocked_with_helpful_error(admin_client):
    """UI mostra erro do backend quando admin tenta se auto-modificar."""
    with admin_client.application.app_context():
        admin_id = User.query.filter_by(email="admin@example.com").first().id

    # Tentar rebaixar a si mesmo.
    resp = admin_client.patch(
        f"/api/admin/users/{admin_id}/role",
        json={"role": "analyst"},
    )
    assert resp.status_code == 409
    error_msg = resp.get_json()["error"]
    # A mensagem deve ser informativa (UI exibe isso em #admin-error).
    assert "demote" in error_msg.lower() or "themselves" in error_msg.lower()
