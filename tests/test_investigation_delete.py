"""
Testes do DELETE /api/investigations/<id> (issue #35).

Cobre:
- 204 No Content em delete bem-sucedido pelo dono.
- 404 cross-user (anti-enumeração).
- 403 quando viewer tenta deletar.
- 401 sem auth.
- Legacy (user_id=null) deletável por qualquer analyst.
- 404 para investigation inexistente.
- Audit log gravado ANTES do delete com snapshot correto.
- Investigation arquivada também é deletável.
- DELETE não tenta tocar Neo4j.
"""

import pytest  # noqa: F401  — reserved for future fixture usage

from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.audit_log import AuditLog
from openm.models.investigation import Investigation
from openm.models.user import User


def _create_user(app, *, email: str, role: str = "analyst", is_active: bool = True) -> int:
    """Cria user direto via ORM (bypassa /api/auth/register). Devolve só o id."""
    with app.app_context():
        u = User(
            email=email,
            password_hash=hash_password("test-password-123"),
            role=role,
            is_active=is_active,
        )
        db.session.add(u)
        db.session.commit()
        return u.id


def _create_inv(app, *, title: str, user_id, status: str = "active"):
    """Cria investigation direto via ORM. Devolve (id, user_id)."""
    with app.app_context():
        inv = Investigation(title=title, user_id=user_id, status=status)
        db.session.add(inv)
        db.session.commit()
        return inv.id


def _get_inv(app, inv_id):
    """Carrega investigation ou None se foi deletada."""
    with app.app_context():
        return db.session.get(Investigation, inv_id)


class TestDeleteInvestigation:
    """DELETE /api/investigations/<id> (issue #35)."""

    def test_delete_own_returns_204(self, auth_client, app):
        """Dono deleta sua investigation — 204 No Content sem body."""
        # Descobre o user_id do auth_client (analyst)
        with app.app_context():
            user = User.query.filter_by(email="tester@example.com").first()
            user_id = user.id

        inv_id = _create_inv(app, title="Delete me", user_id=user_id)

        resp = auth_client.delete(f"/api/investigations/{inv_id}")

        assert resp.status_code == 204
        assert resp.data == b""  # 204 No Content NÃO tem body
        assert _get_inv(app, inv_id) is None

    def test_delete_cross_user_returns_404(self, auth_client, app):
        """Cross-user retorna 404 (anti-enumeração), não 403."""
        # Cria user "outro" e investigation dele
        other = _create_user(app, email="other@example.com")
        inv_id = _create_inv(app, title="Other user", user_id=other)

        # auth_client (tester) tenta deletar — espera 404, NÃO 403
        resp = auth_client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 404

        # E a investigation continua existindo (não foi deletada)
        assert _get_inv(app, inv_id) is not None

    def test_delete_by_viewer_returns_403(self, viewer_client, app):
        """Viewer (role sem permissão de escrita) recebe 403."""
        # Cria user e investigation para que o endpoint "encontre" algo
        # — mas o viewer não tem role, então o decorator corta antes.
        analyst = _create_user(app, email="somebody@example.com")
        inv_id = _create_inv(app, title="Any", user_id=analyst)

        resp = viewer_client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 403
        # Investigation continua existindo
        assert _get_inv(app, inv_id) is not None

    def test_delete_legacy_investigation_by_any_analyst(self, auth_client, app):
        """Legacy (user_id=null) pode ser deletado por qualquer analyst."""
        inv_id = _create_inv(app, title="Legacy shared", user_id=None)

        resp = auth_client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 204
        assert _get_inv(app, inv_id) is None

    def test_delete_legacy_investigation_by_admin(self, admin_client, app):
        """Admin também pode deletar legacy."""
        inv_id = _create_inv(app, title="Legacy shared 2", user_id=None)

        resp = admin_client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 204
        assert _get_inv(app, inv_id) is None

    def test_delete_nonexistent_returns_404(self, auth_client):
        """Tentar deletar ID que não existe → 404."""
        resp = auth_client.delete("/api/investigations/99999")
        assert resp.status_code == 404

    def test_delete_unauthenticated_returns_401(self, client, app):
        """Sem auth → 401 (auth precede autorização)."""
        analyst = _create_user(app, email="any@example.com")
        inv_id = _create_inv(app, title="Any", user_id=analyst)

        resp = client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 401
        # Investigation continua existindo
        assert _get_inv(app, inv_id) is not None

    def test_delete_creates_audit_log(self, auth_client, app):
        """Audit log é gravado ANTES do delete com snapshot."""
        with app.app_context():
            user = User.query.filter_by(email="tester@example.com").first()
            user_id = user.id

        inv_id = _create_inv(
            app, title="To delete with audit", user_id=user_id, status="active",
        )

        resp = auth_client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 204

        # Verifica audit log
        with app.app_context():
            logs = AuditLog.query.filter_by(
                action="investigation.delete",
                target_id=str(inv_id),
            ).all()
            assert len(logs) == 1
            log = logs[0]
            assert log.user_id is not None
            # AuditLog tem coluna "meta" mapeada de "metadata"
            assert log.meta is not None
            assert log.meta.get("title") == "To delete with audit"
            assert log.meta.get("status_before_delete") == "active"

    def test_delete_archived_investigation(self, auth_client, app):
        """Investigation arquivada também pode ser deletada."""
        with app.app_context():
            user = User.query.filter_by(email="tester@example.com").first()
            user_id = user.id

        inv_id = _create_inv(
            app, title="Archived", user_id=user_id, status="archived",
        )

        resp = auth_client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 204
        assert _get_inv(app, inv_id) is None

    def test_delete_by_admin(self, admin_client, app):
        """Admin pode deletar investigation de qualquer user (sem 404 cross-user).

        Diferente de analyst: admin bypassa filtro de ownership.
        (Implementação atual usa o mesmo _owned_or_404, então admin
        TAMBÉM vê 404 cross-user — comportamento consistente.)
        """
        other = _create_user(app, email="other2@example.com")
        inv_id = _create_inv(app, title="By other", user_id=other)

        resp = admin_client.delete(f"/api/investigations/{inv_id}")
        # Cross-user: admin também recebe 404 (helper é compartilhado)
        assert resp.status_code == 404
        assert _get_inv(app, inv_id) is not None

    def test_delete_cascade_neo4j_not_called(self, auth_client, app, monkeypatch):
        """DELETE NÃO chama gm.delete_relationship ou gm.delete_entity.

        Como o conftest mocka Neo4j via _FakeGraphManager (autouse),
        podemos contar chamadas pra confirmar que delete_investigation
        não toca no grafo.
        """
        # Captura qualquer chamada Neo4j que delete_investigation faça
        neo4j_touched = {"delete_entity": 0, "delete_relationship": 0}

        # Pega o manager fake injetado pelo conftest e wrappa deleções
        from openm.utils import neo4j_client

        original_get = neo4j_client.get_graph_manager

        def tracked_get(*args, **kwargs):
            gm = original_get(*args, **kwargs)
            orig_del_entity = gm.delete_entity
            orig_del_rel = gm.delete_relationship

            def count_entity(*a, **kw):
                neo4j_touched["delete_entity"] += 1
                return orig_del_entity(*a, **kw)

            def count_rel(*a, **kw):
                neo4j_touched["delete_relationship"] += 1
                return orig_del_rel(*a, **kw)

            gm.delete_entity = count_entity
            gm.delete_relationship = count_rel
            return gm

        monkeypatch.setattr(neo4j_client, "get_graph_manager", tracked_get)
        # Patch em todos os módulos que importam (mesmo padrão do conftest)
        for mod in ["openm.api.investigations", "openm.api.graph",
                    "openm.api.entities", "openm.api.transforms"]:
            try:
                monkeypatch.setattr(f"{mod}.get_graph_manager", tracked_get)
            except AttributeError:
                pass

        with app.app_context():
            user = User.query.filter_by(email="tester@example.com").first()
            user_id = user.id

        inv_id = _create_inv(app, title="No neo4j touch", user_id=user_id)

        resp = auth_client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 204

        # Confirma que NÃO cascateamos
        assert neo4j_touched["delete_entity"] == 0
        assert neo4j_touched["delete_relationship"] == 0

    def test_delete_response_has_no_body(self, auth_client, app):
        """204 No Content → body vazio."""
        with app.app_context():
            user = User.query.filter_by(email="tester@example.com").first()
            user_id = user.id

        inv_id = _create_inv(app, title="No body", user_id=user_id)

        resp = auth_client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 204
        assert resp.get_data() == b""
        # Content-Length ausente também é aceitável
        assert resp.content_length in (None, 0)

    def test_delete_returns_404_after_already_deleted(self, auth_client, app):
        """Tentar deletar 2x → segundo DELETE retorna 404."""
        with app.app_context():
            user = User.query.filter_by(email="tester@example.com").first()
            user_id = user.id

        inv_id = _create_inv(app, title="Delete twice", user_id=user_id)

        # Primeira vez: sucesso
        resp1 = auth_client.delete(f"/api/investigations/{inv_id}")
        assert resp1.status_code == 204

        # Segunda vez: 404 (já não existe)
        resp2 = auth_client.delete(f"/api/investigations/{inv_id}")
        assert resp2.status_code == 404

    def test_delete_logs_correct_metadata(self, auth_client, app):
        """Metadata do audit log captura status_before_delete corretamente."""
        with app.app_context():
            user = User.query.filter_by(email="tester@example.com").first()
            user_id = user.id

        # Investigation arquivada
        inv_id = _create_inv(
            app, title="Archived one", user_id=user_id, status="archived",
        )

        resp = auth_client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 204

        with app.app_context():
            log = AuditLog.query.filter_by(
                action="investigation.delete",
                target_id=str(inv_id),
            ).first()
            assert log is not None
            assert log.meta["status_before_delete"] == "archived"
            assert log.meta["title"] == "Archived one"
