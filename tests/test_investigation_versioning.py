"""
Testes de optimistic locking para Investigation (issue #37).

Cobre:
- PUT sem If-Match (compat): 200, version++
- PUT com If-Match correto: 200, version++
- PUT com If-Match errado: 409 + current_snapshot
- Cross-user PUT com If-Match: 404 (anti-enumeração)
- Legacy (user_id=null): PUT sem/com If-Match
- If-Match inválido: 400
- Audit log 409 gravado
- Version em to_dict (POST/GET/PUT)
- DELETE não incrementa version
"""

import pytest  # noqa: F401 — reserved for future fixture usage

from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.audit_log import AuditLog
from openm.models.investigation import Investigation
from openm.models.user import User


class TestVersioning:
    """Optimistic locking via If-Match header (issue #37)."""

    @staticmethod
    def _create_investigation(app, *, user_id=None, title="Test"):
        with app.app_context():
            inv = Investigation(title=title, user_id=user_id, status="active")
            db.session.add(inv)
            db.session.commit()
            return inv.id

    @staticmethod
    def _get_version(app, inv_id):
        with app.app_context():
            return db.session.get(Investigation, inv_id).version

    def test_put_without_if_match_succeeds_and_increments_version(self, auth_client, app):
        """PUT sem If-Match mantém compatibilidade — version++ silencioso."""
        inv_id = self._create_investigation(app, title="Compat")

        # PUT sem If-Match
        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "New title"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["investigation"]["title"] == "New title"
        assert data["investigation"]["version"] == 2  # era 1, agora 2

        # Confirma no DB
        assert self._get_version(app, inv_id) == 2

    def test_put_with_correct_if_match_succeeds(self, auth_client, app):
        inv_id = self._create_investigation(app)

        # Versão inicial = 1
        assert self._get_version(app, inv_id) == 1

        # PUT com If-Match=1 (correto)
        resp1 = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "v1 edit"},
            headers={"If-Match": '"1"'},
        )
        assert resp1.status_code == 200
        assert resp1.get_json()["investigation"]["version"] == 2

        # PUT com If-Match=2 (correto novamente)
        resp2 = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "v2 edit"},
            headers={"If-Match": '"2"'},
        )
        assert resp2.status_code == 200
        assert resp2.get_json()["investigation"]["version"] == 3

    def test_put_with_wrong_if_match_returns_409(self, auth_client, app):
        inv_id = self._create_investigation(app)

        # Versão atual = 1, envia If-Match=5 (stale)
        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "stale edit"},
            headers={"If-Match": '"5"'},
        )
        assert resp.status_code == 409
        data = resp.get_json()
        assert data["error"] == "conflict"
        assert data["current_version"] == 1
        assert data["your_version"] == 5
        assert "current_snapshot" in data  # sempre presente (pode ser None)

        # Versão no DB NÃO mudou
        assert self._get_version(app, inv_id) == 1

    def test_409_includes_current_snapshot_when_present(self, auth_client, app):
        inv_id = self._create_investigation(app)

        # Salva um snapshot primeiro (PUT sem If-Match)
        r = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"graph_snapshot": {"nodes": [{"id": "a"}], "edges": []}},
        )
        assert r.status_code == 200
        # Version agora = 2

        # PUT com If-Match errado → 409 com current_snapshot do servidor
        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "stale"},
            headers={"If-Match": '"99"'},
        )
        assert resp.status_code == 409
        data = resp.get_json()
        assert data["current_version"] == 2
        assert data["current_snapshot"]["nodes"] == [{"id": "a"}]

    def test_409_does_not_increment_version(self, auth_client, app):
        inv_id = self._create_investigation(app)
        version_before = self._get_version(app, inv_id)

        # Tenta PUT com If-Match errado
        auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "stale"},
            headers={"If-Match": '"99"'},
        )

        # Version não mudou
        assert self._get_version(app, inv_id) == version_before

    def test_409_creates_audit_log(self, auth_client, app):
        inv_id = self._create_investigation(app)

        auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "stale"},
            headers={"If-Match": '"5"'},
        )

        with app.app_context():
            logs = AuditLog.query.filter_by(
                action="investigation.update",
                target_id=str(inv_id),
            ).all()
            assert len(logs) >= 1
            conflict_log = next(
                (log for log in logs if log.meta and log.meta.get("conflict")), None
            )
            assert conflict_log is not None
            assert conflict_log.meta.get("your_version") == 5
            assert conflict_log.meta.get("current_version") == 1

    def test_if_match_invalid_header_returns_400(self, auth_client, app):
        inv_id = self._create_investigation(app)

        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "x"},
            headers={"If-Match": "not-a-number"},
        )
        assert resp.status_code == 400
        assert "If-Match" in resp.get_json()["error"]

    def test_if_match_accepts_unquoted_number(self, auth_client, app):
        """Lenient: aceita If-Match sem aspas (apesar de RFC exigir)."""
        inv_id = self._create_investigation(app)

        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "lenient"},
            headers={"If-Match": "1"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["investigation"]["version"] == 2

    def test_cross_user_with_if_match_returns_404(self, auth_client, app):
        """Anti-enumeração tem prioridade sobre conflict check (issue #38)."""
        with app.app_context():
            other = User(
                email="other-ver@example.com",
                password_hash=hash_password("password"),
                role="analyst",
                is_active=True,
            )
            db.session.add(other)
            db.session.commit()

            inv = Investigation(title="Private", user_id=other.id)
            db.session.add(inv)
            db.session.commit()
            inv_id = inv.id

        # auth_client (analyst diferente) tenta PUT com If-Match
        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "stale"},
            headers={"If-Match": '"1"'},
        )
        # 404, NÃO 409 — anti-enumeração cross-user vence
        assert resp.status_code == 404

    def test_legacy_investigation_put_without_if_match(self, auth_client, app):
        """Legacy (user_id=null) aceita PUT sem If-Match (qualquer user logado)."""
        with app.app_context():
            inv = Investigation(title="Legacy", user_id=None)
            db.session.add(inv)
            db.session.commit()
            inv_id = inv.id

        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "Updated legacy"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["investigation"]["version"] == 2

    def test_legacy_investigation_put_with_correct_if_match(self, auth_client, app):
        """Legacy com If-Match correto também funciona."""
        with app.app_context():
            inv = Investigation(title="Legacy", user_id=None)
            db.session.add(inv)
            db.session.commit()
            inv_id = inv.id

        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "Updated"},
            headers={"If-Match": '"1"'},
        )
        assert resp.status_code == 200
        assert resp.get_json()["investigation"]["version"] == 2

    def test_legacy_investigation_put_with_wrong_if_match_returns_409(self, auth_client, app):
        """Legacy com If-Match errado também retorna 409 (consistência)."""
        with app.app_context():
            inv = Investigation(title="Legacy", user_id=None)
            db.session.add(inv)
            db.session.commit()
            inv_id = inv.id

        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "x"},
            headers={"If-Match": '"5"'},
        )
        assert resp.status_code == 409

    def test_version_in_to_dict(self, auth_client, app):
        """GET inclui version (e POST também, no investigation criada)."""
        inv_id = self._create_investigation(app)

        # GET inclui version=1
        get_resp = auth_client.get(f"/api/investigations/{inv_id}")
        assert get_resp.get_json()["investigation"]["version"] == 1

        # PUT incrementa
        put_resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"description": "new desc"},
        )
        assert put_resp.get_json()["investigation"]["version"] == 2

        # GET reflete a versão nova
        get_resp2 = auth_client.get(f"/api/investigations/{inv_id}")
        assert get_resp2.get_json()["investigation"]["version"] == 2

    def test_successful_put_audit_log_has_version(self, auth_client, app):
        """Audit log do PUT bem-sucedido inclui metadata.version."""
        inv_id = self._create_investigation(app)

        auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "audit test"},
        )

        with app.app_context():
            log = AuditLog.query.filter_by(
                action="investigation.update",
                target_id=str(inv_id),
            ).first()
            assert log is not None
            assert log.meta.get("version") == 2  # incremented

    def test_archive_does_not_increment_version(self, auth_client, app):
        """Archive é idempotente — NÃO mexe na versão."""
        inv_id = self._create_investigation(app)
        version_before = self._get_version(app, inv_id)

        auth_client.post(f"/api/investigations/{inv_id}/archive")

        version_after = self._get_version(app, inv_id)
        assert version_after == version_before

    def test_unarchive_does_not_increment_version(self, auth_client, app):
        """Unarchive é idempotente — NÃO mexe na versão."""
        inv_id = self._create_investigation(app)

        # Primeiro arquiva (idempotente)
        auth_client.post(f"/api/investigations/{inv_id}/archive")
        version_before = self._get_version(app, inv_id)

        # Depois desarquiva
        auth_client.post(f"/api/investigations/{inv_id}/unarchive")

        version_after = self._get_version(app, inv_id)
        assert version_after == version_before


class TestVersioningAfterDelete:
    """Combinação de versioning + DELETE (issue #35)."""

    def test_put_after_delete_returns_404(self, auth_client, app):
        inv_id = TestVersioning._create_investigation(app)

        # Delete
        del_resp = auth_client.delete(f"/api/investigations/{inv_id}")
        assert del_resp.status_code == 204

        # PUT com If-Match correto → 404 (sumiu)
        put_resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "ghost"},
            headers={"If-Match": '"1"'},
        )
        assert put_resp.status_code == 404

    def test_put_after_delete_with_if_match_mismatch_returns_404_not_409(self, auth_client, app):
        """DELETE tem prioridade — anti-enumeração cross-user + not found vence."""
        inv_id = TestVersioning._create_investigation(app)
        auth_client.delete(f"/api/investigations/{inv_id}")

        # PUT com If-Match errado (mas deletion já ocorreu)
        resp = auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"title": "ghost"},
            headers={"If-Match": '"5"'},
        )
        # 404 (não existe) — não 409 (versão errada)
        assert resp.status_code == 404
