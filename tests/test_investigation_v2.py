"""
Testes do Investigation model v2 (issue #25).

Cobre:
- Novos campos: status, archived_at, graph_snapshot, last_auto_save_at
- Métodos archive() / unarchive()
- to_dict() com novos campos
- Default status='active' pra investigations legadas (graph_snapshot=None)
"""

from __future__ import annotations

import pytest

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.investigation import Investigation
from openm.models.user import User


class V2TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


@pytest.fixture
def v2_app():
    app = create_app(V2TestConfig)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def alice(v2_app):
    with v2_app.app_context():
        u = User(
            email="alice@v2.com",
            password_hash=hash_password("alice-pass-123"),
            role="analyst",
            is_active=True,
        )
        db.session.add(u)
        db.session.commit()
        return u.id


# ============ Schema / defaults ============

class TestInvestigationV2Defaults:
    def test_new_investigation_defaults_to_active(self, v2_app, alice):
        with v2_app.app_context():
            inv = Investigation(title="X", user_id=alice)
            db.session.add(inv)
            db.session.commit()
            assert inv.status == "active"
            assert inv.archived_at is None
            assert inv.graph_snapshot is None
            assert inv.last_auto_save_at is None

    def test_legacy_investigation_without_user_id_is_active(self, v2_app):
        """Investigations legadas (user_id=null) recebem status='active' por default."""
        with v2_app.app_context():
            inv = Investigation(title="Legacy", user_id=None)
            db.session.add(inv)
            db.session.commit()
            assert inv.status == "active"

    def test_status_index_exists(self, v2_app, alice):
        """Verifica que existe o índice em status (criado pela migration)."""
        with v2_app.app_context():
            from sqlalchemy import inspect
            inv = InspectionFactory(alice)
            db.session.add(inv)
            db.session.commit()
            indexes = inspect(db.engine).get_indexes("investigations")
            index_names = {ix["name"] for ix in indexes}
            assert "ix_investigations_status" in index_names


# ============ Archive / Unarchive ============

class TestArchiveUnarchive:
    def test_archive_sets_status_and_timestamp(self, v2_app, alice):
        with v2_app.app_context():
            inv = Investigation(title="A", user_id=alice)
            db.session.add(inv)
            db.session.commit()

            inv.archive()
            db.session.commit()

            assert inv.status == "archived"
            assert inv.archived_at is not None

    def test_unarchive_resets_status_and_clears_timestamp(self, v2_app, alice):
        with v2_app.app_context():
            inv = Investigation(title="A", user_id=alice, status="archived")
            from datetime import datetime, timezone
            inv.archived_at = datetime.now(timezone.utc)
            db.session.add(inv)
            db.session.commit()

            inv.unarchive()
            db.session.commit()

            assert inv.status == "active"
            assert inv.archived_at is None

    def test_to_dict_includes_v2_fields(self, v2_app, alice):
        with v2_app.app_context():
            snapshot = {"nodes": [{"data": {"id": "n1"}}], "edges": []}
            inv = Investigation(
                title="A",
                user_id=alice,
                graph_snapshot=snapshot,
            )
            db.session.add(inv)
            db.session.commit()

            d = inv.to_dict()
            assert d["status"] == "active"
            assert d["archived_at"] is None
            assert d["graph_snapshot"] == snapshot
            assert d["last_auto_save_at"] is None
            # Campos legados continuam
            assert d["title"] == "A"
            assert d["user_id"] == alice


# ============ Helpers ============

def InspectionFactory(user_id):
    """Helper — equivalente a Investigation(...)."""
    return Investigation(title="Helper", user_id=user_id)
