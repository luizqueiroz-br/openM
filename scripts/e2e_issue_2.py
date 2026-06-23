"""
Smoke test E2E da issue #2: cria users + investigations direto via ORM
dentro do contexto do app, e verifica isolamento.
"""
import sys

from openm.app import create_app
from openm.config import Config
from openm.extensions import db
from openm.models.investigation import Investigation
from openm.models.user import User


class LiveConfig(Config):
    SQLALCHEMY_DATABASE_URI = "postgresql://openm:openm123@localhost:5432/openm"
    NEO4J_URI = "bolt://neo4j:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASSWORD = "openm123"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True


def main():
    app = create_app(LiveConfig)
    with app.app_context():
        # Limpa invs (mantém users pra não conflitar com hashes de teste)
        Investigation.query.delete()
        db.session.commit()
        print("✓ investigations limpas")

        # Pega os 2 users criados
        alice = User.query.filter_by(email="alice@test.com").first()
        bob = User.query.filter_by(email="bob@test.com").first()
        if not alice or not bob:
            print("✗ Users não encontrados. Crie com o DB direto antes.")
            sys.exit(1)
        print(f"✓ Users: alice={alice.id}, bob={bob.id}")

        # Cria 2 invs da Alice
        inv_a1 = Investigation(title="A1", user_id=alice.id, root_entity_id="a.com")
        inv_a2 = Investigation(title="A2", user_id=alice.id, root_entity_id="b.com")
        # Cria 1 inv do Bob
        inv_b1 = Investigation(title="B1", user_id=bob.id, root_entity_id="c.com")
        # Cria 1 legacy sem dono
        inv_legacy = Investigation(title="LEGACY", user_id=None, root_entity_id="d.com")
        db.session.add_all([inv_a1, inv_a2, inv_b1, inv_legacy])
        db.session.commit()
        print("✓ 4 investigations criadas: A1, A2, B1, LEGACY")
        print(f"  ids: a1={inv_a1.id}, a2={inv_a2.id}, b1={inv_b1.id}, legacy={inv_legacy.id}")

        # Verifica o que Alice vê
        alice_view = Investigation.query.filter(
            (Investigation.user_id == alice.id) | (Investigation.user_id.is_(None))
        ).all()
        print("\n=== Visão da Alice (deve ver A1, A2, LEGACY — 3 itens) ===")
        for inv in alice_view:
            print(f"  - id={inv.id} title={inv.title!r} user_id={inv.user_id}")

        # Verifica o que Bob vê
        bob_view = Investigation.query.filter(
            (Investigation.user_id == bob.id) | (Investigation.user_id.is_(None))
        ).all()
        print("\n=== Visão do Bob (deve ver B1, LEGACY — 2 itens) ===")
        for inv in bob_view:
            print(f"  - id={inv.id} title={inv.title!r} user_id={inv.user_id}")

        # Anti-enumeração: Bob tenta buscar inv da Alice
        sneak = Investigation.query.filter(
            Investigation.id == inv_a1.id,
            (Investigation.user_id == bob.id) | (Investigation.user_id.is_(None)),
        ).first()
        print("\n=== Bob tenta acessar inv da Alice (id=" + str(inv_a1.id) + ") ===")
        print(f"  resultado: {sneak}  ← deve ser None (404)")

        # Cascade delete: deletar Alice → invs dela somem
        print("\n=== Cascade delete: deletar Alice ===")
        alice_inv_count_before = Investigation.query.filter_by(user_id=alice.id).count()
        db.session.delete(alice)
        db.session.commit()
        alice_inv_count_after = Investigation.query.filter_by(user_id=alice.id).count()
        print(f"  Invs da Alice antes: {alice_inv_count_before}, depois: {alice_inv_count_after}")
        print("  LEGACY e B1 devem continuar existindo:")
        print(f"    LEGACY existe: {Investigation.query.get(inv_legacy.id) is not None}")
        print(f"    B1 existe: {Investigation.query.get(inv_b1.id) is not None}")


if __name__ == "__main__":
    main()
