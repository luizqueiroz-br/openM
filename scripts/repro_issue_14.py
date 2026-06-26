"""
Reprodução all-in-one da issue #14.

Sobe Flask debug em thread separada, roda Playwright, mata tudo.
Não precisa de processo background nem shell orchestration.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

# Reset DB
DB_PATH = "/tmp/openm-debug.db"
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)


class _FakeGraphManager:
    def get_subgraph(self, entity_id, depth=2):
        return {
            "elements": [
                {"data": {"id": "root1", "label": "example.com", "type": "Domain"}},
                {"data": {"id": "ip1", "label": "1.2.3.4", "type": "IPAddress"}},
                {"data": {"id": "ip2", "label": "5.6.7.8", "type": "IPAddress"}},
                {"data": {"id": "e1", "source": "root1", "target": "ip1", "label": "resolves_to"}},
                {"data": {"id": "e2", "source": "root1", "target": "ip2", "label": "resolves_to"}},
            ]
        }
    def get_entity(self, *a, **k): return None
    def create_relationship(self, *a, **k): return True
    def delete_relationship(self, *a, **k): return True
    def merge_entity(self, *a, **k): return None
    def is_owned_by(self, *a, **k): return True
    def update_entity_properties(self, *a, **k): return True
    def delete_entity(self, *a, **k): return True


# Monkeypatch ANTES do app
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import openm.utils.neo4j_client as _n4
import openm.api.graph as _graph
import openm.api.entities as _entities
import openm.api.transforms as _transforms

_fake = lambda *a, **k: _FakeGraphManager()
_n4.get_graph_manager = _fake
_graph.get_graph_manager = _fake
_entities.get_graph_manager = _fake
_transforms.get_graph_manager = _fake

from openm.app import create_app
from openm.config import Config
from openm.core.auth import hash_password
from openm.extensions import db
from openm.models.user import User


class DebugConfig(Config):
    TESTING = False
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"
    NEO4J_URI = "bolt://localhost:7687"
    RATELIMIT_STORAGE_URI = "memory://"
    ALLOW_REGISTRATION = True
    JWT_COOKIE_SECURE = False


app = create_app(DebugConfig)


def seed():
    with app.app_context():
        db.create_all()
        existing = User.query.filter_by(email="debug@x.com").first()
        if not existing:
            u = User(email="debug@x.com", password_hash=hash_password("debug-pass-123"), role="analyst", is_active=True)
            db.session.add(u)
            db.session.commit()


# Subir server em thread
def run_server():
    app.run(host="127.0.0.1", port=5057, debug=False, use_reloader=False, threaded=True)


# === PLAYWRIGHT ===
def run_playwright():
    from playwright.sync_api import sync_playwright

    OUT = Path("/tmp/openm-debug-shots")
    OUT.mkdir(exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_context(viewport={"width": 1400, "height": 900}).new_page()

        requests_log = []
        page.on("request", lambda r: requests_log.append(f"{r.method} {r.url}"))
        console_log = []
        page.on("console", lambda m: console_log.append(f"[{m.type}] {m.text}"))
        page.on("pageerror", lambda e: console_log.append(f"[pageerror] {e}"))

        # Limpa db primeiro
        page.goto("http://localhost:5057/login", wait_until="networkidle")
        page.fill('input[name="email"]', "debug@x.com")
        page.fill('input[name="password"]', "debug-pass-123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:5057/", timeout=10000)
        page.wait_for_timeout(500)

        # Deleta todas investigações via API (simulação: cria só uma)
        # Não tem DELETE, então criamos uma única e ignoramos o resto
        # (o backend tem dados de runs anteriores que vão aparecer — lidamos com isso)

        # Cria nossa investigação de teste
        create_resp = page.evaluate("""async () => {
            const r = await fetch('/api/investigations', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({title: 'TESTE_14', root_entity_id: 'root1'})
            });
            return {status: r.status};
        }""")
        print(f"Created: {create_resp}")

        # Reload
        page.reload(wait_until="networkidle")
        page.wait_for_timeout(1000)

        items = page.locator("#investigations-list li").all()
        print(f"Items na lista: {len(items)}")

        # Encontra o nosso (TESTE_14)
        target_li = None
        for li in items:
            if 'TESTE_14' in li.inner_text():
                target_li = li
                break

        if not target_li:
            print("❌ TESTE_14 não encontrado na lista")
            browser.close()
            return False

        data_root = target_li.get_attribute("data-root")
        print(f"Encontrou TESTE_14 com data-root={data_root!r}")

        # Click
        requests_before = len(requests_log)
        target_li.click()
        page.wait_for_timeout(3000)
        new_reqs = requests_log[requests_before:]
        print(f"Requests após click: {new_reqs}")

        cy_state = page.evaluate("""() => ({
            nodes: cy.nodes().length,
            edges: cy.edges().length,
            ids: cy.nodes().map(n => n.id()),
        })""")
        print(f"Canvas: {cy_state}")

        status_msg = page.locator("#status-msg").inner_text()
        print(f"Statusbar: {status_msg!r}")

        page.screenshot(path=str(OUT / "final.png"), full_page=True)

        # Console errors
        errs = [c for c in console_log if 'error' in c.lower() or 'pageerror' in c]
        if errs:
            print("=== ERROS NO CONSOLE ===")
            for e in errs:
                print(f"  {e}")

        browser.close()

        # Sucesso = nodes > 0 E edges > 0
        return cy_state['nodes'] > 0 and cy_state['edges'] > 0


if __name__ == "__main__":
    seed()

    # Sobe Flask em thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Espera o server ficar pronto
    import urllib.request
    for i in range(20):
        try:
            urllib.request.urlopen("http://localhost:5057/health", timeout=1)
            print(f"[server] up após {i+1}s")
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("❌ server não subiu")
        sys.exit(1)

    # Roda Playwright
    try:
        success = run_playwright()
        print()
        print("=" * 60)
        print(f"{'✅ SUCESSO' if success else '❌ FALHA'}: bug {'resolvido' if success else 'persiste'}")
        print("=" * 60)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ erro no playwright: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)