"""
Reprodução all-in-one da issue #14 no ambiente REAL (Postgres + Neo4j).

Diferente do scripts/repro_issue_14.py (que usa mock), este conecta no
Flask real rodando em :5000 e usa dados reais do banco.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path("/tmp/openm-real-shots")
OUT.mkdir(exist_ok=True)


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_context(viewport={"width": 1400, "height": 900}).new_page()

        requests_log = []
        page.on("request", lambda r: requests_log.append({
            "method": r.method, "url": r.url,
            "post_data": r.post_data,
        }))

        console_log = []
        page.on("console", lambda m: console_log.append({
            "type": m.type, "text": m.text,
        }))
        page.on("pageerror", lambda e: console_log.append({
            "type": "pageerror", "text": str(e),
        }))

        responses = []
        page.on("response", lambda r: responses.append({
            "status": r.status, "url": r.url,
        }))

        # 1. LOGIN
        print("=" * 60)
        print("[1] LOGIN")
        print("=" * 60)
        page.goto("http://localhost:5000/login", wait_until="networkidle")
        page.fill('input[name="email"]', "debug@x.com")
        page.fill('input[name="password"]', "debug-pass-123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:5000/", timeout=10000)
        page.wait_for_timeout(2000)
        page.screenshot(path=str(OUT / "01-home.png"), full_page=True)
        print("✓ login OK")

        # Lista investigações
        print()
        print("=" * 60)
        print("[2] LISTA DE INVESTIGAÇÕES (após reload)")
        print("=" * 60)
        page.reload(wait_until="networkidle")
        page.wait_for_timeout(2000)
        items = page.locator("#investigations-list li").all()
        print(f"Itens: {len(items)}")
        for i, item in enumerate(items[:8]):
            txt = item.inner_text().strip().replace("\n", " | ")
            data_root = item.get_attribute("data-root")
            data_id = item.get_attribute("data-id")
            print(f"  [{i}] id={data_id} root={data_root!r} text={txt!r}")

        # 3. TESTAR 3 CENÁRIOS
        results = []

        # Cenário A: investigar COM root (deve funcionar)
        print()
        print("=" * 60)
        print("[3A] CLICK em investigação COM root_entity_id")
        print("=" * 60)
        target_with_root = None
        for li in items:
            if li.get_attribute("data-root"):  # não-vazio
                target_with_root = li
                break
        if not target_with_root:
            print("❌ nenhuma investigação COM root_entity_id — vou criar uma")
            page.evaluate("""async () => {
                // Cria uma entity + investigation com root
                await fetch('/api/entity', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({type: 'Domain', value: 'test-root.com'})
                });
                await fetch('/api/investigations', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({title: 'WITH_ROOT', root_entity_id: 'test-root.com'})
                });
            }""")
            page.reload(wait_until="networkidle")
            page.wait_for_timeout(1000)
            items = page.locator("#investigations-list li").all()
            for li in items:
                if li.inner_text().startswith("WITH_ROOT"):
                    target_with_root = li
                    break

        if target_with_root:
            requests_before = len(requests_log)
            console_before = len(console_log)
            target_with_root.click()
            page.wait_for_timeout(3000)
            page.screenshot(path=str(OUT / "02-click-with-root.png"), full_page=True)

            cy_state = page.evaluate("""() => ({
                nodes: cy.nodes().length,
                edges: cy.edges().length,
                ids: cy.nodes().map(n => n.id()),
            })""")
            status = page.locator("#status-msg").inner_text()
            new_reqs = requests_log[requests_before:]
            new_errs = [c for c in console_log[console_before:] if c['type'] in ('error', 'pageerror')]
            print(f"  Requests: {new_reqs}")
            print(f"  Canvas: {cy_state}")
            print(f"  Statusbar: {status!r}")
            print(f"  Console errors: {new_errs}")
            results.append(("WITH_ROOT", cy_state['nodes'] > 0, status))
        else:
            print("❌ não foi possível criar investigação COM root")
            results.append(("WITH_ROOT", False, "não criou"))

        # Cenário B: investigar SEM root (a maioria do user)
        print()
        print("=" * 60)
        print("[3B] CLICK em investigação SEM root_entity_id")
        print("=" * 60)
        page.reload(wait_until="networkidle")
        page.wait_for_timeout(1500)
        items = page.locator("#investigations-list li").all()
        target_without_root = None
        for li in items:
            if not li.get_attribute("data-root"):
                target_without_root = li
                break

        if target_without_root:
            requests_before = len(requests_log)
            console_before = len(console_log)
            target_without_root.click()
            page.wait_for_timeout(2000)
            page.screenshot(path=str(OUT / "03-click-without-root.png"), full_page=True)

            cy_state = page.evaluate("""() => ({
                nodes: cy.nodes().length,
                edges: cy.edges().length,
            })""")
            status = page.locator("#status-msg").inner_text()
            new_reqs = requests_log[requests_before:]
            print(f"  Requests: {new_reqs}")
            print(f"  Canvas: {cy_state}")
            print(f"  Statusbar: {status!r}")
            results.append(("WITHOUT_ROOT", cy_state['nodes'] == 0, status))
        else:
            print("(nenhuma investigação SEM root encontrada — skip)")
            results.append(("WITHOUT_ROOT", None, "não encontrado"))

        # Salva logs
        (OUT / "requests.json").write_text(json.dumps(requests_log[-30:], indent=2))
        (OUT / "console.json").write_text(json.dumps(console_log, indent=2))
        (OUT / "responses.json").write_text(json.dumps(responses[-30:], indent=2))

        # Resumo
        print()
        print("=" * 60)
        print("RESUMO")
        print("=" * 60)
        for name, ok, status in results:
            print(f"  [{name}] {'✅' if ok else '❌'} {status!r}")

        browser.close()


if __name__ == "__main__":
    main()