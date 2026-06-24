"""
Smoke E2E do frontend v2 (issues #27 e #28).

Usa Playwright pra:
1. Logar no app
2. Verificar que sidebar de investigations tem filtros
3. Verificar que indicador #save-status existe
4. Criar uma investigation e verificar AutoSave.start()
5. Modificar o grafo e verificar que vira 'dirty'
6. Aguardar 2min seria muito — em vez disso, validar via:
   - PUT direto (testar backend)
   - Marcar dirty e ver indicador
"""
import sys
import time
from playwright.sync_api import sync_playwright


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        # Captura erros JS
        js_errors = []
        page.on("pageerror", lambda exc: js_errors.append(str(exc)))
        page.on("console", lambda msg: (
            js_errors.append(f"console.{msg.type}: {msg.text}")
            if msg.type == "error" else None
        ))

        # 1. Vai pro login
        page.goto("http://localhost:5000/login")
        page.wait_for_load_state("networkidle")

        # 2. Cria user direto via API (mais rápido que UI)
        # O user precisa existir antes de logar
        # Vamos usar a rota /api/auth/register mas ela pode estar desabilitada
        # Vamos checar primeiro
        reg_resp = page.request.post(
            "http://localhost:5000/api/auth/register",
            data={"email": "e2e@v2.com", "password": "e2e-pass-12345678"},
        )
        # 200 = criado, 400 = já existe
        if reg_resp.status not in (200, 201, 400):
            print(f"⚠ Register status: {reg_resp.status}")
            body = reg_resp.json() if reg_resp.headers.get("content-type", "").startswith("application/json") else reg_resp.text()
            print(f"  body: {body}")

        # 3. Loga
        login_resp = page.request.post(
            "http://localhost:5000/api/auth/login",
            data={"email": "e2e@v2.com", "password": "e2e-pass-12345678"},
        )
        assert login_resp.status == 200, f"Login falhou: {login_resp.status} {login_resp.text()}"
        print("✓ Login OK")

        # 4. Cria investigation via API
        create_resp = page.request.post(
            "http://localhost:5000/api/investigations",
            data={"title": "E2E Test v2", "root_entity_id": "test.com"},
        )
        assert create_resp.status == 201, f"Create falhou: {create_resp.status}"
        inv_id = create_resp.json()["investigation"]["id"]
        print(f"✓ Investigation criada: id={inv_id}")

        # 5. Vai pro index (com sessão)
        page.goto("http://localhost:5000/")
        page.wait_for_load_state("networkidle")
        time.sleep(1)  # JS init

        # 6. Verifica que elementos v2 existem
        checks = [
            ("#inv-search", "search input"),
            ("#inv-status-filter", "status filter"),
            ("#inv-sort", "sort select"),
            ("#save-status", "save indicator"),
        ]
        for selector, name in checks:
            el = page.query_selector(selector)
            assert el is not None, f"✗ {name} não encontrado ({selector})"
            print(f"✓ {name} presente")

        # 7. Verifica que investigation aparece na lista
        list_items = page.query_selector_all("#investigations-list li.inv-item")
        assert len(list_items) >= 1, "✗ Investigation não apareceu na lista"
        print(f"✓ {len(list_items)} investigations na lista")

        # 8. Verifica que AutoSave está no window
        autosave_exists = page.evaluate("typeof window.AutoSave === 'object'")
        assert autosave_exists, "✗ window.AutoSave não definido"
        print("✓ window.AutoSave presente")

        # 9. Simula abrir investigation (chama openInvestigation via JS)
        page.evaluate(f"App.openInvestigation({inv_id})")
        time.sleep(1.5)  # request assíncrono

        # 10. Verifica que currentInvestigationId foi setado
        current_id = page.evaluate("window.AutoSave.currentInvestigationId")
        assert current_id == inv_id, f"✗ currentInvestigationId errado: {current_id} vs {inv_id}"
        print(f"✓ AutoSave.start({inv_id}) executado")

        # 11. Verifica indicador de save (deve mostrar 'Salvo' pois acabou de abrir)
        save_text = page.text_content("#save-status")
        print(f"✓ Indicador: '{save_text}'")
        assert "Salvo" in save_text or "—" in save_text, f"Indicador estranho: {save_text}"

        # 12. Marca dirty e verifica indicador
        page.evaluate("window.AutoSave.markDirty()")
        time.sleep(0.2)
        save_text = page.text_content("#save-status")
        print(f"✓ Após markDirty: '{save_text}'")
        assert "Não salvo" in save_text, f"Indicador após dirty errado: {save_text}"

        # 13. Força tick (não espera 2min)
        page.evaluate("window.AutoSave.tick()")
        time.sleep(2)  # PUT assíncrono
        save_text = page.text_content("#save-status")
        print(f"✓ Após tick: '{save_text}'")
        assert "Salvo" in save_text, f"Indicador após tick errado: {save_text}"

        # 14. Verifica que snapshot foi salvo no backend
        get_resp = page.request.get(f"http://localhost:5000/api/investigations/{inv_id}")
        assert get_resp.status == 200
        inv = get_resp.json()["investigation"]
        assert inv["graph_snapshot"] is not None, "✗ Snapshot não foi salvo"
        assert "nodes" in inv["graph_snapshot"], "✗ Snapshot malformado"
        assert inv["last_auto_save_at"] is not None, "✗ last_auto_save_at não setado"
        print(f"✓ Snapshot persistido: {len(inv['graph_snapshot']['nodes'])} nós")

        # 15. Testa arquivamento
        arch_resp = page.request.post(f"http://localhost:5000/api/investigations/{inv_id}/archive")
        assert arch_resp.status == 200
        print("✓ Archive endpoint OK")

        # 16. Verifica filtração
        # Default (?status=active) NÃO deve mostrar a inv arquivada
        list_resp = page.request.get("http://localhost:5000/api/investigations")
        active_items = list_resp.json()["investigations"]
        assert all(i["status"] == "active" for i in active_items), \
            "Default list não filtra archived"
        assert not any(i["id"] == inv_id for i in active_items), \
            "Inv arquivada apareceu em ?status=active"
        # Com ?status=all, deve aparecer
        list_resp_all = page.request.get("http://localhost:5000/api/investigations?status=all")
        all_items = list_resp_all.json()["investigations"]
        assert any(i["id"] == inv_id and i["status"] == "archived" for i in all_items), \
            "Inv arquivada não apareceu em ?status=all"
        print(f"✓ Archive filtra corretamente: {len(active_items)} active default, "
              f"{len(all_items)} total com ?status=all")

        # 17. Verifica erros JS
        # Filtra erros conhecidos (CSRF, etc)
        critical_errors = [e for e in js_errors if "favicon" not in e.lower()]
        if critical_errors:
            print(f"\n⚠ {len(critical_errors)} erros JS capturados:")
            for e in critical_errors[:5]:
                print(f"  - {e}")
        else:
            print("✓ Zero erros JS")

        # Cleanup
        page.request.post(f"http://localhost:5000/api/investigations/{inv_id}/unarchive")

        browser.close()
        print("\n🎉 TODOS OS SMOKE TESTS PASSARAM")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(f"\n✗ FALHOU: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 ERRO INESPERADO: {type(e).__name__}: {e}")
        sys.exit(2)
