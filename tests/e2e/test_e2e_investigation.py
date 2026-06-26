"""
Testes E2E do flow investigation (issue #18).

Valida o ciclo completo de uma investigação contra backend real:
Postgres real + Neo4j real (não mockados).

Cobre:
- Login → criar entidades → criar edges → criar investigation
- PUT snapshot → GET retorna snapshot correto (formato {nodes, edges})
- DELETE investigation (issue #35) → entidades Neo4j permanecem
- Encoding de caracteres especiais (acentos, emojis)
- Reabrir investigation arquivada
- Anti-enumeração cross-user contra Neo4j real
"""

import pytest


pytestmark = pytest.mark.e2e


class TestE2EInvestigationFlow:
    """Flow completo: login → entities → investigation → reload → delete."""

    def test_login_e2e(self, e2e_auth_client):
        """Cliente autenticado consegue fazer requests contra backend real."""
        resp = e2e_auth_client.get("/api/auth/me")
        assert resp.status_code == 200
        # /api/auth/me retorna {"user": {id, email, role, is_active, created_at}}
        body = resp.get_json()
        assert body["user"]["email"] == "e2e-analyst@example.com"
        assert body["user"]["role"] == "analyst"

    def test_create_domain_entity(self, e2e_auth_client):
        """POST /api/entity cria um Domain no Neo4j real."""
        resp = e2e_auth_client.post(
            "/api/entity",
            json={"type": "Domain", "value": "example.com"},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["entity"]["type"] == "Domain"
        assert data["entity"]["value"] == "example.com"
        assert "id" in data["entity"]

    def test_create_multiple_entities_and_subgraph(self, e2e_auth_client):
        """Cria Domain + 2 IPs + edges, depois GET /api/subgraph retorna {nodes, edges}."""
        # 1 Domain
        domain_resp = e2e_auth_client.post(
            "/api/entity",
            json={"type": "Domain", "value": "example.com"},
        )
        assert domain_resp.status_code == 201
        domain_id = domain_resp.get_json()["entity"]["id"]

        # 2 IPs
        ip1_resp = e2e_auth_client.post(
            "/api/entity",
            json={"type": "IPAddress", "value": "1.1.1.1"},
        )
        ip2_resp = e2e_auth_client.post(
            "/api/entity",
            json={"type": "IPAddress", "value": "2.2.2.2"},
        )
        assert ip1_resp.status_code == 201
        assert ip2_resp.status_code == 201
        ip1_id = ip1_resp.get_json()["entity"]["id"]
        ip2_id = ip2_resp.get_json()["entity"]["id"]

        # 2 edges RESOLVES_TO
        e1 = e2e_auth_client.post(
            "/api/edge",
            json={"from_id": domain_id, "to_id": ip1_id, "rel_type": "RESOLVES_TO"},
        )
        e2 = e2e_auth_client.post(
            "/api/edge",
            json={"from_id": domain_id, "to_id": ip2_id, "rel_type": "RESOLVES_TO"},
        )
        assert e1.status_code == 201, f"Edge 1 falhou: {e1.get_json()}"
        assert e2.status_code == 201

        # GET /api/subgraph/<domain_id>
        sub = e2e_auth_client.get(f"/api/subgraph/{domain_id}?depth=2")
        assert sub.status_code == 200
        data = sub.get_json()
        # Contrato estável (issue #19): {nodes, edges}
        assert "nodes" in data
        assert "edges" in data
        assert "elements" not in data  # não legacy
        assert len(data["nodes"]) == 3  # domain + 2 IPs
        assert len(data["edges"]) == 2

    def test_investigation_crud_lifecycle(self, e2e_auth_client):
        """Cria investigation → PUT snapshot → GET → DELETE → confirma Neo4j intacto."""
        # Cria entities
        d = e2e_auth_client.post(
            "/api/entity",
            json={"type": "Domain", "value": "lifecycle.com"},
        ).get_json()["entity"]
        i = e2e_auth_client.post(
            "/api/entity",
            json={"type": "IPAddress", "value": "10.0.0.1"},
        ).get_json()["entity"]
        e2e_auth_client.post(
            "/api/edge",
            json={"from_id": d["id"], "to_id": i["id"], "rel_type": "RESOLVES_TO"},
        )

        # GET subgraph para montar o snapshot
        sub = e2e_auth_client.get(f"/api/subgraph/{d['id']}?depth=2").get_json()
        snapshot = {"nodes": sub["nodes"], "edges": sub["edges"]}

        # POST /api/investigations
        inv_resp = e2e_auth_client.post(
            "/api/investigations",
            json={"title": "Lifecycle test", "root_entity_id": d["value"]},
        )
        assert inv_resp.status_code == 201
        inv_id = inv_resp.get_json()["investigation"]["id"]

        # PUT snapshot
        put_resp = e2e_auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"graph_snapshot": snapshot},
        )
        assert put_resp.status_code == 200

        # GET investigation retorna snapshot (issue #19 contrato)
        get_resp = e2e_auth_client.get(f"/api/investigations/{inv_id}")
        assert get_resp.status_code == 200
        inv = get_resp.get_json()["investigation"]
        assert inv["title"] == "Lifecycle test"
        assert inv["graph_snapshot"] is not None
        assert inv["graph_snapshot"]["nodes"] == snapshot["nodes"]
        assert inv["graph_snapshot"]["edges"] == snapshot["edges"]

        # DELETE investigation (issue #35) → 204 No Content
        del_resp = e2e_auth_client.delete(f"/api/investigations/{inv_id}")
        assert del_resp.status_code == 204

        # GET após DELETE → 404
        get_after = e2e_auth_client.get(f"/api/investigations/{inv_id}")
        assert get_after.status_code == 404

        # MAS entidades Neo4j permanecem (ownership é por user_id)
        sub_after = e2e_auth_client.get(f"/api/subgraph/{d['id']}?depth=2")
        assert sub_after.status_code == 200
        nodes_after = sub_after.get_json()["nodes"]
        # 2 nodes (domain + IP) — não cascateou
        assert len(nodes_after) == 2
        ids = {n["data"]["id"] for n in nodes_after}
        assert d["id"] in ids
        assert i["id"] in ids

    def test_special_characters_encoding(self, e2e_auth_client):
        """Domínio com acentos e emojis sobrevive ao round-trip Neo4j.

        Cria duas entidades + uma edge para garantir que o subgraph
        encontre a primeira (o pattern Cypher ``-[r*1..depth]-`` exige
        pelo menos 1 edge no caminho).
        """
        # 2 entidades + 1 edge para que o subgraph encontre o caminho
        d = e2e_auth_client.post(
            "/api/entity",
            json={
                "type": "Domain",
                "value": "acentos.com",
                "description": "ação中文🚀",
            },
        ).get_json()["entity"]
        i = e2e_auth_client.post(
            "/api/entity",
            json={"type": "IPAddress", "value": "1.1.1.1"},
        ).get_json()["entity"]
        e2e_auth_client.post(
            "/api/edge",
            json={"from_id": d["id"], "to_id": i["id"], "rel_type": "RESOLVES_TO"},
        )

        # Subgraph retorna os 2 nodes com description intacta
        sub = e2e_auth_client.get(f"/api/subgraph/{d['id']}?depth=2").get_json()
        assert len(sub["nodes"]) == 2, f"esperava 2 nodes, veio {len(sub['nodes'])}"
        node = next(n for n in sub["nodes"] if n["data"]["id"] == d["id"])
        assert node["data"]["description"] == "ação中文🚀"

    def test_reopen_archived_investigation(self, e2e_auth_client):
        """Investigation arquivada pode ser reaberta e editada."""
        # Setup
        inv = e2e_auth_client.post(
            "/api/investigations",
            json={"title": "Archived then reopen"},
        ).get_json()["investigation"]
        inv_id = inv["id"]

        # Archive
        arch = e2e_auth_client.post(f"/api/investigations/{inv_id}/archive")
        assert arch.status_code == 200

        # GET ainda retorna
        get_arch = e2e_auth_client.get(f"/api/investigations/{inv_id}")
        assert get_arch.get_json()["investigation"]["status"] == "archived"

        # Unarchive
        unarch = e2e_auth_client.post(f"/api/investigations/{inv_id}/unarchive")
        assert unarch.status_code == 200

        # Agora PUT funciona
        put = e2e_auth_client.put(
            f"/api/investigations/{inv_id}",
            json={"graph_snapshot": {"nodes": [], "edges": []}},
        )
        assert put.status_code == 200

    def test_cross_user_isolation_real_neo4j(
        self, e2e_auth_client, e2e_admin_client,
    ):
        """Anti-enumeração: outro user vê 404 (não 403) — contra Neo4j real."""
        # Auth client cria investigation
        inv = e2e_auth_client.post(
            "/api/investigations",
            json={"title": "Private"},
        ).get_json()["investigation"]
        inv_id = inv["id"]

        # Admin tenta acessar → 404 (anti-enumeração)
        get_admin = e2e_admin_client.get(f"/api/investigations/{inv_id}")
        assert get_admin.status_code == 404

        # Admin tenta deletar → 404
        del_admin = e2e_admin_client.delete(f"/api/investigations/{inv_id}")
        assert del_admin.status_code == 404

        # Investigation ainda existe (auth client ainda vê)
        get_owner = e2e_auth_client.get(f"/api/investigations/{inv_id}")
        assert get_owner.status_code == 200
