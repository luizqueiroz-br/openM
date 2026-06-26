"""
Testes E2E diretos do GraphManager (issue #18).

Valida o ``GraphManager`` contra Neo4j real (não mockado). Foco em:
- Idempotência de constraints
- Operação clear()
- Contrato estável do ``get_subgraph``
"""

import pytest


pytestmark = pytest.mark.e2e


class TestE2EGraphManagerDirect:
    """Testes diretos do GraphManager contra Neo4j real (não via API)."""

    def test_ensure_constraints_idempotent(self, e2e_app):
        """ensure_constraints() pode ser chamado múltiplas vezes sem erro."""
        from openm.utils.neo4j_client import get_graph_manager, reset_graph_manager

        reset_graph_manager()
        gm1 = get_graph_manager()
        gm1.ensure_constraints()
        # Segunda chamada não deve falhar (IF NOT EXISTS)
        gm2 = get_graph_manager()
        gm2.ensure_constraints()

    def test_clear_removes_all_nodes(self, e2e_app):
        """clear() apaga todos os nós e relacionamentos."""
        from openm.utils.neo4j_client import get_graph_manager

        gm = get_graph_manager()
        # Cria uma entidade via driver direto
        with gm.driver.session() as session:
            session.run(
                "CREATE (n:Entity {id: 'temp-1', type: 'Domain', "
                "value: 'temp.com', properties: '{}'})"
            )
        # Confirma que existe
        with gm.driver.session() as session:
            result = session.run("MATCH (n:Entity {id: 'temp-1'}) RETURN n")
            assert result.single() is not None

        # clear()
        gm.clear()

        # Confirma que sumiu
        with gm.driver.session() as session:
            result = session.run("MATCH (n:Entity {id: 'temp-1'}) RETURN n")
            assert result.single() is None

    def test_get_subgraph_returns_stable_wrapper(self, e2e_app):
        """get_subgraph retorna {nodes, edges} — contrato estável (issue #19)."""
        from openm.utils.neo4j_client import get_graph_manager

        gm = get_graph_manager()
        # depth=0 → clamped to 1
        result0 = gm.get_subgraph("qualquer-id", depth=0)
        assert "nodes" in result0
        assert "edges" in result0
        assert "elements" not in result0  # não legacy
        # depth=999 → clamped to 5
        result999 = gm.get_subgraph("qualquer-id", depth=999)
        assert "nodes" in result999
        assert "edges" in result999
