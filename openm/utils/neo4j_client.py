import logging

from openm.config import Config
from openm.core.graph_manager import GraphManager

logger = logging.getLogger(__name__)

# Singleton do GraphManager, reutilizado pela aplicação.
# A inicialização lazy evita conexão ao Neo4j durante importação.
_graph_manager: GraphManager | None = None


def get_graph_manager() -> GraphManager:
    """Retorna instância única do GraphManager."""
    global _graph_manager
    if _graph_manager is None:
        _graph_manager = GraphManager(
            uri=Config.NEO4J_URI,
            user=Config.NEO4J_USER,
            password=Config.NEO4J_PASSWORD,
        )
        try:
            _graph_manager.ensure_constraints()
        except Exception as exc:
            logger.warning(
                "Neo4j indisponível em %s: %s. Persistência de grafo desativada.",
                Config.NEO4J_URI,
                exc,
            )
    return _graph_manager


def reset_graph_manager() -> None:
    """Fecha e reseta o singleton. Útil em testes."""
    global _graph_manager
    if _graph_manager is not None:
        try:
            _graph_manager.close()
        except Exception:
            pass
        _graph_manager = None
