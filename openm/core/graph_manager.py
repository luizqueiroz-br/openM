import json
import logging
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase

from .entity import Entity

logger = logging.getLogger(__name__)


class GraphManager:
    """
    Gerenciador de comunicação com o Neo4j.

    Responsável por inserir/atualizar entidades (merge), criar
    relacionamentos tipados e retornar subgrafos no formato
    Cytoscape.js para o frontend.
    """

    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self._available = True

    def close(self):
        """Fecha o driver do Neo4j."""
        self.driver.close()

    def ensure_constraints(self):
        """
        Cria constraint de unicidade no id de Entity, se ainda não existir.
        Também verifica se o Neo4j está acessível.

        Cypher:
            CREATE CONSTRAINT entity_id IF NOT EXISTS
            FOR (n:Entity) REQUIRE n.id IS UNIQUE
        """
        try:
            with self.driver.session() as session:
                session.run(
                    "CREATE CONSTRAINT entity_id IF NOT EXISTS "
                    "FOR (n:Entity) REQUIRE n.id IS UNIQUE"
                )
            self._available = True
        except Exception as exc:
            logger.warning("Neo4j indisponível: %s", exc)
            self._available = False
            raise

    def merge_entity(self, entity: Entity) -> None:
        """
        Faz merge de uma entidade no Neo4j.

        A label dinâmica do tipo da entidade é aplicada junto com a label
        genérica `Entity`. Propriedades dinâmicas são serializadas como JSON
        para evitar problemas de tipo no Cypher.

        Cypher:
            MERGE (n:Entity:<Tipo> {id: $id})
            SET n.value = $value,
                n.type = $type,
                n.properties = $properties_json,
                n.updated_at = datetime()
        """
        if not self._available:
            logger.warning("Tentativa de merge sem Neo4j disponível: %s", entity)
            return
        label = entity.type
        query = (
            f"MERGE (n:Entity:{label} {{id: $id}}) "
            "SET n.value = $value, "
            "n.type = $type, "
            "n.properties = $properties_json, "
            "n.updated_at = datetime()"
        )
        with self.driver.session() as session:
            session.run(
                query,
                id=entity.id,
                value=entity.value,
                type=entity.type,
                properties_json=json.dumps(entity.properties),
            )

    def create_relationship(
        self,
        from_id: str,
        to_id: str,
        rel_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Cria (ou atualiza) um relacionamento tipado entre duas entidades.

        Cypher:
            MATCH (a:Entity {id: $from_id}), (b:Entity {id: $to_id})
            MERGE (a)-[r:<REL_TYPE>]->(b)
            SET r += $properties, r.updated_at = datetime()
        """
        properties = properties or {}
        query = (
            "MATCH (a:Entity {id: $from_id}), (b:Entity {id: $to_id}) "
            f"MERGE (a)-[r:{rel_type}]->(b) "
            "SET r += $properties, r.updated_at = datetime()"
        )
        with self.driver.session() as session:
            session.run(
                query,
                from_id=from_id,
                to_id=to_id,
                properties=properties,
            )

    def get_subgraph(
        self, center_id: str, depth: int = 2
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Busca um subgrafo em profundidade a partir de um nó central.

        Varre tanto saídas quanto entradas do nó central para capturar
        contexto completo da investigação.

        Cypher:
            MATCH path = (center:Entity {id: $center_id})-[r*1..depth]-(n)
            RETURN center, relationships(path) AS rels, nodes(path) AS nodes

        Nota: Neo4j não aceita parâmetro na profundidade de variação de
        relacionamentos, então interpolamos o valor após validação.
        """
        depth = max(1, min(depth, 5))  # limite de segurança
        query = (
            f"MATCH path = (center:Entity {{id: $center_id}})-[r*1..{depth}]-(n) "
            "RETURN center, relationships(path) AS rels, nodes(path) AS nodes"
        )

        nodes_map: Dict[str, Dict[str, Any]] = {}
        edges_map: Dict[str, Dict[str, Any]] = {}

        with self.driver.session() as session:
            result = session.run(query, center_id=center_id)
            for record in result:
                center = record["center"]
                nodes_map[center["id"]] = self._node_to_cytoscape(center)

                for node in record["nodes"]:
                    nodes_map[node["id"]] = self._node_to_cytoscape(node)

                for rel in record["rels"]:
                    edge_id = rel.element_id
                    edges_map[edge_id] = self._rel_to_cytoscape(rel)

        return {
            "elements": {
                "nodes": list(nodes_map.values()),
                "edges": list(edges_map.values()),
            }
        }

    @staticmethod
    def _node_to_cytoscape(node) -> Dict[str, Any]:
        """Converte um nó Neo4j para elemento Cytoscape.js."""
        props = node.get("properties", "{}")
        try:
            parsed_props = json.loads(props) if isinstance(props, str) else props
        except json.JSONDecodeError:
            parsed_props = {}

        return {
            "data": {
                "id": node["id"],
                "label": node["value"],
                "type": node["type"],
                **parsed_props,
            }
        }

    @staticmethod
    def _rel_to_cytoscape(rel) -> Dict[str, Any]:
        """Converte um relacionamento Neo4j para elemento Cytoscape.js."""
        props = dict(rel.items())
        # Remove metadatas que não são propriedades úteis para o frontend
        props.pop("updated_at", None)
        return {
            "data": {
                "id": rel.element_id,
                "source": rel.start_node["id"],
                "target": rel.end_node["id"],
                "label": rel.type,
                **props,
            }
        }

    def clear(self) -> None:
        """Apaga todos os nós e relacionamentos do grafo. Útil em testes."""
        if not self._available:
            return
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")

    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Busca uma entidade por id; retorna None se não existir."""
        if not self._available:
            return None
        query = "MATCH (n:Entity {id: $id}) RETURN n"
        with self.driver.session() as session:
            result = session.run(query, id=entity_id).single()
            if not result:
                return None
            node = result["n"]
            return self._node_to_cytoscape(node)

    def update_entity_properties(
        self, entity_id: str, properties: Dict[str, Any]
    ) -> bool:
        """Atualiza propriedades dinâmicas de uma entidade (merge)."""
        if not self._available:
            return True
        query = (
            "MATCH (n:Entity {id: $id}) "
            "SET n += $props, n.updated_at = datetime() "
            "RETURN n"
        )
        with self.driver.session() as session:
            result = session.run(query, id=entity_id, props=properties).single()
            return result is not None

    def delete_entity(self, entity_id: str) -> bool:
        """Remove um nó e seus relacionamentos adjacentes."""
        if not self._available:
            return True
        query = "MATCH (n:Entity {id: $id}) DETACH DELETE n"
        with self.driver.session() as session:
            session.run(query, id=entity_id)
            return True

    def delete_relationship(self, relationship_id: str) -> bool:
        """Remove um relacionamento pelo id do elemento Neo4j."""
        if not self._available:
            return True
        query = "MATCH ()-[r]->() WHERE elementId(r) = $id DELETE r"
        with self.driver.session() as session:
            session.run(query, id=relationship_id)
            return True
