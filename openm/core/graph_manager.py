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

        Se `entity.created_by_user_id` estiver definido, é persistido no nó
        para posterior checagem de ownership (issue #38).

        Cypher:
            MERGE (n:Entity:<Tipo> {id: $id})
            SET n.value = $value,
                n.type = $type,
                n.properties = $properties_json,
                n.created_by_user_id = $user_id,
                n.updated_at = datetime()
        """
        if not self._available:
            logger.warning(
                "Tentativa de merge sem Neo4j disponível: %s", entity
            )
            return
        label = entity.type
        query = (
            f"MERGE (n:Entity:{label} {{id: $id}}) "
            "SET n.value = $value, "
            "n.type = $type, "
            "n.properties = $properties_json, "
            "n.created_by_user_id = $user_id, "
            "n.updated_at = datetime()"
        )
        with self.driver.session() as session:
            session.run(
                query,
                id=entity.id,
                value=entity.value,
                type=entity.type,
                properties_json=json.dumps(entity.properties),
                user_id=entity.created_by_user_id,
            )

    def is_owned_by(
        self, entity_id: str, user_id: int, is_admin: bool = False
    ) -> bool:
        """
        Retorna True se a entidade pertence ao usuário (issue #38).

        Regras:
        - Admin (`is_admin=True`) sempre pode (bypass).
        - Entidade legada (sem `created_by_user_id`) → True para todos.
        - Dono: True.
        - Outros: False.

        Retorna False também se a entidade não existir.
        """
        if not self._available:
            return False
        if is_admin:
            return True
        query = (
            "MATCH (n:Entity {id: $id}) "
            "RETURN n.created_by_user_id AS owner_id"
        )
        with self.driver.session() as session:
            result = session.run(query, id=entity_id).single()
            if not result:
                return False
            owner_id = result["owner_id"]
            if owner_id is None:
                # Entidade legada: visível para todos os autenticados.
                return True
            return int(owner_id) == int(user_id)

    def create_relationship(
        self,
        from_id: str,
        to_id: str,
        rel_type: str,
        properties: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
        is_admin: bool = False,
    ) -> bool:
        """
        Cria (ou atualiza) um relacionamento tipado entre duas entidades.

        Se `user_id` for fornecido, verifica que o usuário é dono de pelo
        menos uma das pontas (issue #38). Admin pode criar qualquer edge.
        Entidades legadas (sem user_id) são tratadas como públicas.

        Retorna False se o usuário não puder criar o edge.

        Cypher:
            MATCH (a:Entity {id: $from_id}), (b:Entity {id: $to_id})
            MERGE (a)-[r:<REL_TYPE>]->(b)
            SET r += $properties, r.updated_at = datetime()
        """
        properties = properties or {}
        if user_id is not None and not is_admin:
            if not (
                self.is_owned_by(from_id, user_id)
                or self.is_owned_by(to_id, user_id)
            ):
                return False
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
        return True

    def get_subgraph(
        self, center_id: str, depth: int = 2
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Busca um subgrafo em profundidade a partir de um nó central.

        Varre tanto saídas quanto entradas do nó central para capturar
        contexto completo da investigação.

        Aceita tanto o ``id`` interno da entidade (UUID) quanto o ``value``
        legível (ex: "example.com") como ponto de partida. Isso é necessário
        porque investigações gravam ``root_entity_id`` usando o value (que é
        o que o usuário vê), mas o id interno do Neo4j é um UUID.

        Cypher:
            MATCH path = (center:Entity)-[r*1..depth]-(n)
            WHERE center.id = $center_id OR center.value = $center_id
            RETURN center, relationships(path) AS rels, nodes(path) AS nodes

        Nota: Neo4j não aceita parâmetro na profundidade de variação de
        relacionamentos, então interpolamos o valor após validação.
        """
        depth = max(1, min(depth, 5))  # limite de segurança
        query = (
            f"MATCH path = (center:Entity)-[r*1..{depth}]-(n) "
            "WHERE center.id = $center_id OR center.value = $center_id "
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
            parsed_props = (
                json.loads(props) if isinstance(props, str) else props
            )
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
        self, entity_id: str, properties: Dict[str, Any], user_id: int,
        is_admin: bool = False
    ) -> bool:
        """
        Atualiza propriedades dinâmicas de uma entidade (merge).

        Retorna False se a entidade não existir OU se o usuário não for
        o dono (issue #38). Admin pode atualizar qualquer entidade.
        """
        if not self._available:
            return True
        if not self.is_owned_by(entity_id, user_id, is_admin=is_admin):
            return False
        query = (
            "MATCH (n:Entity {id: $id}) "
            "SET n += $props, n.updated_at = datetime() "
            "RETURN n"
        )
        with self.driver.session() as session:
            result = session.run(
                query, id=entity_id, props=properties
            ).single()
            return result is not None

    def delete_entity(
        self, entity_id: str, user_id: int, is_admin: bool = False
    ) -> bool:
        """
        Remove um nó e seus relacionamentos adjacentes.

        Retorna False se a entidade não existir OU se o usuário não for
        o dono (issue #38). Admin pode deletar qualquer entidade.
        """
        if not self._available:
            return True
        if not self.is_owned_by(entity_id, user_id, is_admin=is_admin):
            return False
        query = "MATCH (n:Entity {id: $id}) DETACH DELETE n"
        with self.driver.session() as session:
            session.run(query, id=entity_id)
            return True

    def delete_relationship(
        self, relationship_id: str, user_id: int, is_admin: bool = False
    ) -> bool:
        """
        Remove um relacionamento pelo id do elemento Neo4j.

        Retorna False se a relação não existir OU se nenhuma das pontas
        pertencer ao usuário (issue #38). Admin pode deletar qualquer
        relação. Retorna também False se as pontas forem legadas e
        pertencerem a outro user.
        """
        if not self._available:
            return True
        if is_admin:
            query = "MATCH ()-[r]->() WHERE elementId(r) = $id DELETE r"
            with self.driver.session() as session:
                session.run(query, id=relationship_id)
                return True

        # Pega os ids dos nós das duas pontas
        query = (
            "MATCH (a)-[r]->(b) WHERE elementId(r) = $id "
            "RETURN a.id AS from_id, b.id AS to_id"
        )
        with self.driver.session() as session:
            record = session.run(query, id=relationship_id).single()
            if not record:
                return False
            from_id = record["from_id"]
            to_id = record["to_id"]

        # Pelo menos uma ponta precisa ser do usuário (ou ser legacy/null)
        if not (
            self.is_owned_by(from_id, user_id)
            or self.is_owned_by(to_id, user_id)
        ):
            return False

        query = "MATCH ()-[r]->() WHERE elementId(r) = $id DELETE r"
        with self.driver.session() as session:
            session.run(query, id=relationship_id)
            return True
