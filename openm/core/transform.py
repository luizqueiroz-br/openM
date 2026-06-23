from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Type

from .entity import Entity


@dataclass
class TransformResult:
    """Resultado padrão de um Transform."""

    entities: List[Entity] = field(default_factory=list)
    relationships: List[Dict] = field(default_factory=list)


class Transform(ABC):
    """
    Interface base para todos os transforms do OpenM.

    Um transform recebe uma entidade de entrada, executa uma lógica
    (consulta DNS, API de threat intel, etc.) e retorna novas
    entidades mais os vínculos entre elas.
    """

    name: str = "base_transform"
    display_name: str = "Base Transform"
    input_types: List[str] = []
    description: str = ""

    @abstractmethod
    def run(self, entity: Entity) -> TransformResult:
        """
        Executa a lógica do transform.

        Args:
            entity: entidade de entrada.

        Returns:
            TransformResult contendo novas entidades e relacionamentos.
        """
        raise NotImplementedError

    @classmethod
    def register(cls, transform_class: Type["Transform"] | None = None, *, name: str | None = None):
        """Atalho para TransformRegistry.register mantendo sintaxe @Transform.register."""
        return TransformRegistry.register(transform_class, name=name)


class TransformRegistry:
    """
    Registro global de transforms disponíveis.

    Permite descobrir dinamicamente quais transforms podem ser
    executados sobre determinado tipo de entidade.
    """

    _transforms: Dict[str, Type[Transform]] = {}

    @classmethod
    def register(cls, transform_class: Type[Transform] | None = None, *, name: str | None = None):
        """
        Decorador/funcional para registrar um transform.

        Pode ser usado como @Transform.register ou explicitamente.
        """
        def _register(tc: Type[Transform]) -> Type[Transform]:
            key = name or tc.name
            cls._transforms[key] = tc
            return tc

        if transform_class is not None:
            return _register(transform_class)
        return _register

    @classmethod
    def get(cls, name: str) -> Type[Transform] | None:
        return cls._transforms.get(name)

    @classmethod
    def list_for_type(cls, entity_type: str) -> List[Dict]:
        """Lista transforms compatíveis com um tipo de entidade."""
        return [
            {
                "name": t.name,
                "display_name": t.display_name,
                "input_types": t.input_types,
                "description": t.description,
            }
            for t in cls._transforms.values()
            if entity_type in t.input_types
        ]

    @classmethod
    def list_all(cls) -> List[Dict]:
        """Lista todos os transforms registrados."""
        return [
            {
                "name": t.name,
                "display_name": t.display_name,
                "input_types": t.input_types,
                "description": t.description,
            }
            for t in cls._transforms.values()
        ]
