from abc import ABC, abstractmethod
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type

from .entity import Entity


@dataclass
class TransformResult:
    """Resultado padrão de um Transform."""

    entities: List[Entity] = field(default_factory=list)
    relationships: List[Dict] = field(default_factory=list)


# ContextVar para contar chamadas externas (HTTP/API) durante a execucao
# de um transform. Services HTTP devem chamar increment_api_call_counter()
# a cada request realizado. O valor e automaticamente isolado por
# execucao/thread async.
_api_call_counter: ContextVar[int] = ContextVar("api_call_counter", default=0)


def reset_api_call_counter() -> None:
    """Reseta o contador de chamadas externas para zero."""
    _api_call_counter.set(0)


def increment_api_call_counter() -> int:
    """Incrementa o contador de chamadas externas e retorna novo valor."""
    new_value = _api_call_counter.get(0) + 1
    _api_call_counter.set(new_value)
    return new_value


def get_api_call_count() -> int:
    """Retorna o numero atual de chamadas externas acumuladas."""
    return _api_call_counter.get(0)


@dataclass
class TransformMetrics:
    """Metricas de execucao de um Transform."""

    duration_ms: float = 0.0
    status: str = "success"  # success / error / timeout / quota_exceeded
    entities_created: int = 0
    relationships_created: int = 0
    api_calls: int = 0
    cache_hit: bool = False
    error_message: Optional[str] = None


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
    # Identifica a API externa (e sua chave) consumida pelo transform.
    # Transforms que NAO precisam de chave (whois, geoip, resolve_ip)
    # deixam ambos como None. Usado para popular dinamicamente o
    # dropdown de API Keys no frontend (issue #6 follow-up).
    service_name: Optional[str] = None  # ex: "shodan", "virustotal"
    service_display: Optional[str] = None  # ex: "Shodan", "VirusTotal"
    # TTL do cache de resultado em segundos. ``0`` desabilita o cache.
    # O endpoint /api/run_transform consulta o cache antes de executar
    # e salva o resultado depois — ver openm.core.transform_cache.
    cache_ttl_seconds: int = 0

    def run(self, entity: Entity) -> TransformResult:
        """
        Template method que valida input_types, mede execucao e delega
        para _run().

        Se o tipo da entidade não está em input_types, retorna
        TransformResult vazio imediatamente (sem executar o transform).

        Args:
            entity: entidade de entrada.

        Returns:
            TransformResult contendo novas entidades e relacionamentos.
        """
        if entity.type not in self.input_types:
            return TransformResult()

        import time

        reset_api_call_counter()
        start = time.perf_counter()
        status = "success"
        error_message: Optional[str] = None

        try:
            result = self._run(entity)
        except TimeoutError as exc:
            status = "timeout"
            error_message = str(exc) or "timeout"
            result = TransformResult()
        except Exception as exc:
            status = "error"
            error_message = str(exc)
            result = TransformResult()

        duration_ms = (time.perf_counter() - start) * 1000.0
        metrics = TransformMetrics(
            duration_ms=round(duration_ms, 2),
            status=status,
            entities_created=len(result.entities),
            relationships_created=len(result.relationships),
            api_calls=get_api_call_count(),
        )
        # Anexa as metricas no resultado para a API/CLI consumir sem
        # precisar modificar a assinatura publica de run().
        result._metrics = metrics  # type: ignore[attr-defined]

        if error_message:
            result._metrics.error_message = error_message  # type: ignore[attr-defined]

        return result

    @abstractmethod
    def _run(self, entity: Entity) -> TransformResult:
        """
        Implementação específica do transform.

        O tipo da entidade já foi validado contra input_types pelo
        template method run(). Subclasses não precisam repetir a
        verificação de tipo.

        Args:
            entity: entidade de entrada (tipo já validado).

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
                "service_name": getattr(t, "service_name", None),
                "service_display": getattr(t, "service_display", None),
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
                "service_name": getattr(t, "service_name", None),
                "service_display": getattr(t, "service_display", None),
            }
            for t in cls._transforms.values()
        ]

    @classmethod
    def list_services(cls) -> List[Dict]:
        """Lista services disponíveis para cadastro de API Key.

        Retorna apenas transforms que declararam ``service_name`` (nao
        None). Usado para popular o dropdown de API Keys no frontend.
        Deduplicado por ``service_name`` (caso 2 transforms usem o mesmo
        service). Ordenado por ``display_name`` (case-insensitive) para
        uma UI estável.

        Returns:
            Lista de dicts com chaves:
              - service_name: slug usado em ``ApiKey.service_name``
              - display_name: label legivel para o usuario
              - transform_name: ``name`` do primeiro transform que
                declarou esse service (util para o usuario entender
                qual transform consome essa chave).
        """
        seen = set()
        out = []
        for t in cls._transforms.values():
            sn = getattr(t, "service_name", None)
            if sn and sn not in seen:
                seen.add(sn)
                out.append({
                    "service_name": sn,
                    "display_name": getattr(t, "service_display", sn),
                    "transform_name": t.name,
                })
        out.sort(key=lambda x: x["display_name"].lower())
        return out
