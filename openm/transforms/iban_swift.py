import re
from datetime import datetime, timezone
from typing import Any, Dict

from openm.core.entity import BankAccount, Entity
from openm.core.transform import Transform, TransformResult
from openm.services.bic_service import BICService
from openm.services.iban_service import IBANService


# Ordem: BIC puro (8/11 chars alfanumericos) vs IBAN (2 letras + 2 digitos).
_IBAN_HINT_RE = re.compile(r"^[A-Z]{2}\d{2}")
_BIC_HINT_RE = re.compile(r"^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$")


@Transform.register
class IbanSwiftTransform(Transform):
    """
    Transform que valida e enriquece uma BankAccount com base no valor.

    Detecta automaticamente o tipo (IBAN ou BIC/SWIFT) e aplica a
    validacao correspondente:

      - IBAN: checksum mod 97-10, parsing BBAN por pais, identificacao
        do codigo do pais e comprimento.
      - BIC/SWIFT: formato ISO 9362, pais ISO 3166-1 alpha-2, branch code.

    Saida: BankAccount enriquecida com propriedades:
      - bank_account_valid (bool)
      - bank_account_type (iban | bic | unknown)
      - bank_account_country_code
      - bank_account_formatted
      - bank_account_metadata (dict com detalhes do parser)

    Sem API key (validacao totalmente local). Util para pivotar de
    contas bancarias em uma investigacao OSINT/financeira.
    """

    name = "iban_swift_validation"
    display_name = "IBAN/SWIFT Validation"
    input_types = ["BankAccount"]
    description = (
        "Valida e enriquece BankAccount: detecta se o valor e IBAN ou "
        "BIC/SWIFT, aplica checksum mod 97-10 para IBAN e formato ISO "
        "9362 para BIC. Sem API key."
    )
    cache_ttl_seconds = 604800  # 7 dias — dados estruturais nao mudam

    def _run(self, entity: Entity) -> TransformResult:
        if not isinstance(entity, BankAccount):
            return TransformResult()

        value = entity.value
        if not value or not isinstance(value, str):
            return TransformResult()

        checked_at = datetime.now(timezone.utc).isoformat()

        iban_validation = None
        bic_validation = None
        detected_type = "unknown"
        valid = False
        country_code = None
        formatted = None
        metadata: Dict[str, Any] = {}

        # Heuristica de deteccao: IBAN comeca com 2 letras + 2 digitos;
        # BIC comeca com 4 letras. Compara para evitar falsos positivos.
        normalized = value.strip().upper().replace(" ", "").replace("-", "")
        if _IBAN_HINT_RE.match(normalized) and not _BIC_HINT_RE.match(normalized):
            detected_type = "iban"
        elif _BIC_HINT_RE.match(normalized) and not _IBAN_HINT_RE.match(normalized):
            detected_type = "bic"
        else:
            # Tenta ambos e usa o que for valido; senao escolhe pelo
            # comprimento/alfabeto.
            iban_try = IBANService.validate(normalized)
            bic_try = BICService.validate(normalized)
            if iban_try["valid"]:
                detected_type = "iban"
            elif bic_try["valid"]:
                detected_type = "bic"
            elif len(normalized) >= 15 and normalized[:2].isalpha():
                detected_type = "iban"
            else:
                detected_type = "bic"

        if detected_type == "iban":
            iban_validation = IBANService.validate(normalized)
            valid = iban_validation["valid"]
            country_code = iban_validation["country_code"]
            formatted = iban_validation["formatted"]
            metadata = {
                "iban_check_digits": iban_validation["check_digits"],
                "iban_bban": iban_validation["bban"],
                "iban_format": iban_validation["iban_format"],
            }
        elif detected_type == "bic":
            bic_validation = BICService.validate(normalized)
            valid = bic_validation["valid"]
            country_code = bic_validation["country_code"]
            formatted = normalized
            metadata = {
                "bic_format": bic_validation["format"],
                "bic_business_party_prefix": bic_validation["business_party_prefix"],
                "bic_location_code": bic_validation["location_code"],
                "bic_branch_code": bic_validation["branch_code"],
            }

        # Enriquece a BankAccount preservando id e propriedades anteriores.
        enriched_props: Dict[str, Any] = {
            "bank_account_valid": valid,
            "bank_account_type": detected_type,
            "bank_account_country_code": country_code,
            "bank_account_formatted": formatted,
            "bank_account_metadata": metadata,
            "bank_account_checked_at": checked_at,
            "bank_account_source": "local_validation",
        }
        enriched = BankAccount(
            value=entity.value,
            properties={**entity.properties, **enriched_props},
            entity_id=entity.id,
        )

        return TransformResult(entities=[enriched], relationships=[])
