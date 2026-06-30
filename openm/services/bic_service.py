"""
Servico de validacao de SWIFT/BIC (Bank Identifier Code).

Formato (ISO 9362):
- 8 chars: AAAA BB CC (business party prefix + country + location)
- 11 chars: AAAA BB CC XXX (8 chars + branch code opcional)
- AAAA: 4 letras identificando a instituicao (codigo SWIFT).
- BB: 2 letras do pais ISO 3166-1 alpha-2.
- CC: 2 chars (letra ou digito) do codigo de localidade/cidade.
- XXX: 3 chars alfanumericos do branch code (opcional).

Referencia: https://en.wikipedia.org/wiki/ISO_9362
"""
import re
from typing import Any, Dict, List


_BIC8_RE = re.compile(r"^([A-Z]{4})([A-Z]{2})([A-Z0-9]{2})$")
_BIC11_RE = re.compile(r"^([A-Z]{4})([A-Z]{2})([A-Z0-9]{2})([A-Z0-9]{3})$")

# Codigos de pais conhecidos (subset usado para validacao rapida).
_KNOWN_COUNTRY_CODES = {
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AR", "AT", "AU", "AW", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO",
    "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ",
    "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR",
    "CU", "CV", "CW", "CX", "CY", "CZ",
    "DE", "DJ", "DK", "DM", "DO", "DZ",
    "EC", "EE", "EG", "EH", "ER", "ES", "ET",
    "FI", "FJ", "FK", "FM", "FO", "FR",
    "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ",
    "GR", "GS", "GT", "GU", "GW", "GY",
    "HK", "HM", "HN", "HR", "HT", "HU",
    "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT",
    "JE", "JM", "JO", "JP",
    "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ",
    "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY",
    "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP",
    "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ",
    "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ",
    "OM",
    "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY",
    "QA",
    "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN",
    "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ",
    "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT",
    "TV", "TW", "TZ",
    "UA", "UG", "UM", "US", "UY", "UZ",
    "VA", "VC", "VE", "VG", "VI", "VN", "VU",
    "WF", "WS",
    "XK",
    "YE", "YT",
    "ZA", "ZM", "ZW",
}


class BICService:
    """Validacao de SWIFT/BIC (Bank Identifier Code)."""

    @staticmethod
    def is_bic(value: str) -> bool:
        """Retorna True se o valor parece um BIC/SWIFT valido."""
        if not value or not isinstance(value, str):
            return False
        return BICService.validate(value)["valid"]

    @staticmethod
    def validate(value: str) -> Dict[str, Any]:
        """
        Valida um BIC/SWIFT code.

        Args:
            value: BIC de 8 ou 11 chars (letras/digitos, sem hifens).

        Returns:
            Dict com chaves:
              - valid (bool): True se formato e codigo de pais sao validos.
              - business_party_prefix (str): 4 letras do codigo da instituicao.
              - country_code (str): 2 letras do pais ISO 3166-1.
              - location_code (str): 2 chars de cidade/locacao.
              - branch_code (str|None): 3 chars do branch (apenas BIC11).
              - format (str): 'BIC8' ou 'BIC11'.
              - errors (list[str]): erros de validacao.
        """
        result: Dict[str, Any] = {
            "valid": False,
            "business_party_prefix": None,
            "country_code": None,
            "location_code": None,
            "branch_code": None,
            "format": None,
            "errors": [],
            "source": "bic_validation",
        }

        if not value or not isinstance(value, str):
            result["errors"].append("empty_value")
            return result

        cleaned = value.strip().upper()
        if "-" in cleaned:
            cleaned = cleaned.replace("-", "")

        if len(cleaned) == 8:
            match = _BIC8_RE.match(cleaned)
            if not match:
                result["errors"].append("format_invalid_8")
                return result
            bpp, country, location = match.groups()
            result["format"] = "BIC8"
            result["business_party_prefix"] = bpp
            result["country_code"] = country
            result["location_code"] = location
        elif len(cleaned) == 11:
            match = _BIC11_RE.match(cleaned)
            if not match:
                result["errors"].append("format_invalid_11")
                return result
            bpp, country, location, branch = match.groups()
            result["format"] = "BIC11"
            result["business_party_prefix"] = bpp
            result["country_code"] = country
            result["location_code"] = location
            # Branch code "XXX" indica sede principal.
            if branch == "XXX":
                result["branch_code"] = "primary"
            else:
                result["branch_code"] = branch
        else:
            result["errors"].append("wrong_length")
            return result

        if country not in _KNOWN_COUNTRY_CODES:
            result["errors"].append("country_code_unknown")
        else:
            result["valid"] = True
        return result

    @staticmethod
    def known_country_codes() -> List[str]:
        """Retorna lista de paises ISO 3166-1 alpha-2 conhecidos."""
        return sorted(_KNOWN_COUNTRY_CODES)
