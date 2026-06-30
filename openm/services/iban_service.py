"""
Servico de validacao de IBAN (International Bank Account Number).

Implementa validacao completa conforme ISO 13616:
- Formato: 2 letras (pais) + 2 digitos (check) + ate 30 chars (BBAN).
- Algoritmo de checksum mod 97-10: letras viram numeros (A=10..Z=35),
  primeiros 4 chars movidos para o final, modulo 97 deve ser 1.
- Comprimento varia por pais (BR=29, DE=22, GB=22, FR=27, ES=24, etc.).

Inclui tabela minima de paises com comprimento, regex BBAN e exemplo.
Em producao, considerar usar ``python-stdnum`` para cobertura completa
de todos os paises; aqui implementamos manualmente os paises mais
comuns para evitar dependencia extra.

Referencias:
- https://en.wikipedia.org/wiki/International_Bank_Account_Number
- https://www.swift.com/standards/data-standards/iban
"""
import re
from typing import Any, Dict


# Mapeamento: pais (ISO 3166-1 alpha-2) -> (comprimento total IBAN, regex BBAN, exemplo)
# regex BBAN captura os grupos principais; a estrutura exata varia por pais.
_IBAN_SPECS: Dict[str, Dict[str, Any]] = {
    "AL": {"length": 28, "bban_re": r"^(\d{8})(\w{16})$", "example": "AL47212110090000000235698741"},
    "AD": {"length": 24, "bban_re": r"^(\d{8})(\w{12})$", "example": "AD1200012030200359100100"},
    "AT": {"length": 20, "bban_re": r"^(\d{5})(\d{11})$", "example": "AT611904300234573201"},
    "AZ": {"length": 28, "bban_re": r"^(\w{4})(\d{20})$", "example": "AZ21NABZ00000000137010001944"},
    "BE": {"length": 16, "bban_re": r"^(\d{3})(\d{7})(\d{2})$", "example": "BE68539007547034"},
    "BR": {
        "length": 29,
        "bban_re": r"^(\d{8})(\d{5})(\d{10})([A-Z]{1})(\d{1})$",
        "example": "BR9700360305000010009795493P1",
    },
    "BG": {"length": 22, "bban_re": r"^(\w{4})(\d{6})(\d{8})$", "example": "BG80BNBG96611020345678"},
    "BY": {"length": 28, "bban_re": r"^(\w{4})(\d{20})$", "example": "BY13NBRB3600900000002Z00AB00"},
    "CH": {"length": 21, "bban_re": r"^(\d{5})(\w{12})$", "example": "CH9300762011623852957"},
    "CR": {"length": 22, "bban_re": r"^(\d{4})(\d{14})$", "example": "CR15015200000000000001234567"},
    "CY": {"length": 28, "bban_re": r"^(\d{3})(\d{5})(\w{16})$", "example": "CY17002001280000001200527600"},
    "CZ": {"length": 24, "bban_re": r"^(\d{4})(\d{6})(\d{10})$", "example": "CZ6508000000192000145399"},
    "DE": {"length": 22, "bban_re": r"^(\d{8})(\d{10})$", "example": "DE89370400440532013000"},
    "DK": {"length": 18, "bban_re": r"^(\d{4})(\d{10})$", "example": "DK5000400440116243"},
    "DO": {"length": 28, "bban_re": r"^(\w{4})(\d{20})$", "example": "DO28BAGR00000001212453611324"},
    "EE": {"length": 20, "bban_re": r"^(\d{2})(\d{2})(\d{11})(\d{1})$", "example": "EE382200221020145685"},
    "ES": {"length": 24, "bban_re": r"^(\d{4})(\d{4})(\d{2})(\d{10})$", "example": "ES9121000418450200051332"},
    "FI": {"length": 18, "bban_re": r"^(\d{6})(\d{7})(\d{1})$", "example": "FI2112345600000785"},
    "FR": {
        "length": 27,
        "bban_re": r"^(\d{5})(\d{5})(\w{11})(\d{2})$",
        "example": "FR1420041010050500013M02606",
    },
    "GB": {"length": 22, "bban_re": r"^(\w{4})(\d{6})(\d{8})$", "example": "GB29NWBK60161331926819"},
    "GR": {"length": 27, "bban_re": r"^(\d{3})(\d{4})(\w{16})$", "example": "GR1601101250000000012300695"},
    "HR": {"length": 21, "bban_re": r"^(\d{7})(\d{10})$", "example": "HR1210010051863000160"},
    "HU": {
        "length": 28,
        "bban_re": r"^(\d{3})(\d{4})(\d{1})(\d{15})(\d{1})$",
        "example": "HU42117730161111101800000000",
    },
    "IE": {"length": 22, "bban_re": r"^(\w{4})(\d{6})(\d{8})$", "example": "IE29AIBK93115212345678"},
    "IL": {"length": 23, "bban_re": r"^(\d{3})(\d{3})(\d{13})$", "example": "IL620108000000099999999"},
    "IS": {"length": 26, "bban_re": r"^(\d{4})(\d{2})(\d{6})(\d{10})$", "example": "IS140159260076545510730339"},
    "IT": {"length": 27, "bban_re": r"^(\w{5})(\d{5})(\w{5})(\d{12})$", "example": "IT60X0542811101000000123456"},
    "KW": {"length": 30, "bban_re": r"^(\w{4})(\d{22})$", "example": "KW81CBKU0000000000001234560101"},
    "KZ": {"length": 20, "bban_re": r"^(\d{3})(\w{13})$", "example": "KZ86125KZT5004100100"},
    "LB": {"length": 28, "bban_re": r"^(\d{4})(\w{20})$", "example": "LB62099900000001001901229114"},
    "LI": {"length": 21, "bban_re": r"^(\d{5})(\w{12})$", "example": "LI21088100002324013AA"},
    "LT": {"length": 20, "bban_re": r"^(\d{5})(\d{11})$", "example": "LT121000011101001000"},
    "LU": {"length": 20, "bban_re": r"^(\d{3})(\w{13})$", "example": "LU280019400644750000"},
    "LV": {"length": 21, "bban_re": r"^(\w{4})(\d{13})$", "example": "LV80BANK0000435195001"},
    "MC": {"length": 27, "bban_re": r"^(\d{5})(\d{5})(\w{11})(\d{2})$", "example": "MC5811222000010123456789030"},
    "MD": {"length": 24, "bban_re": r"^(\w{2})(\d{18})$", "example": "MD24AG000225100013104168"},
    "ME": {"length": 22, "bban_re": r"^(\d{3})(\d{13})(\d{2})$", "example": "ME25505000012345678951"},
    "MT": {"length": 31, "bban_re": r"^(\w{4})(\d{5})(\w{18})$", "example": "MT84MALT011000012345MTLCAST001S"},
    "NL": {"length": 18, "bban_re": r"^(\w{4})(\d{10})$", "example": "NL91ABNA0417164300"},
    "NO": {"length": 15, "bban_re": r"^(\d{4})(\d{6})(\d{1})$", "example": "NO9386011117947"},
    "PL": {"length": 28, "bban_re": r"^(\d{8})(\d{16})$", "example": "PL61109010140000071219812874"},
    "PT": {"length": 25, "bban_re": r"^(\d{4})(\d{4})(\d{11})(\d{2})$", "example": "PT50000201231234567890154"},
    "RO": {"length": 24, "bban_re": r"^(\w{4})(\w{16})$", "example": "RO49AAAA1B31007593840000"},
    "RS": {"length": 22, "bban_re": r"^(\d{3})(\d{13})(\d{2})$", "example": "RS35260005601001611379"},
    "SA": {"length": 24, "bban_re": r"^(\d{2})(\w{18})$", "example": "SA0380000000608010167519"},
    "SE": {"length": 24, "bban_re": r"^(\d{3})(\d{17})$", "example": "SE4550000000058398257466"},
    "SI": {"length": 19, "bban_re": r"^(\d{5})(\d{8})(\d{2})$", "example": "SI56263300012039086"},
    "SK": {"length": 24, "bban_re": r"^(\d{4})(\d{6})(\d{10})$", "example": "SK3112000000198742637541"},
    "SM": {"length": 27, "bban_re": r"^(\w{5})(\d{5})(\w{5})(\d{12})$", "example": "SM86U0322509800000000270100"},
    "TR": {"length": 26, "bban_re": r"^(\d{5})(\d{1})(\w{4})(\d{16})$", "example": "TR330006100519786457841326"},
    "UA": {"length": 29, "bban_re": r"^(\d{6})(\d{19})$", "example": "UA213996220000026007233566001"},
    "VA": {"length": 22, "bban_re": r"^(\d{3})(\d{15})$", "example": "VA59001123000012345678"},
    "XK": {"length": 20, "bban_re": r"^(\d{4})(\d{10})(\d{2})$", "example": "XK051212012345678906"},
}

# Regex basica: 2 letras + 2 digitos + 8..30 chars alfanumericos.
_IBAN_BASE_RE = re.compile(r"^([A-Z]{2})(\d{2})([A-Z0-9]{8,30})$")


def _to_numeric(iban: str) -> str:
    """Converte letras do IBAN em numeros (A=10..Z=35) e reordena."""
    rearranged = iban[4:] + iban[:4]
    return "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)


def _mod97(numeric: str) -> int:
    """Calcula checksum mod 97 sobre uma string de digitos (algoritmo ISO 7064)."""
    # Processa em chunks para evitar inteiros gigantes em IBANs longos.
    remainder = 0
    for chunk_start in range(0, len(numeric), 9):
        chunk = numeric[chunk_start:chunk_start + 9]
        remainder = (remainder * (10 ** len(chunk)) + int(chunk)) % 97
    return remainder


class IBANService:
    """Validacao de IBAN (International Bank Account Number)."""

    @staticmethod
    def is_iban(value: str) -> bool:
        """Retorna True se o valor parece um IBAN (formato + checksum)."""
        if not value or not isinstance(value, str):
            return False
        return IBANService.validate(value)["valid"]

    @staticmethod
    def validate(value: str) -> Dict[str, Any]:
        """
        Valida um IBAN.

        Args:
            value: IBAN em qualquer formato (com ou sem espacos/separadores).

        Returns:
            Dict com chaves:
              - valid (bool): True se o IBAN passa na validacao completa.
              - country_code (str): codigo ISO 3166-1 alpha-2.
              - check_digits (str): 2 digitos de checksum.
              - bban (str): parte especifica do pais.
              - formatted (str): IBAN formatado com espacos a cada 4 chars.
              - iban_format (dict): estrutura especifica do pais
                (comprimento, bank_code, account_number, etc.).
              - errors (list[str]): lista de erros de validacao.
        """
        result: Dict[str, Any] = {
            "valid": False,
            "country_code": None,
            "check_digits": None,
            "bban": None,
            "formatted": None,
            "iban_format": {},
            "errors": [],
            "source": "iban_validation",
        }

        if not value or not isinstance(value, str):
            result["errors"].append("empty_value")
            return result

        # Remove espacos e separadores comuns.
        cleaned = re.sub(r"[\s\-]", "", value).upper()
        match = _IBAN_BASE_RE.match(cleaned)
        if not match:
            result["errors"].append("format_invalid")
            return result

        country_code, check_digits, bban = match.groups()
        result["country_code"] = country_code
        result["check_digits"] = check_digits
        result["bban"] = bban

        spec = _IBAN_SPECS.get(country_code)
        if spec is None:
            result["errors"].append("country_unsupported")
            return result

        expected_length = spec["length"]
        if len(cleaned) != expected_length:
            result["errors"].append(
                f"wrong_length: expected {expected_length}, got {len(cleaned)}"
            )
            return result

        # Checksum ISO 7064 mod 97-10.
        numeric = _to_numeric(cleaned)
        if _mod97(numeric) != 1:
            result["errors"].append("checksum_invalid")
            return result

        # Estrutura especifica do pais.
        structure_match = re.match(spec["bban_re"], bban)
        if structure_match is None:
            result["errors"].append("bban_structure_mismatch")
        else:
            groups = {
                f"group{i+1}": g for i, g in enumerate(structure_match.groups())
            }
            result["iban_format"] = {
                "length": expected_length,
                "bban_groups": groups,
            }

        # Formatacao legivel: XX## XXXX XXXX ...
        formatted = " ".join(cleaned[i:i+4] for i in range(0, len(cleaned), 4))
        result["formatted"] = formatted

        result["valid"] = True
        return result

    @staticmethod
    def country_specs() -> Dict[str, Dict[str, Any]]:
        """Retorna a tabela de especificacoes por pais (comprimento, exemplo)."""
        return {
            country: {"length": spec["length"], "example": spec["example"]}
            for country, spec in _IBAN_SPECS.items()
        }
