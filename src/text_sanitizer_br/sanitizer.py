"""Brazilian region: documents, phone, plate, street address and the Portuguese name model.

The engine and the country-independent rules (secrets, e-mail, card, IP...) live in
text-sanitizer-core; these masks run in the core's regional slot, after secrets and e-mail and
before the generic number rules that would otherwise take pieces of a document.
"""
from __future__ import annotations

from text_sanitizer_core import CORE_MASKS_AFTER, CORE_MASKS_BEFORE, DEFAULT_BLOCKS, Region, Report  # noqa: F401
from text_sanitizer_core import Sanitizer as _CoreSanitizer

NER_MODEL = "pt_core_news_sm"

MASKS: list[tuple] = [
    # Street address: a street word, a name, a number and optional unit ("Rua X, 150, apto 42").
    ("address_br", r"(?i)\b(?:rua|r\.|avenida|av\.?|travessa|tv\.|alameda|rodovia|rod\.|estrada|praça|pça\.?)\s+"
                   r"[^\d,;\n<>]{2,60}?,?\s*(?:n[º°o]?\.?\s*)?\d{1,5}[A-Za-z]?"
                   r"(?:\s*,?\s*(?:apto?\.?|apartamento|casa|bloco|bl\.|sala|conj(?:unto)?\.?|lote)\s*[\w-]+)*",
     "<ADDRESS>"),
    ("cnpj", r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b", "<CNPJ>"),
    ("cpf", r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", "<CPF>"),
    ("rg", r"\b\d{1,2}\.\d{3}\.\d{3}-[\dXx]\b", "<RG>"),
    ("cep", r"\b\d{5}-\d{3}\b", "<CEP>"),
    ("phone_br", r"(?<!\d)(\+?55\s?)?\(?\d{2}\)?\s?9?\d{4}[-\s]\d{4}(?!\d)", "<PHONE>"),
    ("plate_br", r"(?i)\b[A-Z]{3}-?\d[A-Z0-9]\d{2}\b", "<PLATE>"),
]

# Registered as the "br" entry point in the text_sanitizers group (see pyproject.toml).
REGION = Region("br", masks=MASKS, ner_model=NER_MODEL)

# Full rule list as applied, in order: core before, Brazil, core after.
DEFAULT_MASKS: list[tuple] = [*CORE_MASKS_BEFORE, *MASKS, *CORE_MASKS_AFTER]


class Sanitizer(_CoreSanitizer):
    """Core + Brazilian rules. ner=True masks person names with the Portuguese model (extra "ner");
    without the model every call is blocked."""

    def __init__(self, extra_masks=(), extra_blocks=(), max_chars: int = 20000, entropy_threshold: float = 4.0,
                 ner: bool = False, ner_model: str = NER_MODEL):
        super().__init__(region_masks=MASKS, extra_masks=extra_masks, extra_blocks=extra_blocks, max_chars=max_chars,
                         entropy_threshold=entropy_threshold, ner_models=[ner_model] if ner else [])


_default = Sanitizer()


def sanitize(text) -> tuple[str, Report]:
    """Sanitize with the core and Brazilian rules (no person names)."""
    return _default.sanitize(text)
