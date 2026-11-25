"""Brazilian region: documents, phone, plate, street address and the Portuguese name model.

The engine and the country-independent rules (secrets, e-mail, card, IP...) live in
text-sanitizer-core; these masks run in the core's regional slot, after secrets and e-mail and
before the generic number rules that would otherwise take pieces of a document.
"""
from __future__ import annotations

import re

from text_sanitizer_core import CORE_MASKS_AFTER, CORE_MASKS_BEFORE, DEFAULT_BLOCKS, Region, Report  # noqa: F401
from text_sanitizer_core import Sanitizer as _CoreSanitizer
from text_sanitizer_core import id_after_words, login_after_words

NER_MODEL = "pt_core_news_sm"

# A capitalized name of 1-5 words, with the Portuguese connectors (da, de, do, dos, e, &).
_NAME = r"[A-ZÀ-Ý][a-zà-ÿ]+(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ý][a-zà-ÿ]+){0,4}"
_ORG_WORD = r"[A-ZÀ-Ý][\w&'.-]*"
# The model tags a lone first name after an article as ORG or LOC ("o Rodrigo reclamou"), so the
# person slot is also caught by context: a verb that only people do, or "falei com".
_HUMAN_VERBS = (r"reclamou|ligou|disse|pediu|falou|informou|avisou|solicitou|relatou|comprou|vendeu|perguntou"
                r"|comentou|mandou|escreveu|contou|explicou|arrematou|cancelou|aguarda|quer|precisa")

def _doc_after_word(m) -> str:
    """Value after a document word ("CPF 111.444.777/35"): masked when it has enough digits for that document."""
    if len(re.sub(r"\D", "", m.group("v"))) < 7:
        return m.group(0)
    word = m.group("d").lower()
    return f"{m.group('k')}<{word.upper() if word in ('cpf', 'cnpj', 'rg', 'cep') else 'PHONE'}>"


# Words that make a capitalized sequence a business name ("Auto Exemplo Veículos", "Silva Imóveis").
# Generic words (Serviços, Indústria) stay out: "Google Cloud Serviços" is a product, not a client.
_BIZ_WORD = (r"Ve[ií]culos|Autom[oó]veis|Motors|Multimarcas|Seminovos|Autos|Im[oó]veis|Distribuidora|Transportes"
             r"|Representa[cç][oõ]es")
_EMPTY_PT = r"(?!(?:null|none|vazio|inv[aá]lid[oa]|n[aã]o|desconhecid[oa]|nenhum)\b)"
_SIGN_OFF = r"att|atenciosamente|abs|abra[cç]os?|obrigad[oa]|grat[oa]|cumprimentos|regards|thanks"

# Subset of _HUMAN_VERBS safe at the start of a line: tools also "avisam", "informam", "querem".
_START_VERBS = r"reclamou|ligou|disse|pediu|falou|solicitou|perguntou|comentou|contou|explicou|arrematou"

_DOC_WORDS = r"cpf|cnpj|rg|cep|tel(?:efone)?|cel(?:ular)?|fone|whats(?:app)?|zap|contato"

MASKS: list[tuple] = [
    # Any separator after a document word: the word says what it is, so the layout does not matter.
    ("doc_word", r"(?i)\b(?P<k>(?P<d>" + _DOC_WORDS + r")\s*(?:n[º°o]\.?)?\s*[:=]?\s*)(?P<v>\+?\(?\d[\d .\-/()]{5,22}\d)",
     _doc_after_word),
    ("plate_word", r"(?i)\b(?P<k>placa\s*[:=]?\s*)[A-Z]{3}[\s.\-]?\d[A-Z0-9]\d{2}\b", r"\g<k><PLATE>"),
    # Value after an address key ("endereço: Flores, 150 - Centro"): the key says it is an address.
    ("address_key", r"(?i)\b(?P<k>endere[cç]o|logradouro)(?P<sep>\s*:\s*)" + _EMPTY_PT + r"(?!\d{1,3}(?:\.\d{1,3}){3})[^\s\"|;][^\n\"|;]{2,80}",
     r"\g<k>\g<sep><ADDRESS>"),
    # Street address: a street word, a name, a number and optional unit ("Rua X, 150, apto 42").
    ("address_br", r"(?i)\b(?:rua|r\.|avenida|av\.?|travessa|tv\.|alameda|rodovia|rod\.|estrada|praça|pça\.?)\s+"
                   r"(?:\d{1,2}\s+de\s+)?[^\d,;\n<>]{2,60}?,?\s*(?:n[º°o]?\.?\s*)?(?:\d{1,5}[A-Za-z]?|s/?n\b)"
                   r"(?:\s*,?\s*(?:apto?\.?|apartamento|casa|bloco|bl\.|sala|conj(?:unto)?\.?|lote)\s*[\w-]+)*",
     "<ADDRESS>"),
    ("cnpj", r"\b\d{2}[.\s]?\d{3}[.\s]?\d{3}[/.\s]?\d{4}[-\s]?\d{2}\b", "<CNPJ>"),
    ("cpf", r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", "<CPF>"),
    ("cpf_spaced", r"\b\d{3}[-.\s]\d{3}[-.\s]\d{3}[-.\s]\d{2}\b", "<CPF>"),
    ("rg", r"\b\d{1,2}[.\s]\d{3}[.\s]\d{3}[-\s][\dXx]\b", "<RG>"),
    ("cep", r"\b\d{5}-\d{3}\b", "<CEP>"),
    ("cep_dotted", r"\b\d{2}\.\d{3}-\d{3}\b", "<CEP>"),
    ("cep_word", r"(?i)\b(?P<k>cep\s*:?\s*)\d{5}[\s.]?\d{3}\b", r"\g<k><CEP>"),
    ("phone_br", r"(?<!\d)(\+?55\s?)?\(?\d{2}\)?\s?(?:9\s?)?\d{4}[-\s]\d{4}(?!\d)", "<PHONE>"),
    # Mobile without area code: 9XXXX-XXXX.
    ("mobile_br", r"(?<![\d.\-])9\d{4}-\d{4}(?![\d\-])", "<PHONE>"),
    ("plate_br", r"(?i)\b[A-Z]{3}-?\d[A-Z0-9]\d{2}\b", "<PLATE>"),
    # With a space only in capitals: "ABC 1D23" (in lower case, "por 2024" would match).
    ("plate_br_spaced", r"\b[A-Z]{3}\s\d[A-Z0-9]\d{2}\b", "<PLATE>"),
    ("company_suffix", r"\b(?:" + _ORG_WORD + r"\s+(?:(?:d[aeo]s?|e|&)\s+)?){1,5}(?:Ltda\.?|LTDA|S\.A\.|S/A|EIRELI|Eireli|EPP)(?!\w)",
     "<ORG>"),
    # Two or more capitalized words ending in a business word, or "X Comércio de Y".
    ("company_biz", r"\b(?!(?:API|M[oó]dulo|Tela|Painel|Menu|Relat[oó]rio|Cadastro|Busca|Lista|Tabela|Gest[aã]o"
                    r"|Servi[cç]o|Sistema)\b)(?:" + _ORG_WORD + r"\s+){2,4}(?:" + _BIZ_WORD + r")\b", "<ORG>"),
    # ME/MEI only after Title-case words ("Auto Exemplo ME"), so "DEPLOY ME" stays.
    ("company_me", r"\b(?:[A-ZÀ-Ý][a-zà-ÿ][\w&'.-]*\s+){1,5}MEI?\b", "<ORG>"),
    ("company_trade", r"\b(?:" + _ORG_WORD + r"\s+){1,4}Com[eé]rcio\s+(?:d[aeo]s?\s+)?" + _ORG_WORD, "<ORG>"),
    ("store_name", r"\b(?P<w>(?i:loja|concession[aá]ria|revenda|empresa|filial|garagem)\s*:?\s+)" + _ORG_WORD
                   + r"(?:\s+(?:(?:d[aeo]s?|e|&)\s+)?" + _ORG_WORD + r"){0,4}", r"\g<w><ORG>"),
    ("person_title", r"\b(?P<t>(?:Sr|Sra|Srta|Dr|Dra)\.?\s+)" + _NAME, r"\g<t><PERSON>"),
    ("person_talk", r"(?P<v>\b(?i:falei|falou|conversei|conversou|liguei|ligou|avisei|avisou|atendi|atendeu)\s+"
                    r"(?i:com|para|pra|a|o)\s+(?:(?i:o|a)\s+)?)" + _NAME, r"\g<v><PERSON>"),
    # Name after a role with a colon ("Atendente: Rosângela") or in a JSON name field.
    ("person_role", r"(?P<k>\b(?i:atendente|vendedor[a]?|comprador[a]?|respons[aá]vel|solicitante|nome|contato"
                    r"|assinado|cliente|analista|operador[a]?)\s*:\s*)" + _NAME, r"\g<k><PERSON>"),
    ("person_json", r"(?P<k>(?i:\"(?:nome|nome_completo|full_name|first_name|last_name|respons[aá]vel|atendente"
                    r"|vendedor|comprador|cliente)\"\s*:\s*\"))" + _EMPTY_PT + r"[^\"\d@]{2,80}(?=\")", r"\g<k><PERSON>"),
    # Name after a greeting, closed by punctuation or end of line ("Prezado Fulano,", "Oi Fulano, tudo bem").
    ("person_greeting", r"(?P<k>\b(?i:prezad[oa]s?|oi|ol[aá]|bom\s+dia|boa\s+tarde|boa\s+noite|car[oa]|hi|hello|dear)"
                        r",?\s+)(?!(?i:mundo|world|sir|madam|senhor(?:a|es)?|todos|todas|pessoal|equipe|time|team|all|everyone)\b)"
                        + _NAME + r"(?=\s*(?:[,!.:]|$))", r"\g<k><PERSON>"),
    # Name at the start of a line before a verb only people do ("Fulana ligou ontem").
    ("person_line_start", r"(?m)^" + _NAME + r"(?=\s+(?i:" + _START_VERBS + r")\b)", "<PERSON>"),
    # Surname before a masked first name ("Silva, <PERSON>").
    ("person_surname", r"(?m)^[A-ZÀ-Ý][a-zà-ÿ]+(?=,\s*<PERSON>)", "<PERSON>"),
    # Name after a sign-off ("Att, Carlos").
    ("person_signoff", r"(?P<k>\b(?i:" + _SIGN_OFF + r")[,.!]?\s+)" + _NAME + r"(?=\s*(?:$|[\n.!]))",
     r"\g<k><PERSON>"),
    ("person_subject", r"(?P<a>\b(?i:o|a|cliente|vendedor[a]?|comprador[a]?|atendente|usu[aá]ri[oa])\s+)" + _NAME + r"(?=\s+(?i:" + _HUMAN_VERBS + r")\b)", r"\g<a><PERSON>"),
    login_after_words(r"usu[aá]rio|login"),
    id_after_words(r"usu[aá]ri[oa]|cliente|loja|pedido|anunciante|participante|avalia[cç](?:[aã]o|[oõ]es)|ve[ií]culo"
                   r"|lote|leil[aã]o|vendedor|comprador|revenda|concession[aá]ria|empresa"),
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
