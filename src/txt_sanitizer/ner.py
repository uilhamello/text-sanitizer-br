"""Optional person-name detection with spaCy. Install: pip install "txt-sanitizer[ner]".

Only person entities are masked. Location entities are ignored on purpose: the Portuguese models
tag technical words as places ("Connection", "p95"); street addresses are covered by a regex.
"""
from __future__ import annotations

DEFAULT_MODEL = "pt_core_news_sm"
PERSON_LABELS = {"PER", "PERSON"}


def load(model: str = DEFAULT_MODEL):
    import spacy  # imported here: the base package has no dependencies

    nlp = spacy.load(model)
    nlp.select_pipes(enable=[p for p in ("tok2vec", "ner") if p in nlp.pipe_names])
    return nlp


def mask_persons(nlp, text: str) -> tuple[str, int]:
    spans = [(e.start_char, e.end_char) for e in nlp(text).ents if e.label_ in PERSON_LABELS]
    for start, end in reversed(spans):  # right to left keeps the earlier offsets valid
        text = text[:start] + "<PERSON>" + text[end:]
    return text, len(spans)
