"""text-sanitizer-br — Brazilian region for text-sanitizer-core: masks PII and secrets in free text."""
__version__ = "0.2.0"

from .sanitizer import DEFAULT_BLOCKS, DEFAULT_MASKS, MASKS, NER_MODEL, REGION, Report, Sanitizer, sanitize  # noqa: E402

__all__ = ["Sanitizer", "Report", "sanitize", "REGION", "MASKS", "NER_MODEL", "DEFAULT_MASKS", "DEFAULT_BLOCKS",
           "__version__"]
