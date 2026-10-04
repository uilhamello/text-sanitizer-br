"""text-sanitizer-br — masks PII and secrets in free text; blocks when something risky survives."""
__version__ = "0.1.0"

from .sanitizer import DEFAULT_BLOCKS, DEFAULT_MASKS, Report, Sanitizer, sanitize  # noqa: E402

__all__ = ["Sanitizer", "Report", "sanitize", "DEFAULT_MASKS", "DEFAULT_BLOCKS", "__version__"]
