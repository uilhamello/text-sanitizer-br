"""CLI: txt-sanitizer [--ner] [--max-chars N]. Text on stdin, sanitized text on stdout.

The report (masks, blocked) goes to stderr. Exit codes: 0 ok · 2 blocked (stdout is empty).
Offline: nothing leaves the machine.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .sanitizer import Sanitizer


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="txt-sanitizer", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--ner", action="store_true", help='also mask person names (needs "txt-sanitizer[ner]")')
    ap.add_argument("--max-chars", type=int, default=20000)
    args = ap.parse_args(argv)

    clean, report = Sanitizer(max_chars=args.max_chars, ner=args.ner).sanitize(sys.stdin.read())
    if report.ok:
        print(clean, end="")
    print(json.dumps({"masks": report.masks, "blocked": report.blocked}), file=sys.stderr)
    return 0 if report.ok else 2


if __name__ == "__main__":
    sys.exit(main())
