from __future__ import annotations

from .base import ScannerParser
from .prowler import ProwlerParser
from .trivy import TrivyParser

PARSERS: tuple[type[ScannerParser], ...] = (TrivyParser, ProwlerParser)


def parser_for(data: dict | list) -> type[ScannerParser] | None:
    matches = [p for p in PARSERS if p.sniff(data)]
    if len(matches) > 1:
        names = ", ".join(p.__name__ for p in matches)
        raise ValueError(f"ambiguous scanner format: matched by {names}")
    return matches[0] if matches else None
