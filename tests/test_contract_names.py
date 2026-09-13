"""Names written in the docs must exist in the package.

`IdentityBridge` sat in README's module map for weeks and never existed in
src/ascc (verified 2026-09-13). This test turns that class of drift into a red
CI run: every backticked CamelCase name or dotted ascc path in CLAUDE.md and
README.md must appear somewhere under src/.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).parents[1]
DOCS = ("CLAUDE.md", "README.md")

# Backticked CamelCase identifiers (`BridgeFact`) and dotted ascc paths
# (`ascc.correlate.bridge`). Flags, shell snippets and ALL-CAPS acronyms in
# backticks match neither shape.
_NAME = re.compile(r"`(ascc(?:\.[a-z_][a-z0-9_]*)+|[A-Z][A-Za-z0-9]*[a-z][A-Za-z0-9]*)`")

# Backticked CamelCase that is deliberately not ascc code: external tools,
# third-party classes, prose. Triaged once; add a reason when you extend it.
_ALLOWED_ABSENT: frozenset[str] = frozenset(
    {
        # fill from the first run
    }
)


def _source_text() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "src").rglob("*.py"))


def test_documented_names_exist_in_source():
    source = _source_text()
    missing: dict[str, list[str]] = {}
    for doc in DOCS:
        path = ROOT / doc
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for name in sorted(set(_NAME.findall(text))):
            leaf = name.rsplit(".", 1)[-1]
            if leaf in _ALLOWED_ABSENT or leaf in source:
                continue
            missing.setdefault(doc, []).append(name)
    assert not missing, f"documented names absent from src/: {missing}"
