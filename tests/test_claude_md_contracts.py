"""CLAUDE.md contract anchors.

A deleted line is fine; a lost contract is not. Replaces the numstat-based
guard in justfile, which fired on any edit and was bypassable via env var.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REQUIRED_ANCHORS = [
    "ExitCode",
    "ASCC_LLM",
    "ASCC_NOW",
    "MAX_CONFIDENCE",
    "KEV",
    "effective_confidence",
    "observed_together",
    "{scanner}/{rule_id}",
    "--store",
    "uv run",
]


def test_claude_md_exists() -> None:
    assert Path("CLAUDE.md").is_file()


@pytest.mark.parametrize("anchor", REQUIRED_ANCHORS)
def test_contract_anchor_present(anchor: str) -> None:
    text = Path("CLAUDE.md").read_text(encoding="utf-8")
    assert anchor in text, f"CLAUDE.md lost anchor: {anchor!r}"
