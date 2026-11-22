"""A3-AI contract: CLAUDE.md carries the AI layer contract before any LLM code.

The contract is written first (CLAUDE.md, "AI layer (A3-AI)"): one write
surface for model output, an off switch that keeps the SARIF byte-identical,
prompt hygiene for scanner-controlled strings, a confinement test with a
compromised model, a deterministic output filter, live evidence on two
models, the corpus rule, the wording a public claim may use and where the
narrator lives. The operator decisions of 2026-11-17 are contract, not an
open list: off when ASCC_LLM is unset, drop the whole text on a filter
violation, two named models with n = 5, a separate package. A deleted
line is fine; a lost rule is not: each rule is pinned by its id and by the
terms that carry its meaning.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HEADING = "## AI layer (A3-AI)"
GATE = "tests/test_claude_md_ai_layer.py"

RULE_TERMS = {
    "AI-1": ("message.markdown", "never touches edges or chains"),
    "AI-2": ("ASCC_LLM=off", "byte-identical", "unset means off", "configuration error"),
    "AI-3": ("data delimiters", "data-not-commands"),
    "AI-4": ("stub model", "severity", "confidence", "identity"),
    "AI-5": ("deterministic filter", "URLs", "images", "HTML", "whole text", "stderr"),
    "AI-6": ("small model", "qwen-2.5-7b", "robust", "n = 5", "resolved"),
    "AI-7": ("RASRL", "not committed"),
    "AI-8": ("authoritative field", "resistant to prompt injection"),
    "AI-9": ("install extra", "never imports", "finding id"),
}

MOVED_FROM_BACKLOG = (
    "delimit scanner-controlled strings in LLM prompts (XML tags",
    "CANNOT alter severity/confidence/identity (only message.markdown reachable)",
)


def _claude_md() -> str:
    return (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def ai_layer_section(text: str) -> str:
    """The body of the AI layer section; "" when the section is absent."""
    marker = f"\n{HEADING}\n"
    if marker not in text:
        return ""
    return text.split(marker, 1)[1].split("\n## ", 1)[0]


def ai_layer_rules(text: str) -> dict[str, list[str]]:
    """Rule id -> the flattened bullets that carry it, in file order."""
    parts = re.split(r"^- (AI-\d+) ", ai_layer_section(text), flags=re.MULTILINE)
    rules: dict[str, list[str]] = {}
    for rule_id, body in zip(parts[1::2], parts[2::2], strict=True):
        bullet = body.split("\n\n", 1)[0]
        rules.setdefault(rule_id, []).append(_flat(bullet))
    return rules


def test_ai_layer_section_is_present_once_and_names_its_gate() -> None:
    text = _claude_md()
    assert text.count(f"\n{HEADING}\n") == 1
    assert GATE in ai_layer_section(text)


def test_ai_layer_rules_are_exactly_the_contracted_ids() -> None:
    rules = ai_layer_rules(_claude_md())
    assert list(rules) == list(RULE_TERMS)
    assert {rule_id: len(bullets) for rule_id, bullets in rules.items()} == dict.fromkeys(
        RULE_TERMS, 1
    )


@pytest.mark.parametrize("rule_id", list(RULE_TERMS))
def test_ai_layer_rule_keeps_its_terms(rule_id: str) -> None:
    bullets = ai_layer_rules(_claude_md()).get(rule_id, [])
    assert len(bullets) == 1, f"{rule_id}: expected one bullet, found {len(bullets)}"
    missing = [term for term in RULE_TERMS[rule_id] if term not in bullets[0]]
    assert not missing, f"{rule_id} lost its terms: {missing}"


def test_backlog_no_longer_carries_what_became_contract() -> None:
    flat = _flat(_claude_md())
    left = [intent for intent in MOVED_FROM_BACKLOG if intent in flat]
    assert not left, f"still worded as a backlog intent: {left}"


def test_ai_layer_has_no_pending_operator_decisions() -> None:
    section = _flat(ai_layer_section(_claude_md()))
    assert "not yet contract" not in section
    assert "Open decisions: none." in section
