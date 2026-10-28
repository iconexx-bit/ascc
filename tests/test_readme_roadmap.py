"""A3-4 contract: the README roadmap names the next step for runtime evidence.

While the containment lab's binding is declared (ClabParser accepts only
operator_declared), the README roadmap carries exactly one item for the
AWS-signed binding (EC2 instance identity document) and the runtime-evidence
section points to it. The PR that ships a signed binding method removes the
item in the same change (CLAUDE.md, "Runtime evidence (A3)").
"""

from __future__ import annotations

import re
from pathlib import Path

from ascc.ingest import clab
from ascc.store.policy import MAX_CONFIDENCE

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_END = "<!-- /readme-demo:evidence -->"
MARK = "instance identity document"


def _readme() -> str:
    return (REPO_ROOT / "README.md").read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _roadmap_items(text: str) -> list[str]:
    if "\n## Roadmap\n" not in text:
        return []
    roadmap = text.split("\n## Roadmap\n", 1)[1].split("\n## ", 1)[0]
    return [_flat(item) for item in re.split(r"^- ", roadmap, flags=re.MULTILINE)[1:]]


def roadmap_problems(text: str, binding_method: str) -> list[str]:
    """What is wrong with the roadmap for this binding method; [] when it is current."""
    items = [item for item in _roadmap_items(text) if MARK in item]
    if binding_method != "operator_declared":
        return ["the binding is no longer declared: remove the roadmap item"] if items else []
    if len(items) != 1:
        return [f"expected one roadmap item naming the {MARK}, found {len(items)}"]
    [item] = items
    needed = ["AWS-signed", "`operator_declared`", f"({MAX_CONFIDENCE['operator_declared']})"]
    problems = [f"roadmap item lacks {word!r}" for word in needed if word not in item]
    if "observed" in item.lower():
        problems.append("roadmap item must not call the binding observed")
    return problems


def test_roadmap_names_the_aws_signed_binding() -> None:
    assert roadmap_problems(_readme(), clab.BINDING_METHOD) == []


def test_roadmap_item_leaves_with_the_declared_binding() -> None:
    """The guard that keeps the roadmap honest after the signed binding ships."""
    assert roadmap_problems(_readme(), "aws_identity_document") == [
        "the binding is no longer declared: remove the roadmap item"
    ]


def test_runtime_evidence_section_points_to_the_roadmap() -> None:
    text = _readme()
    assert text.count(EVIDENCE_END) == 1
    tail = _flat(text.split(EVIDENCE_END, 1)[1].split("\n## ", 1)[0])
    assert "AWS-signed binding" in tail
    assert "](#roadmap)" in tail
    assert "observed" not in tail.lower()
