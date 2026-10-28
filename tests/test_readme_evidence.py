"""A3-I4 contract: the README's runtime-evidence block is a projection of code output.

README.md, block between BEGIN and END (CLAUDE.md, "Runtime evidence (A3)").
Every row, count and claim there is derived here from the golden
tests/data/leaky_data_lake_contained.sarif.json (pinned to the CLI by
tests/test_clab.py), from one live CLI run, or from the fixture's provenance
README. The binding is said to be declared, never observed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = REPO_ROOT / "tests" / "data" / "leaky_data_lake_contained.sarif.json"
BASE_GOLDEN = REPO_ROOT / "tests" / "data" / "leaky_data_lake.sarif.json"
FIXTURE_README = REPO_ROOT / "fixtures" / "leaky_data_lake_contained" / "README.md"
BEGIN = "<!-- readme-demo:evidence -->"
END = "<!-- /readme-demo:evidence -->"


@pytest.fixture
def section() -> str:
    """The block, or "" when the markers are missing: each test then fails on its own."""
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        return ""
    return text.split(BEGIN, 1)[1].split(END, 1)[0]


@pytest.fixture(scope="module")
def run0() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))["runs"][0]


@pytest.fixture(scope="module")
def node(run0: dict) -> dict:
    [chain] = run0["properties"]["chains"]
    [with_evidence] = [n for n in chain["nodes"] if n.get("evidence")]
    return with_evidence


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_readme_holds_one_evidence_block() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert text.count(BEGIN) == 1 and text.count(END) == 1
    assert text.index(BEGIN) < text.index(END)


def test_cli_lines_match_a_live_run(section: str, tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ascc",
            "correlate",
            "--input",
            "fixtures/leaky_data_lake_contained",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=dict(os.environ, ASCC_CONSOLE_WIDTH="200"),
        check=True,
    )
    lines = proc.stdout.splitlines()
    wanted = [x for x in lines if x.startswith(("Attack chains:", "Runtime evidence:"))]
    assert len(wanted) == 2
    for line in wanted:
        assert line in section.splitlines(), f"README console block must show: {line}"
    assert "uv run ascc correlate --input fixtures/leaky_data_lake_contained/" in section


def test_table_rows_are_the_golden_evidence(section: str, node: dict) -> None:
    rows = [
        f"| `{e['rule_id']}` | {e['control']} | {e['status']} | "
        f"{e['message'].split(' — ', 1)[-1]} |"
        for e in node["evidence"]
    ]
    table = [x for x in section.splitlines() if x.startswith("| `CLAB-")]
    assert table == rows, "README table must equal the evidence on the golden chain node"
    assert f"`{node['key']}`" in section


def test_results_and_chain_are_unchanged_by_evidence(section: str, run0: dict) -> None:
    base = json.loads(BASE_GOLDEN.read_text(encoding="utf-8"))["runs"][0]
    assert run0["results"] == base["results"]
    [chain], [base_chain] = run0["properties"]["chains"], base["properties"]["chains"]
    assert (chain["id"], chain["confidence"]) == (base_chain["id"], base_chain["confidence"])
    claim = (
        f"The SARIF still carries {len(run0['results'])} results, and the chain, its edges "
        f"and its {chain['confidence']!r} confidence are unchanged."
    )
    assert claim in _flat(section), f"README must carry: {claim}"


def test_binding_is_said_to_be_declared(section: str, node: dict) -> None:
    [binding] = {json.dumps(e["binding"], sort_keys=True) for e in node["evidence"]}
    binding = json.loads(binding)
    flat = _flat(section)
    assert "The binding is declared, not observed." in flat
    assert f"(`{binding['method']}`, confidence {binding['confidence']!r})" in flat
    assert "local Docker range" in flat
    assert "observed by" not in flat and "lab observed" not in flat


def test_provenance_is_the_fixture_readme(section: str, node: dict) -> None:
    provenance = FIXTURE_README.read_text(encoding="utf-8")
    flat = _flat(section)
    [ts] = {e["provenance"]["probe_ts"] for e in node["evidence"]}
    assert f"probe at {ts}" in flat and ts in provenance
    commit = re.search(r"lab commit `([0-9a-f]{7})`", flat)
    assert commit and f"`{commit.group(1)}`" in provenance
    [ttc] = [e["message"] for e in node["evidence"] if e["rule_id"] == "CLAB-TTC-001"]
    median = re.search(r"TTC median (\d+) ms", ttc).group(1)
    n = re.search(r"; \d+ of (\d+) cycles", ttc).group(1)
    assert f"TTC median {median} ms over {n} cycles" in flat


def test_confidence_table_lists_the_declared_binding() -> None:
    from ascc.store.policy import MAX_CONFIDENCE

    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    row = f"| {MAX_CONFIDENCE['operator_declared']} | `operator_declared` |"
    assert row in text, f"README confidence table must carry: {row}"


def test_intro_names_the_lab_as_a_source() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    intro = text.split("\n## ", 1)[0]
    assert "](https://github.com/iconexx-bit/ai-agent-containment-lab)" in intro
