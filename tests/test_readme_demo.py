"""A3-1 contract: the README chain demo is a projection of code output.

README.md, block between BEGIN and END below (CLAUDE.md, "README demo (A3)").
Every number, key and the JSON fragment there is derived here from the golden
SARIF (tests/data/leaky_data_lake.sarif.json, pinned to the CLI by
test_cli_golden) or from one live CLI run. When the golden changes, these
tests fail with the line the README must carry instead.

Provenance is asserted, not implied: which scanner supplied the edges, which
findings reach a node only through an identity bridge, and what happens to
the chain when scanners are dropped.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from ascc.correlate.run import correlate
from ascc.export.sarif import to_sarif
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = REPO_ROOT / "tests" / "data" / "leaky_data_lake.sarif.json"
BEGIN = "<!-- readme-demo:chain -->"
END = "<!-- /readme-demo:chain -->"
LOG4SHELL = "trivy/CVE-2021-44228"


@pytest.fixture
def section() -> str:
    """The demo block, or "" when the markers are missing: every test then fails
    on its own assertion instead of erroring in setup."""
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        return ""
    return text.split(BEGIN, 1)[1].split(END, 1)[0]


@pytest.fixture(scope="module")
def run0() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))["runs"][0]


@pytest.fixture(scope="module")
def chain(run0: dict) -> dict:
    [only] = run0["properties"]["chains"]
    return only


def _fqn(result: dict) -> str:
    return result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]


def _scanner(result: dict) -> str:
    return result["ruleId"].split("/", 1)[0]


def _on_node(run0: dict, node: dict) -> list[dict]:
    members = set(node["members"])
    return [r for r in run0["results"] if _fqn(r) in members]


def _flat(text: str) -> str:
    """Prose claims are matched across the README's line wrapping."""
    return " ".join(text.split())


def _block(section: str, lang: str) -> str:
    blocks = re.findall(rf"^```{lang}\n(.*?)^```$", section, re.MULTILINE | re.DOTALL)
    assert len(blocks) == 1, f"expected one ```{lang} block in the demo, found {len(blocks)}"
    return blocks[0]


def _is_projection(part: object, whole: object, path: str = "$") -> None:
    """part keeps a subset of keys at every level; lists keep length and order."""
    if isinstance(part, dict):
        assert isinstance(whole, dict), f"{path}: README has an object, golden does not"
        for key, value in part.items():
            assert key in whole, f"{path}.{key}: not in golden"
            _is_projection(value, whole[key], f"{path}.{key}")
    elif isinstance(part, list):
        assert isinstance(whole, list) and len(part) == len(whole), f"{path}: list differs"
        for i, (p, w) in enumerate(zip(part, whole, strict=True)):
            _is_projection(p, w, f"{path}[{i}]")
    else:
        assert part == whole, f"{path}: README {part!r} != golden {whole!r}"


def _funnel(run0: dict, chain: dict) -> str:
    results = run0["results"]
    on_chain = sum(len(_on_node(run0, n)) for n in chain["nodes"])
    n = len(results)
    share = f"all {n}" if on_chain == n else f"{on_chain} of {n}"
    return (
        f"**{n} findings → {len({_fqn(r) for r in results})} resource keys → "
        f"{run0['properties']['graph_stats']['nodes']} graph nodes → "
        f"{len(run0['properties']['chains'])} chain of {chain['hops']} hops.** "
        f"The findings come from {len({_scanner(r) for r in results})} scanners, "
        f"and {share} sit on the chain's nodes."
    )


def _row(run0: dict, chain: dict, i: int) -> str:
    node = chain["nodes"][i]
    label = f"`{node['key']}`"
    if i == 0 and node["entry_findings"]:
        label += " (entry)"
    if "data_classification" in node:
        label += f" (target, `{node['data_classification']}`)"
    if i == 0:
        edge_in = "—"
    else:
        e = chain["edges"][i - 1]
        edge_in = f"`{e['kind']}` · `{e['method']}` · {e['confidence']!r}"
    counts: dict[str, int] = {}
    for r in _on_node(run0, node):
        counts[_scanner(r)] = counts.get(_scanner(r), 0) + 1
    found = " · ".join(f"{s} {c}" for s, c in sorted(counts.items()))
    return f"| {i} | {label} | {len(node['members'])} | {edge_in} | {found} |"


def _parse(fixtures_dir: Path, names: tuple[str, ...]) -> dict:
    parsers = {
        "checkov": lambda: CheckovParser().parse(fixtures_dir / "checkov.json"),
        "prowler": lambda: ProwlerParser().parse(fixtures_dir / "prowler.json"),
        "trivy": lambda: TrivyParser().parse(fixtures_dir / "trivy.json"),
    }
    sarif = to_sarif(correlate([parsers[n]() for n in names]))
    return sarif["runs"][0].get("properties", {})


def test_readme_holds_one_demo_block() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert text.count(BEGIN) == 1, f"README.md must hold exactly one {BEGIN}"
    assert text.count(END) == 1, f"README.md must hold exactly one {END}"
    assert text.index(BEGIN) < text.index(END)


def test_cli_line_matches_a_live_run(section: str, tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ascc",
            "correlate",
            "--input",
            "fixtures/leaky_data_lake",
            "--output",
            str(tmp_path / "out.sarif.json"),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    [line] = [x for x in (proc.stdout + proc.stderr).splitlines() if x.startswith("Attack chains:")]
    console = _block(section, "console")
    assert line in console.splitlines(), f"README console block must show: {line}"
    assert "uv run ascc correlate --input fixtures/leaky_data_lake/" in console


def test_funnel_matches_golden(section: str, run0: dict, chain: dict) -> None:
    expected = _funnel(run0, chain)
    assert expected in _flat(section), f"README must carry: {expected}"


def test_json_fragment_is_a_projection_of_the_golden_chain(section: str, chain: dict) -> None:
    fragment = json.loads(_block(section, "json"))
    _is_projection(fragment, chain)
    for key in ("id", "hops", "confidence", "edges"):
        assert key in fragment, f"fragment must keep {key}"
    for edge in fragment["edges"]:
        assert {"src", "kind", "dst", "method", "confidence", "source"} <= edge.keys()
    # The honesty signal must survive the trim: the wildcard edge says what it did not see.
    wildcard = [e for e in fragment["edges"] if e["method"] == "policy_wildcard"]
    assert wildcard and {"deny_check", "unobserved_layers"} <= wildcard[0]["properties"].keys()


def test_arithmetic_is_the_product_of_edge_confidences(section: str, chain: dict) -> None:
    factors = [e["confidence"] for e in chain["edges"]]
    product = 1.0
    for f in factors:
        product *= f
    assert round(product, 6) == chain["confidence"]
    line = " × ".join(repr(f) for f in factors) + f" = {chain['confidence']!r}"
    assert f"**{line}**" in _flat(section), f"README must carry: **{line}**"


def test_node_table_matches_the_golden_join(section: str, run0: dict, chain: dict) -> None:
    rows = [_row(run0, chain, i) for i in range(len(chain["nodes"]))]
    lines = section.splitlines()
    for row in rows:
        assert row in lines, f"README table must carry: {row}"
    table = [x for x in lines if re.match(r"^\| \d+ \|", x)]
    assert table == rows, "README table has rows the golden does not"


def test_edge_provenance_is_stated(section: str, chain: dict) -> None:
    sources = {e["source"] for e in chain["edges"]}
    assert sources == {"prowler"}
    assert f"All {chain['hops']} edges come from Prowler data" in _flat(section)


def test_bridged_findings_are_counted(section: str, run0: dict, chain: dict) -> None:
    bridged = [r for n in chain["nodes"] for r in _on_node(run0, n) if _fqn(r) != n["key"]]
    keys = sorted({_fqn(r) for r in bridged})
    scanners = sorted({_scanner(r) for r in bridged})
    assert scanners == ["trivy"]
    claim = f"{len(bridged)} of the {len(run0['results'])} findings reach a chain node only"
    assert claim in _flat(section), f"README must carry: {claim}"
    for key in keys:
        assert f"`{key}`" in section


def test_log4shell_sits_on_the_instance_node(section: str, run0: dict, chain: dict) -> None:
    [node] = [n for n in chain["nodes"] if n["key"].startswith("aws:ec2:instance:")]
    assert LOG4SHELL in {r["ruleId"] for r in _on_node(run0, node)}
    assert "`CVE-2021-44228`" in section


def test_dropping_scanners_is_described_truthfully(
    section: str, chain: dict, fixtures_dir: Path
) -> None:
    alone = _parse(fixtures_dir, ("prowler",))["chains"]
    assert [c["id"] for c in alone] == [chain["id"]]
    assert "Prowler's output alone yields the same chain" in _flat(section)
    assert _parse(fixtures_dir, ("checkov", "trivy"))["chains"] == []
    assert "without Prowler there is no chain" in _flat(section)


def test_sarif_links_are_counted(section: str, run0: dict, chain: dict) -> None:
    joined = {id(r) for n in chain["nodes"] for r in _on_node(run0, n)}
    linked = {
        id(r)
        for r in run0["results"]
        if chain["id"] in r.get("properties", {}).get("chain_ids", [])
    }
    assert linked == joined, "SARIF chain_ids must equal the member-key join shown in the README"
    n = len(run0["results"])
    share = f"all {n}" if len(linked) == n else f"{len(linked)} of the {n}"
    claim = (
        f"The SARIF carries the same join: {share} results carry "
        f'`properties.chain_ids` = `["{chain["id"]}"]`'
    )
    assert claim in _flat(section), f"README must carry: {claim}"
    assert "does not link" not in section


def test_roadmap_no_longer_promises_chains() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    roadmap = text.split("## Roadmap", 1)[1].split("\n## ", 1)[0]
    assert "chain" not in roadmap.lower(), "chains ship on main: move them out of the roadmap"
