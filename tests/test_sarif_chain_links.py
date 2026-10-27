"""A3-1b contract: results[] link to the chains they lie on (CLAUDE.md,
"Graph and chains (A2)", Chain links).

A result whose resource ids include a member of a chain node carries
properties.chain_ids (sorted). The rule is the A2 one -- a finding on any
member belongs to the node -- now exported instead of left to the reader.
Nothing else in results[] changes: count, order, fingerprints and every
other byte are pinned against the pre-A3-1b baseline.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ascc.correlate.run import CorrelationRun, correlate
from ascc.export.sarif import to_sarif
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser
from ascc.schema.identity import IdentityClass, MatchKey, Resolution
from ascc.schema.models import Finding, Resource, ScanRun
from ascc.schema.taxonomy import Category, Severity

# sha256 of runs[0].results of tests/data/leaky_data_lake.sarif.json at ff36192
# (before chain links), canonical JSON: sort_keys, no spaces, ensure_ascii=False.
RESULTS_BEFORE_LINKS = "dcba6e604eb790601c6e4b87d8bd1f85114116d69de818ce2618e7016b6a19f5"
UNRELATED = MatchKey("aws", "s3", "bucket", "unrelated-logs")


def _runs(fixtures_dir: Path, *, prowler: bool = True) -> list[ScanRun]:
    runs = [
        TrivyParser().parse(fixtures_dir / "trivy.json"),
        CheckovParser().parse(fixtures_dir / "checkov.json"),
    ]
    if prowler:
        runs.append(ProwlerParser().parse(fixtures_dir / "prowler.json"))
    return runs


def _results(run: CorrelationRun) -> list[dict]:
    return to_sarif(run)["runs"][0]["results"]


def _chains(run: CorrelationRun) -> list[dict]:
    return to_sarif(run)["runs"][0]["properties"]["chains"]


def _fqns(result: dict) -> set[str]:
    return {loc["logicalLocations"][0]["fullyQualifiedName"] for loc in result.get("locations", [])}


def _off_chain_scan() -> ScanRun:
    """A finding on a bucket no chain reaches: no DataClassification tag, so
    the wildcard role edge may touch it but no chain ends there."""
    finding = Finding(
        scanner="test",
        rule_id="OFF1",
        category=Category.UNCATEGORIZED,
        severity=Severity.LOW,
        title="off the chain",
        resource_ids=[str(UNRELATED)],
        resolutions=[
            Resolution(
                key=UNRELATED,
                confidence=1.0,
                method="test",
                identity_class=IdentityClass.NATURAL_NAME,
            )
        ],
    )
    return ScanRun(
        scanner="test", findings=[finding], resources={str(UNRELATED): Resource(key=UNRELATED)}
    )


def test_every_result_on_a_chain_node_carries_the_chain_id(fixtures_dir: Path) -> None:
    run = correlate(_runs(fixtures_dir))
    [chain] = _chains(run)
    members = {m for node in chain["nodes"] for m in node["members"]}
    linked = 0
    for result in _results(run):
        if _fqns(result) & members:
            assert result["properties"]["chain_ids"] == [chain["id"]], result["ruleId"]
            linked += 1
    assert linked == 16


def test_result_off_every_chain_has_no_chain_ids(fixtures_dir: Path) -> None:
    run = correlate([*_runs(fixtures_dir), _off_chain_scan()])
    [chain] = _chains(run)
    by_fqn = {next(iter(_fqns(r))): r for r in _results(run) if r["ruleId"] == "test/OFF1"}
    off = by_fqn[str(UNRELATED)]
    assert "chain_ids" not in off.get("properties", {})
    on = [r for r in _results(run) if r["ruleId"] != "test/OFF1"]
    assert all(r["properties"]["chain_ids"] == [chain["id"]] for r in on)


def test_without_prowler_no_result_carries_chain_ids(fixtures_dir: Path) -> None:
    run = correlate(_runs(fixtures_dir, prowler=False))
    assert _chains(run) == []
    assert all("chain_ids" not in r.get("properties", {}) for r in _results(run))


def test_links_change_nothing_else_in_results(fixtures_dir: Path) -> None:
    results = _results(correlate(_runs(fixtures_dir)))
    stripped = []
    for result in results:
        result = json.loads(json.dumps(result))
        props = result.get("properties", {})
        props.pop("chain_ids", None)
        if "properties" in result and not props:
            del result["properties"]
        stripped.append(result)
    canonical = json.dumps(stripped, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    assert hashlib.sha256(canonical.encode()).hexdigest() == RESULTS_BEFORE_LINKS


def test_chain_ids_by_key_maps_every_member_to_sorted_ids(fixtures_dir: Path) -> None:
    from ascc.correlate.graph import build_graph, chain_ids_by_key, find_chains

    graph = build_graph(correlate(_runs(fixtures_dir)))
    chains = find_chains(graph)
    links = chain_ids_by_key(graph, chains)
    members = {
        str(m)
        for c in chains
        for k in c.nodes
        for n in graph.nodes
        if n.key == k
        for m in n.members
    }
    assert set(links) == members and len(members) == 6
    assert all(ids == tuple(sorted(ids)) and ids == (chains[0].id,) for ids in links.values())
