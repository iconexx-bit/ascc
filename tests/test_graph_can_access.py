"""A wildcard policy reaches data stores only, and only from a principal (O49).

`can_access` came from any resource holding an Allow `*` on `*` and went to
every other node of the run: on the real output the ETL role drew 21 edges,
to security groups, instances, policies and nodes ASCC could not even type.
`*/*` says what a principal may do; the attack graph asks which data it can
reach. Now the edge goes only to nodes with a member in
`graph.DATA_STORE_TYPES`, and only from a node with a member in
`graph.PRINCIPAL_TYPES`; a `*/*` policy on anything else draws no edge and is
counted in `graph_stats.non_principal_wildcards` (emitted only when > 0).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ascc.correlate import graph as graph_module
from ascc.correlate.graph import build_graph, find_chains
from ascc.correlate.run import CorrelationRun, correlate
from ascc.export.sarif import graph_properties
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL = REPO_ROOT / "fixtures" / "leaky_data_lake_real"
INSTANCE_ARN = "arn:aws:ec2:us-east-2:123456789012:instance/i-0b861a4f57ea57684"


def _run(prowler: Path = REAL / "prowler.json") -> CorrelationRun:
    return correlate(
        [
            ProwlerParser().parse(prowler),
            TrivyParser().parse(REAL / "trivy-config.json"),
            TrivyParser().parse(REAL / "trivy-rootfs.json"),
            CheckovParser().parse(REAL / "checkov.json"),
        ]
    )


def _types(node) -> set[tuple[str, str]]:
    return {(key.service, key.resource_type) for key in node.members}


def test_can_access_reaches_only_data_stores() -> None:
    graph = build_graph(_run())
    nodes = {node.key: node for node in graph.nodes}
    targets = [edge.dst for edge in graph.edges if edge.kind == "can_access"]
    assert targets
    for dst in targets:
        assert _types(nodes[dst]) & {("s3", "bucket")}, str(dst)


def test_can_access_starts_only_at_a_principal() -> None:
    graph = build_graph(_run())
    nodes = {node.key: node for node in graph.nodes}
    sources = {edge.src for edge in graph.edges if edge.kind == "can_access"}
    assert sources
    for src in sources:
        assert _types(nodes[src]) & {("iam", "role"), ("iam", "user")}, str(src)


def test_wildcard_on_a_non_principal_draws_no_edge_and_is_counted(tmp_path: Path) -> None:
    # The same inline `*/*` policy, put on the instance instead of the role.
    entries = json.loads((REAL / "prowler.json").read_text(encoding="utf-8"))
    moved: set[str] = set()
    for entry in entries:
        for resource in entry["resources"]:
            metadata = resource["data"].get("metadata") or {}
            if resource["type"] == "AwsIamPolicy" and metadata.get("type") == "Inline":
                moved.add(resource["uid"])
                resource["uid"] = INSTANCE_ARN
    assert moved
    path = tmp_path / "prowler.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    run = _run(path)
    graph = build_graph(run)
    assert [edge for edge in graph.edges if edge.kind == "can_access"] == []
    assert find_chains(graph) == ()
    assert graph.non_principal_wildcards == 1
    assert graph_properties(run)["graph_stats"]["non_principal_wildcards"] == 1


def test_no_non_principal_count_on_real_output() -> None:
    assert "non_principal_wildcards" not in graph_properties(_run())["graph_stats"]


def test_type_tables_match_the_contract() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    for name in ("DATA_STORE_TYPES", "PRINCIPAL_TYPES"):
        match = re.search(rf"graph\.{name}: ((?:`[a-z0-9-]+:[a-z0-9-]+`(?:, )?)+)\.", text)
        assert match, f"CLAUDE.md must list graph.{name}"
        named = {tuple(item.strip("`").split(":")) for item in match.group(1).split(", ")}
        assert getattr(graph_module, name, None) == frozenset(named), name
