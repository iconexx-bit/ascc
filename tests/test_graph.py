"""A2 contract: the attack graph and its chains (CLAUDE.md, "Graph and chains").

Built on fixtures/leaky_data_lake. The scenario's chain is SG -> EC2 -> IAM role
-> S3: three edges, one per method, product confidence 1.0 x 0.6 x 1.0 = 0.6.
Edges come only from scanner data (Finding.raw); a missing link is a missing
edge, never an invented one. The graph module is imported inside each test so
that, while it is missing, the tests fail one by one instead of erroring
collection.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ascc.correlate.run import CorrelationRun, correlate
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser
from ascc.schema.models import ScanRun

REPO_ROOT = Path(__file__).resolve().parents[1]
SG = "aws:ec2:security-group:sg-0f9e8d7c6b5a43210"
INSTANCE = "aws:ec2:instance:i-0a1b2c3d4e5f67890"
ROLE = "aws:iam:role:datalake-etl-role"
BUCKET = "aws:s3:bucket:datalake-raw"


def _runs(
    fixtures_dir: Path, prowler_doc: list | None = None, tmp: Path | None = None
) -> list[ScanRun]:
    runs = [
        TrivyParser().parse(fixtures_dir / "trivy.json"),
        CheckovParser().parse(fixtures_dir / "checkov.json"),
    ]
    if prowler_doc is None:
        runs.append(ProwlerParser().parse(fixtures_dir / "prowler.json"))
    elif prowler_doc:
        path = tmp / "prowler.json"
        path.write_text(json.dumps(prowler_doc), encoding="utf-8")
        runs.append(ProwlerParser().parse(path))
    return runs


@pytest.fixture(scope="module")
def fixture_run(fixtures_dir: Path) -> CorrelationRun:
    return correlate(_runs(fixtures_dir))


def _node_of(graph, key: str):
    [node] = [n for n in graph.nodes if key in {str(k) for k in n.members}]
    return node


def _edges(graph, kind: str):
    return [e for e in graph.edges if e.kind == kind]


def test_fixture_graph_has_the_three_attack_edges(fixture_run: CorrelationRun) -> None:
    from ascc.correlate.graph import build_graph

    g = build_graph(fixture_run)
    sg, inst, role, bucket = (_node_of(g, k) for k in (SG, INSTANCE, ROLE, BUCKET))

    [exposes] = _edges(g, "exposes")
    assert (exposes.src, exposes.dst, exposes.method, exposes.confidence) == (
        sg.key,
        inst.key,
        "attached_security_group",
        1.0,
    )
    [assumes] = _edges(g, "assumes")
    assert (assumes.src, assumes.dst, assumes.method, assumes.confidence) == (
        inst.key,
        role.key,
        "profile_role_name",
        0.6,
    )
    [to_bucket] = [e for e in _edges(g, "can_access") if e.dst == bucket.key]
    assert (to_bucket.src, to_bucket.method, to_bucket.confidence) == (
        role.key,
        "policy_wildcard",
        1.0,
    )
    props = dict(to_bucket.properties)
    assert props["deny_check"] == "not_observed"
    assert props["unobserved_layers"] == ("bucket_policy", "permissions_boundary", "rcp", "scp")
    assert all(e.src != e.dst for e in g.edges)
    assert g.dropped_edges == 0


def test_nodes_are_clusters_not_raw_keys(fixture_run: CorrelationRun) -> None:
    """The Trivy SG name and the Prowler SG id are one node; its key is the
    derived representative, and a finding on either member belongs to it."""
    from ascc.correlate.graph import build_graph

    g = build_graph(fixture_run)
    sg = _node_of(g, SG)
    assert "aws:ec2:security-group:datalake-etl-sg" in {str(k) for k in sg.members}
    [cluster] = [c for c in fixture_run.clusters if sg.key in c.keys]
    assert sg.key == cluster.representative()
    assert {"trivy:AVD-AWS-0107"} <= set(sg.entry_findings)
    assert _node_of(g, BUCKET).tags.get("DataClassification") == "PII"
    assert _node_of(g, ROLE).accounts == frozenset({"123456789012"})


def test_fixture_yields_one_chain_of_three_hops(fixture_run: CorrelationRun) -> None:
    from ascc.correlate.graph import build_graph, find_chains

    g = build_graph(fixture_run)
    [chain] = find_chains(g)
    expected = tuple(_node_of(g, k).key for k in (SG, INSTANCE, ROLE, BUCKET))
    assert chain.nodes == expected
    assert [e.kind for e in chain.edges] == ["exposes", "assumes", "can_access"]
    assert chain.confidence == pytest.approx(0.6)
    assert chain.id.startswith("chain-") and len(chain.id) == len("chain-") + 12


def test_without_prowler_there_are_no_edges_and_no_chains(fixtures_dir: Path) -> None:
    """Trivy and Checkov carry no cross-resource references: nothing to draw."""
    from ascc.correlate.graph import build_graph, find_chains

    g = build_graph(correlate(_runs(fixtures_dir, prowler_doc=[])))
    assert g.edges == ()
    assert find_chains(g) == ()


def test_role_name_mismatch_breaks_the_chain(fixtures_dir: Path, tmp_path: Path) -> None:
    """Mutation of the heuristic edge: the instance profile no longer shares the
    role's name, so no role is assumed, the reference is dropped, no chain."""
    from ascc.correlate.graph import build_graph, find_chains

    doc = json.loads((fixtures_dir / "prowler.json").read_text(encoding="utf-8"))
    doc = copy.deepcopy(doc)
    hits = 0
    for entry in doc:
        for res in entry["resources"]:
            data = res.get("data") or {}
            if "iam_instance_profile_arn" in data:
                data["iam_instance_profile_arn"] = data["iam_instance_profile_arn"].replace(
                    "datalake-etl-role", "other-profile"
                )
                hits += 1
    assert hits == 1
    g = build_graph(correlate(_runs(fixtures_dir, prowler_doc=doc, tmp=tmp_path)))
    assert _edges(g, "assumes") == []
    assert g.dropped_edges == 1
    assert find_chains(g) == ()


def test_wildcard_never_crosses_a_known_account_boundary(
    fixtures_dir: Path, tmp_path: Path
) -> None:
    """A bucket observed in another account gets no can_access edge."""
    from ascc.correlate.graph import build_graph, find_chains

    doc = json.loads((fixtures_dir / "prowler.json").read_text(encoding="utf-8"))
    for entry in doc:
        if any(r["uid"] == "arn:aws:s3:::datalake-raw" for r in entry["resources"]):
            entry["cloud"]["account"]["uid"] = "999999999999"
    g = build_graph(correlate(_runs(fixtures_dir, prowler_doc=doc, tmp=tmp_path)))
    bucket = _node_of(g, BUCKET)
    assert [e for e in _edges(g, "can_access") if e.dst == bucket.key] == []
    assert find_chains(g) == ()


def test_chains_identical_across_hash_seeds() -> None:
    code = (
        "from pathlib import Path\n"
        "from ascc.correlate.run import correlate\n"
        "from ascc.correlate.graph import build_graph, find_chains\n"
        "from ascc.ingest.checkov import CheckovParser\n"
        "from ascc.ingest.prowler import ProwlerParser\n"
        "from ascc.ingest.trivy import TrivyParser\n"
        "d = Path('fixtures/leaky_data_lake')\n"
        "runs = [ProwlerParser().parse(d / 'prowler.json'), TrivyParser().parse(d / 'trivy.json'),"
        " CheckovParser().parse(d / 'checkov.json')]\n"
        "g = build_graph(correlate(runs))\n"
        "print(repr(g.edges)); print(repr(find_chains(g)))\n"
    )
    outs = []
    for seed in ("0", "1", "4242"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        r = subprocess.run(
            [sys.executable, "-c", code],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert r.returncode == 0, r.stderr
        outs.append(r.stdout)
    assert outs[0] == outs[1] == outs[2]
    assert "chain-" in outs[0]


def test_graph_module_is_stdlib_and_core_only() -> None:
    """No NetworkX, no extras: the graph is part of the deterministic core."""
    import ast

    tree = ast.parse((REPO_ROOT / "src/ascc/correlate/graph.py").read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add(node.module.split(".")[0])
    assert roots <= set(sys.stdlib_module_names) | {"ascc"}, roots


def _mutated(fixtures_dir: Path, tmp_path: Path, mutate) -> CorrelationRun:
    doc = json.loads((fixtures_dir / "prowler.json").read_text(encoding="utf-8"))
    assert mutate(doc) == 1
    return correlate(_runs(fixtures_dir, prowler_doc=doc, tmp=tmp_path))


def test_profile_in_another_account_assumes_nothing(fixtures_dir: Path, tmp_path: Path) -> None:
    """Same name, different account: the heuristic must not cross accounts."""
    from ascc.correlate.graph import build_graph

    def mutate(doc) -> int:
        n = 0
        for entry in doc:
            for res in entry["resources"]:
                data = res.get("data") or {}
                if "iam_instance_profile_arn" in data:
                    data["iam_instance_profile_arn"] = data["iam_instance_profile_arn"].replace(
                        "123456789012", "999999999999"
                    )
                    n += 1
        return n

    g = build_graph(_mutated(fixtures_dir, tmp_path, mutate))
    assert _edges(g, "assumes") == []
    assert g.dropped_edges == 1


def test_wildcard_needs_both_action_and_resource_star(fixtures_dir: Path, tmp_path: Path) -> None:
    """Action:* on a scoped Resource is not access to everything."""
    from ascc.correlate.graph import build_graph

    def mutate(doc) -> int:
        n = 0
        for entry in doc:
            for res in entry["resources"]:
                data = res.get("data") or {}
                if data.get("inline_policy_resources") == ["*"]:
                    data["inline_policy_resources"] = ["arn:aws:s3:::other-bucket/*"]
                    n += 1
        return n

    g = build_graph(_mutated(fixtures_dir, tmp_path, mutate))
    assert _edges(g, "can_access") == []
