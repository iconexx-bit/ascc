"""A2-2 contract: chains in SARIF (CLAUDE.md, "Graph and chains (A2)", Export).

Chains go to runs[0].properties.chains, graph totals to
runs[0].properties.graph_stats. Only edges that lie on a reported chain are
exported; results[] is never extended. Byte determinism across PYTHONHASHSEED
is covered by tests/test_cli_determinism.py, which now hashes these properties
too; the golden baseline pins the exact bytes.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from ascc.correlate.run import CorrelationRun, correlate
from ascc.export.sarif import to_sarif
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser

REPO_ROOT = Path(__file__).resolve().parents[1]
SG = "aws:ec2:security-group:sg-0f9e8d7c6b5a43210"
INSTANCE = "aws:ec2:instance:i-0a1b2c3d4e5f67890"
ROLE = "aws:iam:role:datalake-etl-role"
BUCKET = "aws:s3:bucket:datalake-raw"


def _run(fixtures_dir: Path, *, prowler: bool = True) -> CorrelationRun:
    runs = [
        TrivyParser().parse(fixtures_dir / "trivy.json"),
        CheckovParser().parse(fixtures_dir / "checkov.json"),
    ]
    if prowler:
        runs.append(ProwlerParser().parse(fixtures_dir / "prowler.json"))
    return correlate(runs)


def _properties(run: CorrelationRun) -> dict:
    return to_sarif(run)["runs"][0].get("properties", {})


@pytest.fixture(scope="module")
def fixture_props(fixtures_dir: Path) -> dict:
    return _properties(_run(fixtures_dir))


def test_fixture_sarif_carries_one_three_hop_chain(fixture_props: dict) -> None:
    [chain] = fixture_props["chains"]
    assert chain["id"].startswith("chain-") and len(chain["id"]) == len("chain-") + 12
    assert chain["hops"] == 3
    assert chain["confidence"] == 0.6
    assert [n["key"] for n in chain["nodes"]] == [SG, INSTANCE, ROLE, BUCKET]
    assert [(e["src"], e["kind"], e["dst"]) for e in chain["edges"]] == [
        (SG, "exposes", INSTANCE),
        (INSTANCE, "assumes", ROLE),
        (ROLE, "can_access", BUCKET),
    ]


def test_edges_carry_method_confidence_and_evidence(fixture_props: dict) -> None:
    [chain] = fixture_props["chains"]
    by_kind = {e["kind"]: e for e in chain["edges"]}
    assert {k: (e["method"], e["confidence"]) for k, e in by_kind.items()} == {
        "exposes": ("attached_security_group", 1.0),
        "assumes": ("profile_role_name", 0.6),
        "can_access": ("policy_wildcard", 1.0),
    }
    assert all(e["source"] == "prowler" and e["evidence"] for e in chain["edges"])
    assert by_kind["can_access"]["properties"] == {
        "account_match": "same",
        "deny_check": "not_observed",
        "unobserved_layers": ["bucket_policy", "permissions_boundary", "rcp", "scp"],
    }
    assert by_kind["exposes"]["properties"] == {}


def test_nodes_show_why_they_are_entry_and_target(fixture_props: dict) -> None:
    [chain] = fixture_props["chains"]
    nodes = {n["key"]: n for n in chain["nodes"]}
    assert nodes[SG]["entry_findings"] == [
        "prowler:ec2_securitygroup_allow_ingress_from_internet_to_port_22",
        "trivy:AVD-AWS-0107",
    ]
    assert nodes[BUCKET]["data_classification"] == "PII"
    assert "data_classification" not in nodes[SG]
    assert nodes[INSTANCE]["members"] == [
        "aws:ec2:instance:datalake-etl",
        "aws:ec2:instance:i-0a1b2c3d4e5f67890",
    ]
    assert all(n["accounts"] == ["123456789012"] for n in chain["nodes"])


def test_graph_stats_count_the_whole_graph(fixture_props: dict) -> None:
    # The wildcard role reaches every same-account node (3 can_access edges);
    # only the one on the chain is exported, the totals say what was left out.
    assert fixture_props["graph_stats"] == {
        "nodes": 4,
        "edges": 5,
        "dropped_edges": 0,
        "edges_by_kind": {"assumes": 1, "can_access": 3, "exposes": 1},
    }
    exported = sum(len(c["edges"]) for c in fixture_props["chains"])
    assert exported == 3 < fixture_props["graph_stats"]["edges"]


def test_without_prowler_chains_empty_and_stats_present(fixtures_dir: Path) -> None:
    props = _properties(_run(fixtures_dir, prowler=False))
    assert props["chains"] == []
    assert props["graph_stats"]["edges"] == 0
    assert props["graph_stats"]["edges_by_kind"] == {}


def test_chains_never_add_results(fixtures_dir: Path) -> None:
    run = _run(fixtures_dir)
    findings = sum(len(scan_run.findings) for scan_run in run.scan_runs)
    sarif_run = to_sarif(run)["runs"][0]
    assert len(sarif_run["results"]) == findings
    # A3-1b: a result may name its chains in properties.chain_ids, nowhere else.
    for result in sarif_run["results"]:
        properties = dict(result.get("properties", {}))
        properties.pop("chain_ids", None)
        assert "chain" not in json.dumps({**result, "properties": properties})


def test_properties_are_plain_json(fixture_props: dict) -> None:
    # Tuples, MatchKeys or MappingProxy would either crash json.dump or
    # serialize differently from what the golden pins.
    assert json.loads(json.dumps(fixture_props, sort_keys=True)) == fixture_props


def test_cli_prints_chain_count(tmp_path: Path) -> None:
    out = subprocess.run(
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
        check=True,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert "Attack chains: 1 (longest 3 hops, confidence 0.6)" in out.stdout
