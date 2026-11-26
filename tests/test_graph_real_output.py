"""The attack graph reads current Prowler OCSF output.

The graph took its edge facts from the synthetic fixture layout, flat
`resources[].data.{security_groups, iam_instance_profile_arn,
inline_policy_*}` and `resources[].tags`. Current OCSF (Prowler 5.46) carries
the same facts under `resources[].data.metadata`, an inline policy as a
resource of its own, and tags as `[{Key, Value}]`, so on real output the graph
drew no edge and no chain, and said nothing (`dropped_edges` stayed 0). Both
layouts are read now; two real entry check IDs have a category; a managed
`*/*` policy draws no edge (O49); resources whose edge fields are absent in
both layouts are counted in `graph_stats.unread_edge_sources`.
"""

from __future__ import annotations

import json
from pathlib import Path

from ascc.correlate.graph import build_graph, find_chains
from ascc.correlate.run import CorrelationRun, correlate
from ascc.export.sarif import graph_properties
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser
from ascc.schema.taxonomy import Category

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL = REPO_ROOT / "fixtures" / "leaky_data_lake_real"
SG = "aws:ec2:security-group:sg-0586c5b38f77d2611"
INSTANCE = "aws:ec2:instance:i-0b861a4f57ea57684"
ROLE = "aws:iam:role:datalake-etl-role"
BUCKET = "aws:s3:bucket:datalake-raw-123456789012"
ENTRY_IDS = (
    "ec2_instance_port_ssh_exposed_to_internet",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
)
CAN_ACCESS = 2  # role -> the two bucket nodes (O49); the account is no bucket (O50)


def _run(prowler: Path = REAL / "prowler.json") -> CorrelationRun:
    return correlate(
        [
            ProwlerParser().parse(prowler),
            TrivyParser().parse(REAL / "trivy-config.json"),
            TrivyParser().parse(REAL / "trivy-rootfs.json"),
            CheckovParser().parse(REAL / "checkov.json"),
        ]
    )


def test_real_output_draws_the_expected_edges() -> None:
    edges = build_graph(_run()).edges
    triples = {(str(e.src), e.kind, str(e.dst)) for e in edges}
    assert (SG, "exposes", INSTANCE) in triples
    assert (INSTANCE, "assumes", ROLE) in triples
    assert (ROLE, "can_access", BUCKET) in triples
    kinds = [e.kind for e in edges]
    assert (kinds.count("exposes"), kinds.count("assumes")) == (1, 1)
    assert kinds.count("can_access") == CAN_ACCESS


def test_real_output_has_the_demo_chain() -> None:
    chains = find_chains(build_graph(_run()))
    assert [[str(key) for key in chain.nodes] for chain in chains] == [[SG, INSTANCE, ROLE, BUCKET]]
    assert round(chains[0].confidence, 6) == 0.6


def test_real_tags_make_the_bucket_a_target() -> None:
    resources = ProwlerParser().parse(REAL / "prowler.json").resources
    assert resources[BUCKET].tags.get("DataClassification") == "PII"


def test_real_entry_check_ids_are_network_exposure() -> None:
    findings = ProwlerParser().parse(REAL / "prowler.json").findings
    found = {f.rule_id: f.category for f in findings if f.rule_id in ENTRY_IDS}
    assert set(found) == set(ENTRY_IDS)
    assert set(found.values()) == {Category.NETWORK_EXPOSURE}


def test_managed_wildcard_policy_draws_no_edge() -> None:
    sources = {str(e.src) for e in build_graph(_run()).edges}
    assert not any(":iam:policy:" in source for source in sources)


def test_inline_policy_without_star_on_both_draws_no_wildcard(tmp_path: Path) -> None:
    for field, value in (("Resource", "arn:aws:s3:::one-bucket"), ("Effect", "Deny")):
        entries = json.loads((REAL / "prowler.json").read_text(encoding="utf-8"))
        for entry in entries:
            for resource in entry["resources"]:
                metadata = resource["data"].get("metadata") or {}
                if metadata.get("type") == "Inline":
                    for statement in metadata["document"]["Statement"]:
                        statement[field] = value
        path = tmp_path / f"prowler-{field}.json"
        path.write_text(json.dumps(entries), encoding="utf-8")
        kinds = [e.kind for e in build_graph(_run(path)).edges]
        assert "can_access" not in kinds, field
        assert kinds.count("exposes") == 1, field


def test_unread_edge_sources_are_counted(tmp_path: Path) -> None:
    entries = json.loads((REAL / "prowler.json").read_text(encoding="utf-8"))
    stripped: set[str] = set()
    for entry in entries:
        for resource in entry["resources"]:
            metadata = resource["data"].get("metadata") or {}
            if resource["type"] == "AwsEc2Instance" and ":instance/" in resource["uid"]:
                metadata.pop("security_groups", None)
                metadata.pop("instance_profile", None)
                stripped.add(resource["uid"])
            if resource["type"] == "AwsIamPolicy" and metadata.get("type") == "Inline":
                metadata.pop("document", None)
                stripped.add(resource["uid"])
    path = tmp_path / "prowler.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    run = _run(path)
    assert stripped and build_graph(run).unread_edge_sources == len(stripped)
    stats = graph_properties(run)["graph_stats"]
    assert stats["unread_edge_sources"] == len(stripped)
    assert stats["edges"] == 0


def test_no_unread_count_when_every_field_was_read() -> None:
    stats = graph_properties(_run())["graph_stats"]
    assert "unread_edge_sources" not in stats
    assert stats["edges"] > 0


def test_fixture_readme_states_the_real_chain() -> None:
    readme = REPO_ROOT / "fixtures" / "leaky_data_lake" / "README.md"
    text = " ".join(readme.read_text(encoding="utf-8").split())
    assert (
        "on the real output it finds one chain, security group -> instance -> role -> "
        "bucket, 3 hops, confidence 0.6; the role's `*/*` inline policy draws "
        f"{CAN_ACCESS} `can_access` edges, one per bucket node"
    ) in text


def test_contract_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "Current OCSF (Prowler 5.46) carries the same facts elsewhere" in text
