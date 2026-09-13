"""ШАГ 6: store consumer. Asserts live on CorrelationRun.clusters, never on
SARIF bytes — to_sarif reads no cluster state (measured 2026-09-13); exposure
is ШАГ 7."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from ascc.cli import _to_fact
from ascc.correlate.history import facts_to_bridge_facts
from ascc.correlate.run import correlate, effective_confidence
from ascc.schema.identity import IdentityClass, MatchKey, Resolution
from ascc.schema.models import BridgeFact, Finding, ScanRun
from ascc.schema.taxonomy import Category, Severity

NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
A = MatchKey("aws", "ec2", "instance", "a")
G = MatchKey("aws", "ec2", "instance", "ghost")
B = MatchKey("aws", "ec2", "instance", "b")


def _bf(
    left: MatchKey, right: MatchKey, *, method: str = "observed_together", confidence: float = 0.95
) -> BridgeFact:
    return BridgeFact(
        left=left, right=right, method=method, confidence=confidence, source="test", evidence="test"
    )


def _finding(key: MatchKey) -> Finding:
    return Finding(
        scanner="test",
        rule_id="T-1",
        category=Category.UNCATEGORIZED,
        severity=Severity.HIGH,  # IntEnum: INFO is first
        title="t",
        resource_ids=[str(key)],
        resolutions=[
            Resolution(
                key=key, confidence=1.0, method="test", identity_class=IdentityClass.NATURAL_NAME
            )
        ],
    )


def _run(*facts: BridgeFact):
    scan = ScanRun(scanner="test", findings=[_finding(A), _finding(B)])
    return correlate([scan], extra_facts=list(facts))


# --- level B: state ---------------------------------------------------------


def test_ghost_node_joins_cluster() -> None:
    run = _run(_bf(A, G), _bf(G, B))
    assert G in {k for c in run.clusters for k in c.keys}
    assert any({A, B} <= c.keys for c in run.clusters)


def test_ghost_pair_has_no_confidence() -> None:
    run = _run(_bf(A, G), _bf(G, B))
    assert effective_confidence(_finding(A), B, run) is None


def test_ghost_can_be_representative() -> None:
    """CLAUDE.md: representative is a cluster property, the cluster includes
    history. Equal confidences tie-break lexicographically, so 'ghost' wins."""
    run = _run(_bf(A, G), _bf(G, B))
    cluster = next(c for c in run.clusters if G in c.keys)
    assert cluster.representative() == G  # was: `in cluster.keys`


# --- level A: pure ----------------------------------------------------------


def test_round_trip() -> None:
    bf = _bf(A, B)
    assert facts_to_bridge_facts([_to_fact(bf, observed_at=NOW)], known={}) == ([bf], [])


def test_stale_fact_excluded() -> None:
    stale = replace(_to_fact(_bf(A, B), observed_at=NOW), stale=True)  # frozen+slots
    edges, dropped = facts_to_bridge_facts([stale], known={})
    assert edges == []
    assert [r for _, r in dropped] == ["stale"]


def test_llm_fact_excluded() -> None:
    bf = _bf(A, B, method="llm", confidence=0.3)
    edges, dropped = facts_to_bridge_facts([_to_fact(bf, observed_at=NOW)], known={})
    assert edges == []
    assert [r for _, r in dropped] == ["llm"]


def test_v0_fact_needs_known() -> None:
    bf = _bf(A, B)
    v0 = replace(
        _to_fact(bf, observed_at=NOW), payload={"source": "test", "evidence": "test"}
    )  # no payload_v
    assert facts_to_bridge_facts([v0], known={}) == ([], [(v0, "v0_unresolvable")])
    edges, _ = facts_to_bridge_facts([v0], known={str(A): A, str(B): B})
    assert edges == [bf]
