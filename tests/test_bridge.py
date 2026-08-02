from __future__ import annotations

from ascc.correlate.bridge import ResourceCluster, build_clusters
from ascc.schema.identity import MatchKey
from ascc.schema.models import BridgeFact


def _key(identifier: str) -> MatchKey:
    return MatchKey("aws", "ec2", "instance", identifier)


def _fact(left: MatchKey, right: MatchKey, confidence: float) -> BridgeFact:
    return BridgeFact(
        left=left,
        right=right,
        method="observed_together",
        confidence=confidence,
        source="test",
        evidence="synthetic",
    )


def test_fact_pair_order_irrelevant() -> None:
    a, b = _key("a"), _key("b")
    fact_ab = _fact(a, b, 0.95)
    fact_ba = _fact(b, a, 0.95)
    assert fact_ab == fact_ba
    assert hash(fact_ab) == hash(fact_ba)


def test_two_disjoint_bridges_form_two_clusters() -> None:
    a, b, c, d = _key("a"), _key("b"), _key("c"), _key("d")
    clusters = build_clusters([_fact(a, b, 0.9), _fact(c, d, 0.9)])
    assert len(clusters) == 2
    assert all(len(cluster.keys) == 2 for cluster in clusters)


def test_representative_prefers_higher_confidence() -> None:
    a, b, z = _key("a"), _key("b"), _key("z")
    cluster = ResourceCluster(
        keys=frozenset({a, b, z}),
        facts=(_fact(a, b, 0.9), _fact(b, z, 0.2)),
    )
    assert cluster.representative() == b


def test_direct_confidence_returns_none_for_indirect_pair() -> None:
    a, b, c = _key("a"), _key("b"), _key("c")
    clusters = build_clusters([_fact(a, b, 0.9), _fact(b, c, 0.8)])
    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.keys == frozenset({a, b, c})
    assert cluster.direct_confidence(a, c) is None
    path = cluster.path(a, c)
    assert path is not None
    assert len(path) == 2


def test_isolated_key_forms_no_cluster() -> None:
    a, b, isolated = _key("a"), _key("b"), _key("isolated")
    clusters = build_clusters([_fact(a, b, 0.9)])
    all_keys = {key for cluster in clusters for key in cluster.keys}
    assert isolated not in all_keys


def test_direct_confidence_of_key_with_itself_is_none() -> None:
    a = _key("a")
    cluster = ResourceCluster(keys=frozenset({a}), facts=())
    assert cluster.direct_confidence(a, a) is None
