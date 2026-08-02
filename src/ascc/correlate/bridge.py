from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass

from ascc.schema.identity import MatchKey
from ascc.schema.models import BridgeFact


@dataclass(frozen=True, slots=True)
class ResourceCluster:
    keys: frozenset[MatchKey]
    facts: tuple[BridgeFact, ...]

    def representative(self) -> MatchKey:
        def score(key: MatchKey) -> tuple[float, str]:
            confidences = [f.confidence for f in self.facts if key in (f.left, f.right)]
            return (max(confidences, default=0.0), str(key))

        return max(self.keys, key=score)

    def path(self, a: MatchKey, b: MatchKey) -> tuple[BridgeFact, ...] | None:
        if a == b:
            return ()
        adjacency: dict[MatchKey, list[tuple[MatchKey, BridgeFact]]] = defaultdict(list)
        for fact in self.facts:
            adjacency[fact.left].append((fact.right, fact))
            adjacency[fact.right].append((fact.left, fact))
        visited = {a}
        queue: deque[tuple[MatchKey, tuple[BridgeFact, ...]]] = deque([(a, ())])
        while queue:
            node, path_so_far = queue.popleft()
            for neighbor, fact in adjacency[node]:
                if neighbor == b:
                    return path_so_far + (fact,)
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path_so_far + (fact,)))
        return None

    def direct_confidence(self, a: MatchKey, b: MatchKey) -> float | None:
        """Confidence только при прямом факте между a и b.

        Между ключом и им самим моста нет: тождество — не мостовой факт,
        поэтому direct_confidence(a, a) тоже None. path(a, a), напротив,
        возвращает () — пустой путь про тривиальную достижимость, а не
        про наличие моста. Разное поведение на диагонали — осознанное.
        """
        pair = {a, b}
        for fact in self.facts:
            if {fact.left, fact.right} == pair:
                return fact.confidence
        return None


def build_clusters(facts: Iterable[BridgeFact]) -> list[ResourceCluster]:
    facts = list(facts)
    parent: dict[MatchKey, MatchKey] = {}

    def find(key: MatchKey) -> MatchKey:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(a: MatchKey, b: MatchKey) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for fact in facts:
        parent.setdefault(fact.left, fact.left)
        parent.setdefault(fact.right, fact.right)
        union(fact.left, fact.right)

    groups: dict[MatchKey, set[MatchKey]] = defaultdict(set)
    for key in parent:
        groups[find(key)].add(key)

    clusters = []
    for keys in groups.values():
        cluster_facts = tuple(f for f in facts if f.left in keys and f.right in keys)
        clusters.append(ResourceCluster(keys=frozenset(keys), facts=cluster_facts))
    return clusters
