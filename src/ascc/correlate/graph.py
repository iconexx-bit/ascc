"""Attack graph and chains (CLAUDE.md, "Graph and chains (A2)").

Nodes are the run's resources grouped by CorrelationRun.clusters: a cluster is
one node, a key in no cluster is a node of its own. A node's key is the
cluster's derived representative (never stored, see CLAUDE.md). Edges are
directed in attack order and built only from scanner data in Finding.raw; a
reference that resolves to no node is counted in dropped_edges, never turned
into an invented node. Chains run from an entry node (a NETWORK_EXPOSURE
finding) to a target node (a DataClassification tag).

Pure and deterministic: stdlib only, no clock, no I/O, sorted everywhere.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from ascc.schema.identity import ARN_RE, MatchKey, RefScheme, ResourceRef, resolve
from ascc.schema.taxonomy import Category

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from ascc.correlate.run import CorrelationRun
    from ascc.schema.models import Evidence

# Relation methods and their confidence. Identity facts live in
# ascc.store.policy.MAX_CONFIDENCE; the two tables never mix.
EDGE_CONFIDENCE: Mapping[str, float] = MappingProxyType(
    {
        "attached_security_group": 1.0,
        "profile_role_name": 0.6,
        "policy_wildcard": 1.0,
    }
)
UNOBSERVED_LAYERS: tuple[str, ...] = ("bucket_policy", "permissions_boundary", "rcp", "scp")
TARGET_TAG = "DataClassification"


@dataclass(frozen=True, slots=True)
class Node:
    key: MatchKey
    members: frozenset[MatchKey]
    accounts: frozenset[str]
    tags: Mapping[str, str]
    entry_findings: tuple[str, ...]
    # Runtime evidence on any member (CLAUDE.md, "Runtime evidence (A3)"), sorted.
    evidence: tuple[Evidence, ...] = ()

    @property
    def is_entry(self) -> bool:
        return bool(self.entry_findings)

    @property
    def is_target(self) -> bool:
        return TARGET_TAG in self.tags


@dataclass(frozen=True, slots=True)
class Edge:
    src: MatchKey
    dst: MatchKey
    kind: str
    method: str
    confidence: float
    source: str
    evidence: str
    properties: tuple[tuple[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class Graph:
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    dropped_edges: int


@dataclass(frozen=True, slots=True)
class Chain:
    id: str
    nodes: tuple[MatchKey, ...]
    edges: tuple[Edge, ...]
    confidence: float = field(default=1.0)


def _sort_key(key: MatchKey) -> str:
    return str(key)


def build_graph(run: CorrelationRun) -> Graph:
    node_of: dict[MatchKey, MatchKey] = {}
    members: dict[MatchKey, set[MatchKey]] = {}
    for cluster in run.clusters:
        rep = cluster.representative()
        members[rep] = set(cluster.keys)
        for key in cluster.keys:
            node_of[key] = rep
    by_str: dict[str, MatchKey] = {}
    for key_str, resource in sorted(run.resources.items()):
        by_str[key_str] = resource.key
        if resource.key not in node_of:
            node_of[resource.key] = resource.key
            members[resource.key] = {resource.key}

    accounts: dict[MatchKey, set[str]] = {rep: set() for rep in members}
    entries: dict[MatchKey, set[str]] = {rep: set() for rep in members}
    for scan in run.scan_runs:
        for finding in scan.findings:
            account = _account(finding.raw)
            for rid in finding.resource_ids:
                key = by_str.get(rid)
                if key is None or key not in node_of:
                    continue
                rep = node_of[key]
                if account:
                    accounts[rep].add(account)
                if finding.category is Category.NETWORK_EXPOSURE:
                    entries[rep].add(f"{finding.scanner}:{finding.rule_id}")

    evidence: dict[MatchKey, list[Evidence]] = {rep: [] for rep in members}
    for scan in run.scan_runs:
        for item in scan.evidence:
            key = by_str.get(item.resource_id)
            if key is not None and key in node_of:
                evidence[node_of[key]].append(item)

    nodes: dict[MatchKey, Node] = {}
    for rep in sorted(members, key=_sort_key):
        nodes[rep] = Node(
            key=rep,
            members=frozenset(members[rep]),
            accounts=frozenset(accounts[rep]),
            tags=MappingProxyType(_merged_tags(run, members[rep])),
            entry_findings=tuple(sorted(entries[rep])),
            evidence=tuple(
                sorted(evidence[rep], key=lambda e: (e.scanner, e.rule_id, e.resource_id))
            ),
        )

    edges: dict[tuple[str, str, str, str], Edge] = {}
    dropped = 0
    for scan in run.scan_runs:
        for finding in scan.findings:
            for edge in _edges_from(finding, scan.scanner, node_of, nodes):
                if edge is None:
                    dropped += 1
                    continue
                ident = (str(edge.src), edge.kind, str(edge.dst), edge.method)
                if ident not in edges or edge.evidence < edges[ident].evidence:
                    edges[ident] = edge
    ordered = tuple(edges[k] for k in sorted(edges))
    return Graph(nodes=tuple(nodes.values()), edges=ordered, dropped_edges=dropped)


def _account(raw: dict) -> str | None:
    cloud = raw.get("cloud") if isinstance(raw, dict) else None
    account = cloud.get("account") if isinstance(cloud, dict) else None
    uid = account.get("uid") if isinstance(account, dict) else None
    return uid if isinstance(uid, str) and uid else None


def _merged_tags(run: CorrelationRun, keys: set[MatchKey]) -> dict[str, str]:
    """Union of members' tags; a key whose members disagree is left out (the
    disagreement is already reported as a TagConflict)."""
    seen: dict[str, set[str]] = {}
    for key in keys:
        resource = run.resources.get(str(key))
        if resource is None:
            continue
        for tag, value in resource.tags.items():
            seen.setdefault(tag, set()).add(value)
    return {tag: next(iter(values)) for tag, values in sorted(seen.items()) if len(values) == 1}


def _resolve_arn(value: str, scanner: str) -> MatchKey | None:
    resolution = resolve(ResourceRef(scheme=RefScheme.ARN, value=value, scanner=scanner))
    return resolution.key if resolution else None


def _find(nodes: Mapping[MatchKey, Node], service: str, rtype: str, ident: str) -> Node | None:
    ident = ident.strip().lower().replace("_", "-")
    for node in nodes.values():
        for key in node.members:
            if (key.service, key.resource_type, key.identifier) == (service, rtype, ident):
                return node
    return None


def _edges_from(
    finding, scanner: str, node_of: Mapping[MatchKey, MatchKey], nodes: Mapping[MatchKey, Node]
) -> Iterator[Edge | None]:
    """Yield an Edge per resolvable reference and None per dropped one."""
    raw = finding.raw if isinstance(finding.raw, dict) else {}
    for res in raw.get("resources") or ():
        if not isinstance(res, dict) or not isinstance(res.get("uid"), str):
            continue
        uid = res["uid"]
        data = res.get("data") or {}
        if not isinstance(data, dict):
            continue
        src_key = _resolve_arn(uid, scanner)
        src = nodes.get(node_of.get(src_key)) if src_key else None
        if src is None:
            continue

        for sg_id in data.get("security_groups") or ():
            sg = _find(nodes, "ec2", "security-group", str(sg_id))
            yield (
                _edge(
                    sg,
                    src,
                    "exposes",
                    "attached_security_group",
                    scanner,
                    f"{uid} security_groups={sg_id}",
                )
                if sg
                else None
            )

        profile_arn = data.get("iam_instance_profile_arn")
        if isinstance(profile_arn, str):
            yield _assumes(src, profile_arn, scanner, nodes)

        if data.get("inline_policy_actions") == ["*"] and data.get("inline_policy_resources") == [
            "*"
        ]:
            yield from _wildcard(src, uid, scanner, nodes)


def _assumes(
    src: Node, profile_arn: str, scanner: str, nodes: Mapping[MatchKey, Node]
) -> Edge | None:
    m = ARN_RE.match(profile_arn)
    if not m or not m["tail"].startswith("instance-profile/"):
        return None
    name = m["tail"].split("/")[-1]
    role = _find(nodes, "iam", "role", name)
    if role is None or (role.accounts and m["account"] not in role.accounts):
        return None
    return _edge(src, role, "assumes", "profile_role_name", scanner, f"{profile_arn} name={name}")


def _wildcard(src: Node, uid: str, scanner: str, nodes: Mapping[MatchKey, Node]) -> Iterator[Edge]:
    for node in nodes.values():
        if node.key == src.key:
            continue
        if node.accounts and src.accounts and not (node.accounts & src.accounts):
            continue
        match = "same" if node.accounts & src.accounts else "unverified"
        yield _edge(
            src,
            node,
            "can_access",
            "policy_wildcard",
            scanner,
            f"{uid} inline_policy actions=* resources=*",
            (
                ("account_match", match),
                ("deny_check", "not_observed"),
                ("unobserved_layers", UNOBSERVED_LAYERS),
            ),
        )


def _edge(
    src: Node,
    dst: Node,
    kind: str,
    method: str,
    scanner: str,
    evidence: str,
    properties: tuple[tuple[str, object], ...] = (),
) -> Edge:
    return Edge(
        src=src.key,
        dst=dst.key,
        kind=kind,
        method=method,
        confidence=EDGE_CONFIDENCE[method],
        source=scanner,
        evidence=evidence,
        properties=properties,
    )


def find_chains(graph: Graph) -> tuple[Chain, ...]:
    """Simple directed paths entry -> target with at least one edge. A path
    contained in a longer reported path is not reported on its own."""
    nodes = {n.key: n for n in graph.nodes}
    out: dict[MatchKey, list[Edge]] = {}
    for edge in graph.edges:  # already sorted (src, kind, dst, method)
        out.setdefault(edge.src, []).append(edge)

    paths: list[tuple[Edge, ...]] = []

    def walk(at: MatchKey, seen: tuple[MatchKey, ...], path: tuple[Edge, ...]) -> None:
        for edge in out.get(at, ()):
            if edge.dst in seen:
                continue
            step = path + (edge,)
            if nodes[edge.dst].is_target:
                paths.append(step)
                continue
            walk(edge.dst, seen + (edge.dst,), step)

    for node in graph.nodes:
        if node.is_entry:
            walk(node.key, (node.key,), ())

    def keys(path: tuple[Edge, ...]) -> tuple[MatchKey, ...]:
        return (path[0].src, *(e.dst for e in path))

    def contained(short: tuple[MatchKey, ...], long: tuple[MatchKey, ...]) -> bool:
        n = len(short)
        return n < len(long) and any(long[i : i + n] == short for i in range(len(long) - n + 1))

    seqs = [keys(p) for p in paths]
    chains = []
    for path, seq in zip(paths, seqs, strict=True):
        if any(contained(seq, other) for other in seqs):
            continue
        confidence = 1.0
        for edge in path:
            confidence *= edge.confidence
        digest = hashlib.sha256("\n".join(map(str, seq)).encode()).hexdigest()[:12]
        chains.append(Chain(id=f"chain-{digest}", nodes=seq, edges=path, confidence=confidence))
    chains.sort(key=lambda c: (-len(c.edges), tuple(map(str, c.nodes))))
    return tuple(chains)


def chain_ids_by_key(graph: Graph, chains: tuple[Chain, ...]) -> dict[str, tuple[str, ...]]:
    """Member key (as written in Finding.resource_ids) -> sorted ids of the
    chains whose nodes contain it. A finding on any member belongs to the node,
    so a finding lies on a chain iff one of its resource ids is a key here."""
    nodes = {node.key: node for node in graph.nodes}
    links: dict[str, set[str]] = {}
    for chain in chains:
        for key in chain.nodes:
            for member in nodes[key].members:
                links.setdefault(str(member), set()).add(chain.id)
    return {key: tuple(sorted(ids)) for key, ids in sorted(links.items())}
