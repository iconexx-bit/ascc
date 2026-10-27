"""SARIF 2.1.0 export. Pure functions over the domain model."""

from __future__ import annotations

import hashlib
import json

from ascc.correlate.graph import (
    TARGET_TAG,
    Chain,
    Edge,
    Graph,
    Node,
    build_graph,
    chain_ids_by_key,
    find_chains,
)
from ascc.correlate.run import CorrelationRun
from ascc.schema.identity import MatchKey
from ascc.schema.models import Finding
from ascc.schema.taxonomy import Severity

FINGERPRINT_VERSION = "asccDedupKey/v1"

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "ASCC"

# CLAUDE.md, "Инварианты": SARIF level mapping.
# level -> (sarif level, security-severity). CRITICAL/HIGH both map to
# "error" (SARIF has no level above it) — security-severity is what lets
# GitHub Code Scanning tell them apart.
_LEVEL_BY_SEVERITY: dict[Severity, tuple[str, float]] = {
    Severity.CRITICAL: ("error", 9.5),
    Severity.HIGH: ("error", 8.0),
    Severity.MEDIUM: ("warning", 5.5),
    Severity.LOW: ("note", 3.0),
    Severity.INFO: ("none", 0.0),
}


def fingerprint(finding: Finding) -> str:
    """Stable identity of a finding across runs.

    Backed by Finding.dedup_key, which is backed by MatchKey.__str__.
    Changing either invalidates every published fingerprint — bump the
    version suffix instead.
    """
    payload = json.dumps(
        list(finding.dedup_key),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rule_id(finding: Finding) -> str:
    # Scanner-qualified: Trivy, Checkov and Prowler each own their rule_id
    # namespace (CVE-2021-..., CKV_AWS_..., prowler check slugs) and nothing
    # guarantees those strings never collide across scanners.
    return f"{finding.scanner}/{finding.rule_id}"


def _rule(finding: Finding) -> dict:
    level, security_severity = _LEVEL_BY_SEVERITY[finding.severity]
    return {
        "id": _rule_id(finding),
        "properties": {
            "security-severity": str(security_severity),
            "ascc/category": str(finding.category),
            "ascc/level": level,
        },
    }


def _cluster_properties(finding: Finding, run: CorrelationRun) -> dict[str, list[str]]:
    """Cluster/ghost membership for a finding's resources (CLAUDE.md, "Step 7").

    A finding's resolutions (not resource_ids: MatchKey.__str__ is not
    parseable back, CLAUDE.md "Step 6") may land in more than one cluster —
    members is the union across all of them. A ghost is a cluster member
    absent from this run's own `resources`, i.e. reachable only through a
    bridge fact replayed from history (Step 6), never from this run's ingest.
    Returns {} when the finding touches no cluster at all — to_sarif emits
    no empty lists.
    """
    resolution_keys = {resolution.key for resolution in finding.resolutions}
    members: set[MatchKey] = set()
    for cluster in run.clusters:
        if resolution_keys & cluster.keys:
            members |= cluster.keys
    if not members:
        return {}
    properties: dict[str, list[str]] = {"cluster_members": sorted(str(key) for key in members)}
    ghosts = sorted(str(key) for key in members if str(key) not in run.resources)
    if ghosts:
        properties["ghost_members"] = ghosts
    return properties


def _result(finding: Finding, run: CorrelationRun, links: dict[str, tuple[str, ...]]) -> dict:
    level, _ = _LEVEL_BY_SEVERITY[finding.severity]
    resource_ids = sorted(finding.resource_ids)
    result: dict = {
        "ruleId": _rule_id(finding),
        "level": level,
        "message": {"text": finding.title},
        "locations": [
            {"logicalLocations": [{"fullyQualifiedName": resource_id}]}
            for resource_id in resource_ids
        ],
        "partialFingerprints": {FINGERPRINT_VERSION: fingerprint(finding)},
    }
    properties: dict[str, list[str]] = _cluster_properties(finding, run)
    # CLAUDE.md, "Graph and chains (A2)", Chain links: omitted when empty.
    chain_ids = sorted({cid for rid in finding.resource_ids for cid in links.get(rid, ())})
    if chain_ids:
        properties["chain_ids"] = chain_ids
    if properties:
        result["properties"] = properties
    return result


def _json_value(value: object) -> object:
    if isinstance(value, tuple | list | frozenset | set):
        items = [_json_value(v) for v in value]
        return sorted(items) if isinstance(value, frozenset | set) else items
    return value


def _node_properties(node: Node) -> dict:
    props: dict = {
        "key": str(node.key),
        "members": sorted(str(member) for member in node.members),
        "accounts": sorted(node.accounts),
        "entry_findings": list(node.entry_findings),
    }
    if node.is_target:
        props["data_classification"] = node.tags[TARGET_TAG]
    return props


def _edge_properties(edge: Edge) -> dict:
    return {
        "src": str(edge.src),
        "dst": str(edge.dst),
        "kind": edge.kind,
        "method": edge.method,
        "confidence": round(edge.confidence, 6),
        "source": edge.source,
        "evidence": edge.evidence,
        "properties": {key: _json_value(value) for key, value in edge.properties},
    }


def _chain_properties(chain: Chain, nodes: dict) -> dict:
    return {
        "id": chain.id,
        "hops": len(chain.edges),
        "confidence": round(chain.confidence, 6),
        "nodes": [_node_properties(nodes[key]) for key in chain.nodes],
        "edges": [_edge_properties(edge) for edge in chain.edges],
    }


def _graph_stats(graph: Graph) -> dict:
    by_kind: dict[str, int] = {}
    for edge in graph.edges:
        by_kind[edge.kind] = by_kind.get(edge.kind, 0) + 1
    return {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "dropped_edges": graph.dropped_edges,
        "edges_by_kind": dict(sorted(by_kind.items())),
    }


def graph_properties(run: CorrelationRun) -> dict:
    """runs[0].properties for SARIF (CLAUDE.md, "Graph and chains (A2)").

    chains: every reported chain with its nodes and only its own edges.
    graph_stats: totals over the whole graph, so the edges left out of
    chains stay visible as a count. Confidences are rounded to 6 places
    for stable bytes. No result is ever added for a chain; to_sarif links
    existing results to chains through properties.chain_ids (A3-1b).
    """
    graph = build_graph(run)
    return _graph_properties(graph, find_chains(graph))


def _graph_properties(graph: Graph, chains: tuple[Chain, ...]) -> dict:
    nodes = {node.key: node for node in graph.nodes}
    return {
        "chains": [_chain_properties(chain, nodes) for chain in chains],
        "graph_stats": _graph_stats(graph),
    }


def to_sarif(run: CorrelationRun) -> dict:
    """Render a CorrelationRun as a SARIF 2.1.0 log. Pure — no I/O.

    One Finding -> one SARIF result. A finding bound to several resources
    (many-to-many, CLAUDE.md "Инварианты") keeps all of them as separate
    `locations` on that single result rather than fanning out into several
    results — dedup_key already treats the resource_ids tuple as one unit,
    and fingerprint() is defined over that same tuple.
    """
    findings = [finding for scan_run in run.scan_runs for finding in scan_run.findings]
    graph = build_graph(run)
    chains = find_chains(graph)
    links = chain_ids_by_key(graph, chains)

    rules: dict[str, dict] = {}
    results: list[tuple[str, str, str, dict]] = []
    for finding in findings:
        rule_id = _rule_id(finding)
        rules.setdefault(rule_id, _rule(finding))
        resource_ids = sorted(finding.resource_ids)
        sort_resource_id = resource_ids[0] if resource_ids else ""
        results.append((rule_id, sort_resource_id, finding.title, _result(finding, run, links)))

    # CLAUDE.md, "Determinism": results[] sorted by (ruleId, resource_id, message).
    results.sort(key=lambda r: (r[0], r[1], r[2]))

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "rules": [rules[rule_id] for rule_id in sorted(rules)],
                    }
                },
                "results": [result for *_, result in results],
                "properties": _graph_properties(graph, chains),
            }
        ],
    }
