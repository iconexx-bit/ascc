"""SARIF 2.1.0 export. Pure functions over the domain model."""

from __future__ import annotations

import hashlib
import json

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


def _result(finding: Finding, run: CorrelationRun) -> dict:
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
    properties = _cluster_properties(finding, run)
    if properties:
        result["properties"] = properties
    return result


def to_sarif(run: CorrelationRun) -> dict:
    """Render a CorrelationRun as a SARIF 2.1.0 log. Pure — no I/O.

    One Finding -> one SARIF result. A finding bound to several resources
    (many-to-many, CLAUDE.md "Инварианты") keeps all of them as separate
    `locations` on that single result rather than fanning out into several
    results — dedup_key already treats the resource_ids tuple as one unit,
    and fingerprint() is defined over that same tuple.
    """
    findings = [finding for scan_run in run.scan_runs for finding in scan_run.findings]

    rules: dict[str, dict] = {}
    results: list[tuple[str, str, str, dict]] = []
    for finding in findings:
        rule_id = _rule_id(finding)
        rules.setdefault(rule_id, _rule(finding))
        resource_ids = sorted(finding.resource_ids)
        sort_resource_id = resource_ids[0] if resource_ids else ""
        results.append((rule_id, sort_resource_id, finding.title, _result(finding, run)))

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
            }
        ],
    }
