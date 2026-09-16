from __future__ import annotations

from pathlib import Path

import pytest

from ascc.correlate.run import CorrelationRun, correlate
from ascc.export.sarif import fingerprint, to_sarif
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser
from ascc.schema.identity import IdentityClass, MatchKey, Resolution
from ascc.schema.models import BridgeFact, Finding, Resource, ScanRun
from ascc.schema.taxonomy import Category, Severity


@pytest.fixture(scope="module")
def correlation_run(fixtures_dir: Path) -> CorrelationRun:
    runs = [
        TrivyParser().parse(fixtures_dir / "trivy.json"),
        ProwlerParser().parse(fixtures_dir / "prowler.json"),
        CheckovParser().parse(fixtures_dir / "checkov.json"),
    ]
    return correlate(runs)


def _resolution(key: MatchKey, confidence: float = 1.0) -> Resolution:
    return Resolution(
        key=key, confidence=confidence, method="test", identity_class=IdentityClass.NATURAL_NAME
    )


def _finding(
    scanner: str,
    rule_id: str,
    title: str,
    severity: Severity,
    *keys: MatchKey,
) -> Finding:
    resolutions = [_resolution(k) for k in keys]
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        category=Category.UNCATEGORIZED,
        severity=severity,
        title=title,
        resource_ids=[str(k) for k in keys],
        resolutions=resolutions,
    )


def _synthetic_run(*findings: Finding) -> CorrelationRun:
    scan_run = ScanRun(scanner="test", findings=list(findings))
    return correlate([scan_run])


# --- structure, against the fixture scenario ---------------------------------


def test_version_is_2_1_0(correlation_run: CorrelationRun) -> None:
    assert to_sarif(correlation_run)["version"] == "2.1.0"


def test_single_run(correlation_run: CorrelationRun) -> None:
    assert len(to_sarif(correlation_run)["runs"]) == 1


def test_tool_driver_name(correlation_run: CorrelationRun) -> None:
    driver = to_sarif(correlation_run)["runs"][0]["tool"]["driver"]
    assert driver["name"] == "ASCC"


def test_rule_ids_are_scanner_qualified(correlation_run: CorrelationRun) -> None:
    """ruleId must disambiguate scanners — CVE-2021-44228 from Trivy and a
    same-named rule_id from another scanner must not collide."""
    rules = to_sarif(correlation_run)["runs"][0]["tool"]["driver"]["rules"]
    assert all("/" in rule["id"] for rule in rules)


def test_rule_ids_match_declared_rules(correlation_run: CorrelationRun) -> None:
    doc = to_sarif(correlation_run)
    rule_ids = {rule["id"] for rule in doc["runs"][0]["tool"]["driver"]["rules"]}
    result_rule_ids = {result["ruleId"] for result in doc["runs"][0]["results"]}
    assert result_rule_ids <= rule_ids


def test_result_count_matches_finding_count(correlation_run: CorrelationRun) -> None:
    doc = to_sarif(correlation_run)
    expected = sum(len(run.findings) for run in correlation_run.scan_runs)
    assert len(doc["runs"][0]["results"]) == expected


def test_every_result_has_partial_fingerprint(correlation_run: CorrelationRun) -> None:
    results = to_sarif(correlation_run)["runs"][0]["results"]
    assert all(result["partialFingerprints"] for result in results)


def test_fingerprint_matches_export_fingerprint(correlation_run: CorrelationRun) -> None:
    """to_sarif() must reuse export.sarif.fingerprint(), not reimplement it."""
    doc = to_sarif(correlation_run)
    fingerprints = {r["partialFingerprints"]["asccDedupKey/v1"] for r in doc["runs"][0]["results"]}
    findings = [f for run in correlation_run.scan_runs for f in run.findings]
    assert fingerprints == {fingerprint(f) for f in findings}


def test_level_is_one_of_sarif_allowed_values(correlation_run: CorrelationRun) -> None:
    results = to_sarif(correlation_run)["runs"][0]["results"]
    assert all(r["level"] in {"none", "note", "warning", "error"} for r in results)


def test_critical_finding_maps_to_error(correlation_run: CorrelationRun) -> None:
    """Log4Shell (CVE-2021-44228) is CRITICAL in the fixture — must be 'error'."""
    results = to_sarif(correlation_run)["runs"][0]["results"]
    log4shell = next(r for r in results if "CVE-2021-44228" in r["ruleId"])
    assert log4shell["level"] == "error"


def test_critical_carries_higher_security_severity_than_high(
    correlation_run: CorrelationRun,
) -> None:
    """CRITICAL and HIGH both map to SARIF level 'error' — security-severity
    is the only signal that still distinguishes them (CLAUDE.md)."""
    doc = to_sarif(correlation_run)
    rules_by_id = {rule["id"]: rule for rule in doc["runs"][0]["tool"]["driver"]["rules"]}
    findings = [f for run in correlation_run.scan_runs for f in run.findings]
    critical_rule = next(f for f in findings if f.severity is Severity.CRITICAL)
    high_rule = next(f for f in findings if f.severity is Severity.HIGH)
    critical_score = float(
        rules_by_id[f"{critical_rule.scanner}/{critical_rule.rule_id}"]["properties"][
            "security-severity"
        ]
    )
    high_score = float(
        rules_by_id[f"{high_rule.scanner}/{high_rule.rule_id}"]["properties"]["security-severity"]
    )
    assert critical_score > high_score


def test_results_sorted_by_rule_id(correlation_run: CorrelationRun) -> None:
    results = to_sarif(correlation_run)["runs"][0]["results"]
    rule_ids = [r["ruleId"] for r in results]
    assert rule_ids == sorted(rule_ids)


def test_is_pure_no_mutation_of_input(correlation_run: CorrelationRun) -> None:
    before = sum(len(run.findings) for run in correlation_run.scan_runs)
    to_sarif(correlation_run)
    after = sum(len(run.findings) for run in correlation_run.scan_runs)
    assert before == after


def test_deterministic_across_calls(correlation_run: CorrelationRun) -> None:
    assert to_sarif(correlation_run) == to_sarif(correlation_run)


# --- structure, against synthetic edge cases ----------------------------------


def test_empty_run_has_no_results() -> None:
    doc = to_sarif(_synthetic_run())
    assert doc["runs"][0]["results"] == []


def test_finding_with_no_resource_has_no_locations() -> None:
    finding = _finding("test", "R1", "no resource", Severity.INFO)
    doc = to_sarif(_synthetic_run(finding))
    assert doc["runs"][0]["results"][0]["locations"] == []


def test_finding_with_multiple_resources_keeps_one_result() -> None:
    """Many-to-many Finding<->Resource (CLAUDE.md) becomes multiple
    locations on one result, not multiple results."""
    a = MatchKey("aws", "s3", "bucket", "a")
    b = MatchKey("aws", "s3", "bucket", "b")
    finding = _finding("test", "R1", "multi", Severity.LOW, a, b)
    doc = to_sarif(_synthetic_run(finding))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert len(results[0]["locations"]) == 2


def test_two_scanners_same_rule_id_stay_distinct_rules() -> None:
    key = MatchKey("aws", "s3", "bucket", "x")
    f1 = _finding("trivy", "SAME", "from trivy", Severity.LOW, key)
    f2 = _finding("checkov", "SAME", "from checkov", Severity.LOW, key)
    doc = to_sarif(_synthetic_run(f1, f2))
    rule_ids = {rule["id"] for rule in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"trivy/SAME", "checkov/SAME"}


def test_results_sorted_by_resource_id_within_same_rule() -> None:
    key_b = MatchKey("aws", "s3", "bucket", "b")
    key_a = MatchKey("aws", "s3", "bucket", "a")
    f_b = _finding("test", "R1", "b first", Severity.LOW, key_b)
    f_a = _finding("test", "R1", "a first", Severity.LOW, key_a)
    doc = to_sarif(_synthetic_run(f_b, f_a))
    results = doc["runs"][0]["results"]
    resource_ids = [r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] for r in results]
    assert resource_ids == sorted(resource_ids)


# --- cluster / ghost membership (CLAUDE.md, "Step 7") --------------------------


def _bridge(a: MatchKey, b: MatchKey, confidence: float = 0.95) -> BridgeFact:
    return BridgeFact(
        left=a,
        right=b,
        method="observed_together",
        confidence=confidence,
        source="test",
        evidence="test",
    )


def _clustered_run(
    finding: Finding, *, bridge_facts: tuple[BridgeFact, ...], known_keys: tuple[MatchKey, ...]
) -> CorrelationRun:
    """A ScanRun with an explicit `resources` map: real ingest records one
    Resource per resolution (CLAUDE.md, "_record_resource"), which is what
    distinguishes an ordinary cluster member from a ghost. `_synthetic_run`
    leaves `resources` empty, which would make every member look like a
    ghost -- wrong for these tests, so they build the ScanRun directly."""
    resources = {str(k): Resource(key=k) for k in known_keys}
    scan_run = ScanRun(
        scanner="test", findings=[finding], resources=resources, bridge_facts=list(bridge_facts)
    )
    return correlate([scan_run])


def test_no_properties_when_finding_is_not_clustered() -> None:
    finding = _finding(
        "test", "R1", "solo", Severity.LOW, MatchKey("aws", "ec2", "instance", "solo")
    )
    doc = to_sarif(_synthetic_run(finding))
    assert "properties" not in doc["runs"][0]["results"][0]


def test_cluster_members_present_when_finding_is_bridged() -> None:
    a = MatchKey("aws", "ec2", "instance", "a")
    b = MatchKey("aws", "ec2", "instance", "b")
    finding = _finding("test", "R1", "bridged", Severity.LOW, a)
    run = _clustered_run(finding, bridge_facts=(_bridge(a, b),), known_keys=(a, b))
    result = to_sarif(run)["runs"][0]["results"][0]
    assert result["properties"]["cluster_members"] == sorted([str(a), str(b)])


def test_ghost_members_omitted_when_all_members_are_this_runs_own() -> None:
    a = MatchKey("aws", "ec2", "instance", "a")
    b = MatchKey("aws", "ec2", "instance", "b")
    finding = _finding("test", "R1", "bridged", Severity.LOW, a)
    run = _clustered_run(finding, bridge_facts=(_bridge(a, b),), known_keys=(a, b))
    result = to_sarif(run)["runs"][0]["results"][0]
    assert "ghost_members" not in result["properties"]


def test_ghost_members_present_for_key_absent_from_this_runs_resources() -> None:
    """CLAUDE.md, "Step 6": a ghost is a MatchKey present only in history --
    here modelled as a bridge fact endpoint that never got its own Resource
    entry, exactly what a key replayed from the store but absent from this
    run's ingest looks like."""
    a = MatchKey("aws", "ec2", "instance", "a")
    ghost = MatchKey("aws", "ec2", "instance", "ghost")
    finding = _finding("test", "R1", "with ghost", Severity.LOW, a)
    run = _clustered_run(finding, bridge_facts=(_bridge(a, ghost),), known_keys=(a,))
    result = to_sarif(run)["runs"][0]["results"][0]
    assert result["properties"]["ghost_members"] == [str(ghost)]


def test_cluster_members_never_empty_list() -> None:
    """CLAUDE.md task scope: emit cluster_members/ghost_members only when
    non-empty -- never an empty list sitting in properties."""
    finding = _finding(
        "test", "R1", "solo", Severity.LOW, MatchKey("aws", "ec2", "instance", "solo")
    )
    doc = to_sarif(_synthetic_run(finding))
    result = doc["runs"][0]["results"][0]
    if "properties" in result:
        assert result["properties"].get("cluster_members") != []
        assert result["properties"].get("ghost_members") != []
