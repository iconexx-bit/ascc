from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ascc.correlate.bridge import build_clusters
from ascc.correlate.run import CorrelationRun, correlate, effective_confidence
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser
from ascc.schema.identity import IdentityClass, MatchKey, RefScheme, Resolution, ResourceRef
from ascc.schema.models import BridgeFact, Finding, Resource, ScanRun
from ascc.schema.taxonomy import Category, Severity


@pytest.fixture(scope="module")
def trivy_run(fixtures_dir: Path) -> ScanRun:
    return TrivyParser().parse(fixtures_dir / "trivy.json")


@pytest.fixture(scope="module")
def prowler_run(fixtures_dir: Path) -> ScanRun:
    return ProwlerParser().parse(fixtures_dir / "prowler.json")


@pytest.fixture(scope="module")
def correlation_run(trivy_run: ScanRun, prowler_run: ScanRun) -> CorrelationRun:
    return correlate([trivy_run, prowler_run])


def _resolution(key: MatchKey, confidence: float) -> Resolution:
    return Resolution(
        key=key, confidence=confidence, method="test", identity_class=IdentityClass.NATURAL_NAME
    )


def _finding(*resolutions: Resolution) -> Finding:
    return Finding(
        scanner="test",
        rule_id="X",
        category=Category.UNCATEGORIZED,
        severity=Severity.INFO,
        title="t",
        resource_ids=[str(r.key) for r in resolutions],
        resolutions=list(resolutions),
    )


def _fact(left: MatchKey, right: MatchKey, confidence: float) -> BridgeFact:
    return BridgeFact(
        left=left,
        right=right,
        method="observed_together",
        confidence=confidence,
        source="test",
        evidence="synthetic",
    )


def test_correlate_yields_two_clusters(correlation_run: CorrelationRun) -> None:
    assert len(correlation_run.clusters) == 2


def test_bucket_resource_merges_refs_from_both_scanners(correlation_run: CorrelationRun) -> None:
    bucket = correlation_run.resources["aws:s3:bucket:datalake-raw"]
    assert {ref.scanner for ref in bucket.refs} == {"trivy", "prowler"}


def test_effective_confidence_composes_across_bridge(correlation_run: CorrelationRun) -> None:
    cve_finding = next(
        f for run in correlation_run.scan_runs for f in run.findings if f.cve == "CVE-2021-44228"
    )
    source_key = MatchKey("aws", "ec2", "instance", "datalake-etl")
    target_key = MatchKey("aws", "ec2", "instance", "i-0a1b2c3d4e5f67890")
    assert cve_finding.resolutions[0].confidence == 0.5
    cluster = next(c for c in correlation_run.clusters if source_key in c.keys)
    assert cluster.direct_confidence(source_key, target_key) == 0.95
    result = effective_confidence(cve_finding, target_key, correlation_run)
    assert result == pytest.approx(0.475, abs=1e-9)


def test_effective_confidence_none_for_indirect_pair() -> None:
    a = MatchKey("aws", "ec2", "instance", "a")
    b = MatchKey("aws", "ec2", "instance", "b")
    c = MatchKey("aws", "ec2", "instance", "c")
    clusters = tuple(build_clusters([_fact(a, b, 0.9), _fact(b, c, 0.8)]))
    run = CorrelationRun(scan_runs=(), resources={}, clusters=clusters, tag_conflicts=())
    finding = _finding(_resolution(a, 0.9))
    assert effective_confidence(finding, c, run) is None


def test_effective_confidence_takes_best_path() -> None:
    k1 = MatchKey("aws", "ec2", "instance", "k1")
    k2 = MatchKey("aws", "ec2", "instance", "k2")
    target = MatchKey("aws", "ec2", "instance", "target")
    clusters = tuple(build_clusters([_fact(k1, target, 0.95), _fact(k2, target, 0.5)]))
    run = CorrelationRun(scan_runs=(), resources={}, clusters=clusters, tag_conflicts=())
    forward = _finding(_resolution(k1, 0.4), _resolution(k2, 0.9))
    reversed_ = _finding(_resolution(k2, 0.9), _resolution(k1, 0.4))
    assert effective_confidence(forward, target, run) == pytest.approx(0.45, abs=1e-9)
    assert effective_confidence(reversed_, target, run) == pytest.approx(0.45, abs=1e-9)


def test_effective_confidence_skips_resolution_without_direct_fact() -> None:
    k1 = MatchKey("aws", "ec2", "instance", "k1")
    k2 = MatchKey("aws", "ec2", "instance", "k2")
    m = MatchKey("aws", "ec2", "instance", "m")
    target = MatchKey("aws", "ec2", "instance", "target")
    clusters = tuple(
        build_clusters([_fact(k1, target, 0.95), _fact(k2, m, 0.9), _fact(m, target, 0.9)])
    )
    run = CorrelationRun(scan_runs=(), resources={}, clusters=clusters, tag_conflicts=())
    finding = _finding(_resolution(k2, 0.9), _resolution(k1, 0.4))
    assert effective_confidence(finding, target, run) == pytest.approx(0.38, abs=1e-9)


def test_scan_runs_unchanged_after_correlate(trivy_run: ScanRun, prowler_run: ScanRun) -> None:
    before = {
        "trivy": (len(trivy_run.findings), len(trivy_run.resources), len(trivy_run.bridge_facts)),
        "prowler": (
            len(prowler_run.findings),
            len(prowler_run.resources),
            len(prowler_run.bridge_facts),
        ),
    }
    correlate([trivy_run, prowler_run])
    after = {
        "trivy": (len(trivy_run.findings), len(trivy_run.resources), len(trivy_run.bridge_facts)),
        "prowler": (
            len(prowler_run.findings),
            len(prowler_run.resources),
            len(prowler_run.bridge_facts),
        ),
    }
    assert before == after


def test_no_tag_conflicts_in_fixture(correlation_run: CorrelationRun) -> None:
    assert correlation_run.tag_conflicts == ()


def test_tag_conflict_resolved_by_higher_confidence() -> None:
    key = MatchKey("aws", "s3", "bucket", "shared")
    ref_a = ResourceRef(scheme=RefScheme.ARN, value="arn:aws:s3:::shared", scanner="scanner_a")
    ref_b = ResourceRef(
        scheme=RefScheme.TERRAFORM, value="aws_s3_bucket.shared", scanner="scanner_b"
    )
    resource_a = Resource(
        key=key,
        refs=[ref_a],
        resolutions=[_resolution(key, 1.0)],
        tags={"DataClassification": "PII"},
    )
    resource_b = Resource(
        key=key,
        refs=[ref_b],
        resolutions=[_resolution(key, 0.4)],
        tags={"DataClassification": "internal"},
    )
    started_at = datetime(2026, 1, 1, tzinfo=UTC)
    run_a = ScanRun(scanner="scanner_a", started_at=started_at, resources={str(key): resource_a})
    run_b = ScanRun(scanner="scanner_b", started_at=started_at, resources={str(key): resource_b})

    result = correlate([run_a, run_b])

    assert result.resources[str(key)].tags["DataClassification"] == "PII"
    assert len(result.tag_conflicts) == 1
    conflict = result.tag_conflicts[0]
    assert conflict.resource_key == key
    assert conflict.tag_key == "DataClassification"
    assert conflict.values == (("scanner_a", "PII"), ("scanner_b", "internal"))
