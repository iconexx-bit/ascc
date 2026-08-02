from __future__ import annotations

from pathlib import Path

import pytest

from ascc.ingest.prowler import ProwlerParser
from ascc.schema.models import ScanRun
from ascc.schema.taxonomy import Severity


@pytest.fixture(scope="module")
def scan_run(fixtures_dir: Path) -> ScanRun:
    return ProwlerParser().parse(fixtures_dir / "prowler.json")


def test_fixture_yields_six_findings(scan_run: ScanRun) -> None:
    assert len(scan_run.findings) == 6


def test_every_finding_binds_to_a_resource(scan_run: ScanRun) -> None:
    assert all(finding.resource_ids for finding in scan_run.findings)


def test_all_resolutions_use_arn_parse(scan_run: ScanRun) -> None:
    methods = {r.method for f in scan_run.findings for r in f.resolutions}
    assert methods == {"arn_parse"}


def test_all_resolutions_have_full_confidence(scan_run: ScanRun) -> None:
    confidences = {r.confidence for f in scan_run.findings for r in f.resolutions}
    assert confidences == {1.0}


def test_severity_mapping_critical(scan_run: ScanRun) -> None:
    finding = next(
        f for f in scan_run.findings if f.rule_id == "s3_bucket_level_public_access_block"
    )
    assert finding.severity is Severity.CRITICAL


def test_pass_records_excluded_from_findings(scan_run: ScanRun) -> None:
    assert all(f.raw["status_code"] == "FAIL" for f in scan_run.findings)


def test_bucket_tags_extracted_include_pii(scan_run: ScanRun) -> None:
    bucket = scan_run.resources["aws:s3:bucket:datalake-raw"]
    assert bucket.tags["DataClassification"] == "PII"


def test_resources_deduplicated_by_key(scan_run: ScanRun) -> None:
    assert len(scan_run.resources) == 4


def test_repeated_resource_merges_refs(scan_run: ScanRun) -> None:
    """Три находки Prowler ссылаются на один и тот же бакет.

    Если реализация при повторной встрече ресурса перезаписывает
    Resource целиком вместо слияния, test_resources_deduplicated_by_key
    всё равно даст len == 4 (ключ один и тот же) — эта регрессия молча
    пройдёт мимо него. Только счётчик refs ловит потерю накопления.
    """
    bucket = scan_run.resources["aws:s3:bucket:datalake-raw"]
    assert len(bucket.refs) == 3


def test_parse_accepts_str_path(fixtures_dir: Path, scan_run: ScanRun) -> None:
    str_run = ProwlerParser().parse(str(fixtures_dir / "prowler.json"))
    assert len(str_run.findings) == len(scan_run.findings)
    assert set(str_run.resources) == set(scan_run.resources)


def test_prowler_bridges_exactly_ec2_and_security_group(scan_run: ScanRun) -> None:
    pairs = {frozenset((str(f.left), str(f.right))) for f in scan_run.bridge_facts}
    assert pairs == {
        frozenset(("aws:ec2:instance:datalake-etl", "aws:ec2:instance:i-0a1b2c3d4e5f67890")),
        frozenset(
            (
                "aws:ec2:security-group:datalake-etl-sg",
                "aws:ec2:security-group:sg-0f9e8d7c6b5a43210",
            )
        ),
    }


def test_bridge_fact_evidence_names_the_observation(scan_run: ScanRun) -> None:
    assert all("arn:aws:" in f.evidence and "name=" in f.evidence for f in scan_run.bridge_facts)
