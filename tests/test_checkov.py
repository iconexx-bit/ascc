from __future__ import annotations

from pathlib import Path

import pytest

from ascc.ingest.checkov import CheckovParser
from ascc.schema.models import ScanRun
from ascc.schema.taxonomy import Severity


@pytest.fixture(scope="module")
def scan_run(fixtures_dir: Path) -> ScanRun:
    return CheckovParser().parse(fixtures_dir / "checkov.json")


def test_fixture_yields_four_findings(scan_run: ScanRun) -> None:
    assert len(scan_run.findings) == 4


def test_every_finding_binds_to_a_resource(scan_run: ScanRun) -> None:
    assert all(finding.resource_ids for finding in scan_run.findings)


def test_bucket_findings_resolve_deterministically(scan_run: ScanRun) -> None:
    bucket_findings = [
        f for f in scan_run.findings if f.resource_ids == ["aws:s3:bucket:datalake-raw"]
    ]
    assert len(bucket_findings) == 3
    for finding in bucket_findings:
        assert finding.min_confidence == 1.0
        assert finding.resolutions[0].method == "terraform_natural_name"


def test_iam_role_finding_resolves_deterministically(scan_run: ScanRun) -> None:
    finding = next(f for f in scan_run.findings if f.rule_id == "CKV_AWS_40")
    assert finding.resource_ids == ["aws:iam:role:datalake-etl-role"]
    assert finding.min_confidence == 1.0
    assert finding.resolutions[0].method == "terraform_natural_name"


def test_severity_mapping(scan_run: ScanRun) -> None:
    finding = next(f for f in scan_run.findings if f.rule_id == "CKV_AWS_40")
    assert finding.severity is Severity.CRITICAL


def test_bridge_facts_empty(scan_run: ScanRun) -> None:
    """Checkov сообщает один terraform-адрес на находку (resource и
    resource_address дублируют одно и то же значение), а не пару
    независимых представлений идентификатора в одной записи, как
    Prowler (uid + name). Свидетельству для моста взяться неоткуда.
    """
    assert scan_run.bridge_facts == []


def test_checkov_reports_no_scan_time(scan_run: ScanRun) -> None:
    """checkov.json carries no scan time; inventing one would be a lie
    about when the observation happened."""
    assert scan_run.started_at is None
