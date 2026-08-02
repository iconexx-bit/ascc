from __future__ import annotations

from pathlib import Path

import pytest

from ascc.ingest.trivy import TrivyParser
from ascc.schema.models import ScanRun
from ascc.schema.taxonomy import Category, Severity


@pytest.fixture(scope="module")
def scan_run(fixtures_dir: Path) -> ScanRun:
    return TrivyParser().parse(fixtures_dir / "trivy.json")


def test_fixture_yields_six_findings(scan_run: ScanRun) -> None:
    assert len(scan_run.findings) == 6


def test_every_finding_binds_to_a_resource(scan_run: ScanRun) -> None:
    assert all(finding.resource_ids for finding in scan_run.findings)


def test_cve_findings_bind_to_host_with_heuristic_confidence(scan_run: ScanRun) -> None:
    vuln_findings = [f for f in scan_run.findings if f.category is Category.VULNERABILITY]
    assert len(vuln_findings) == 4
    for finding in vuln_findings:
        assert finding.resource_ids == ["aws:ec2:instance:datalake-etl"]
        assert finding.min_confidence == 0.5
        assert finding.resolutions[0].method == "filesystem_path_heuristic"


def test_bucket_misconfig_is_deterministic(scan_run: ScanRun) -> None:
    finding = next(f for f in scan_run.findings if f.rule_id == "AVD-AWS-0028")
    assert finding.resource_ids == ["aws:s3:bucket:datalake-raw"]
    assert finding.min_confidence == 1.0
    assert finding.resolutions[0].method == "terraform_natural_name"


def test_severity_mapping(scan_run: ScanRun) -> None:
    by_cve = {f.cve: f.severity for f in scan_run.findings if f.cve}
    assert by_cve["CVE-2021-44228"] is Severity.CRITICAL
    assert by_cve["CVE-2023-38545"] is Severity.MEDIUM


def test_dedup_key_is_stable(fixtures_dir: Path) -> None:
    path = fixtures_dir / "trivy.json"
    first = TrivyParser().parse(path)
    second = TrivyParser().parse(path)
    first_by_rule = {f.rule_id: f.dedup_key for f in first.findings}
    second_by_rule = {f.rule_id: f.dedup_key for f in second.findings}
    assert first_by_rule == second_by_rule


def test_sg_misconfig_confidence_is_low(scan_run) -> None:
    """SG резолвится через generated-id без моста — уверенность низкая.

    Дополняет test_bucket_misconfig_is_deterministic: тот проверяет
    достоверный резолв (1.0), этот — эвристический (0.4). Оба уровня
    должны быть зафиксированы, иначе регрессия в одном пройдёт молча.
    """
    finding = next(f for f in scan_run.findings if f.rule_id == "AVD-AWS-0107")
    assert finding.min_confidence == 0.4
    assert finding.resolutions[0].method == "terraform_generated_id_unbridged"


def test_resources_count_matches_fixture(scan_run: ScanRun) -> None:
    assert len(scan_run.resources) == 3


def test_repeated_host_resource_merges_refs(scan_run: ScanRun) -> None:
    """Хост встречается в 4 находках (по одной на CVE) с одним и тем же ref.

    Если реализация при повторной встрече ресурса перезаписывает Resource
    целиком вместо слияния, test_resources_count_matches_fixture всё равно
    даст len == 3 (ключ один и тот же) — эта регрессия молча пройдёт мимо
    него. Только счётчик refs ловит потерю накопления.
    """
    host = scan_run.resources["aws:ec2:instance:datalake-etl"]
    assert len(host.refs) == 4


def test_resource_keys_match_finding_resource_ids(scan_run: ScanRun) -> None:
    finding_resource_ids = {rid for f in scan_run.findings for rid in f.resource_ids}
    assert set(scan_run.resources) == finding_resource_ids


def test_bucket_resource_resolution_confidence(scan_run: ScanRun) -> None:
    bucket = scan_run.resources["aws:s3:bucket:datalake-raw"]
    assert bucket.resolutions[0].confidence == 1.0


def test_bucket_resource_resolution_method(scan_run: ScanRun) -> None:
    bucket = scan_run.resources["aws:s3:bucket:datalake-raw"]
    assert bucket.resolutions[0].method == "terraform_natural_name"


def test_trivy_resources_have_no_tags(scan_run: ScanRun) -> None:
    assert all(resource.tags == {} for resource in scan_run.resources.values())
