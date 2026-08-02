"""Baseline of the pre-bridge state. These tests are expected to FAIL the
day IdentityBridge lands: that is the plan, not a regression. Update
them together with the bridge, never "fix" them in isolation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser
from ascc.schema.models import ScanRun


@pytest.fixture(scope="module")
def trivy_run(fixtures_dir: Path) -> ScanRun:
    return TrivyParser().parse(fixtures_dir / "trivy.json")


@pytest.fixture(scope="module")
def prowler_run(fixtures_dir: Path) -> ScanRun:
    return ProwlerParser().parse(fixtures_dir / "prowler.json")


def test_ec2_instance_has_two_unbridged_keys(trivy_run: ScanRun, prowler_run: ScanRun) -> None:
    trivy_ec2 = {k for k in trivy_run.resources if k.startswith("aws:ec2:instance:")}
    prowler_ec2 = {k for k in prowler_run.resources if k.startswith("aws:ec2:instance:")}
    assert trivy_ec2 == {"aws:ec2:instance:datalake-etl"}
    assert prowler_ec2 == {"aws:ec2:instance:i-0a1b2c3d4e5f67890"}
    assert trivy_ec2.isdisjoint(prowler_ec2)


def test_security_group_has_two_unbridged_keys(trivy_run: ScanRun, prowler_run: ScanRun) -> None:
    trivy_sg = {k for k in trivy_run.resources if k.startswith("aws:ec2:security-group:")}
    prowler_sg = {k for k in prowler_run.resources if k.startswith("aws:ec2:security-group:")}
    assert trivy_sg == {"aws:ec2:security-group:datalake-etl-sg"}
    assert prowler_sg == {"aws:ec2:security-group:sg-0f9e8d7c6b5a43210"}
    assert trivy_sg.isdisjoint(prowler_sg)


def test_bucket_collapses_across_scanners(trivy_run: ScanRun, prowler_run: ScanRun) -> None:
    key = "aws:s3:bucket:datalake-raw"
    trivy_bucket = trivy_run.resources[key]
    prowler_bucket = prowler_run.resources[key]
    assert trivy_bucket.resolutions[0].confidence == 1.0
    assert prowler_bucket.resolutions[0].confidence == 1.0
    assert trivy_bucket.resolutions[0].method == "terraform_natural_name"
    assert prowler_bucket.resolutions[0].method == "arn_parse"


def test_prowler_carries_bridging_evidence(fixtures_dir: Path) -> None:
    entries = json.loads((fixtures_dir / "prowler.json").read_text())
    uid_to_name = {
        resource["uid"]: resource["name"]
        for entry in entries
        for resource in entry["resources"]
        if "uid" in resource and "name" in resource
    }
    assert uid_to_name == {
        "arn:aws:s3:::datalake-raw": "datalake-raw",
        "arn:aws:iam::123456789012:role/datalake-etl-role": "datalake-etl-role",
        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0f9e8d7c6b5a43210": "datalake-etl-sg",
        "arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f67890": "datalake-etl",
    }


def test_iam_role_seen_by_prowler_only(trivy_run: ScanRun, prowler_run: ScanRun) -> None:
    key = "aws:iam:role:datalake-etl-role"
    assert key in prowler_run.resources
    assert key not in trivy_run.resources
