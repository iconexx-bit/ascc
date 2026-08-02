"""Post-bridge state. IdentityBridge is wired into correlate() now: the
EC2 instance and security group keys that used to be two disjoint,
unbridged identifiers per resource now share a cluster with a direct
bridge fact. The bucket and IAM role were never a gap — they already
collapsed to the same key by construction, and the bridge changes
nothing about them. Update these tests together with correlate(),
never independently of what it actually does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ascc.correlate.run import CorrelationRun, correlate
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser
from ascc.schema.identity import MatchKey
from ascc.schema.models import ScanRun


@pytest.fixture(scope="module")
def trivy_run(fixtures_dir: Path) -> ScanRun:
    return TrivyParser().parse(fixtures_dir / "trivy.json")


@pytest.fixture(scope="module")
def prowler_run(fixtures_dir: Path) -> ScanRun:
    return ProwlerParser().parse(fixtures_dir / "prowler.json")


@pytest.fixture(scope="module")
def correlation_run(trivy_run: ScanRun, prowler_run: ScanRun) -> CorrelationRun:
    return correlate([trivy_run, prowler_run])


def test_ec2_instance_keys_share_one_cluster(correlation_run: CorrelationRun) -> None:
    trivy_key = MatchKey("aws", "ec2", "instance", "datalake-etl")
    prowler_key = MatchKey("aws", "ec2", "instance", "i-0a1b2c3d4e5f67890")
    cluster = next(c for c in correlation_run.clusters if trivy_key in c.keys)
    assert prowler_key in cluster.keys
    path = cluster.path(trivy_key, prowler_key)
    assert path is not None
    assert len(path) == 1
    assert cluster.direct_confidence(trivy_key, prowler_key) == 0.95


def test_security_group_keys_share_one_cluster(correlation_run: CorrelationRun) -> None:
    trivy_key = MatchKey("aws", "ec2", "security-group", "datalake-etl-sg")
    prowler_key = MatchKey("aws", "ec2", "security-group", "sg-0f9e8d7c6b5a43210")
    cluster = next(c for c in correlation_run.clusters if trivy_key in c.keys)
    assert prowler_key in cluster.keys
    path = cluster.path(trivy_key, prowler_key)
    assert path is not None
    assert len(path) == 1
    assert cluster.direct_confidence(trivy_key, prowler_key) == 0.95


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
