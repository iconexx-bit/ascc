"""Prowler checks of an account-wide setting name the account, not a resource (O50).

For a setting of the whole account (S3 Block Public Access, EBS default
encryption, IMDSv2 default, the root user, the password policy) Prowler puts a
pseudo-ARN in `resources[].uid` (`...:account`, `...:root`, a bare
`...:volume`, `...:password-policy`) and the account ID in `name`. ASCC read
the uid as a bucket, an instance or an untyped resource, and the name as a
second identifier observed together with it, so two clusters joined things
that are not one resource (`aws:ec2:resource:account` with
`aws:ec2:instance:123456789012`; the AWS-managed `AWSSupportAccess` policy with
`aws:iam:role:123456789012`), and `aws:s3:bucket:account` became a bucket node
that a `*/*` role "can access". Now such a uid resolves to
`aws:<service>:account:<account ID>`, and a name equal to the account ID is
not an identifier.
"""

from __future__ import annotations

import json
from pathlib import Path

from ascc.correlate.run import correlate
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL = REPO_ROOT / "fixtures" / "leaky_data_lake_real"
ACCOUNT = "123456789012"
ROLE_PATH_CLUSTERS = [
    ["aws:iam:role:accountfullaccessrole", "aws:iam:role:managed/accountfullaccessrole"],
    [
        (
            "aws:iam:role:aws-service-role/spendlimit-member.budgets.amazonaws.com/"
            "awsserviceroleforbudgetsspendlimitmember"
        ),
        "aws:iam:role:awsserviceroleforbudgetsspendlimitmember",
    ],
    [
        "aws:iam:role:aws-service-role/support.amazonaws.com/awsserviceroleforsupport",
        "aws:iam:role:awsserviceroleforsupport",
    ],
]
ACCOUNT_KEYS = {f"aws:{service}:account:{ACCOUNT}" for service in ("ec2", "iam", "s3")}
PSEUDO_KEYS = {
    "aws:s3:bucket:account",
    "aws:ec2:resource:account",
    "aws:ec2:resource:volume",
    "aws:iam:resource:root",
    "aws:iam:resource:password-policy",
    f"aws:ec2:instance:{ACCOUNT}",
    f"aws:iam:role:{ACCOUNT}",
}


def _real_run():
    return correlate(
        [
            ProwlerParser().parse(REAL / "prowler.json"),
            TrivyParser().parse(REAL / "trivy-config.json"),
            TrivyParser().parse(REAL / "trivy-rootfs.json"),
            CheckovParser().parse(REAL / "checkov.json"),
        ]
    )


def test_only_role_path_clusters_remain_on_real_output() -> None:
    clusters = sorted(sorted(str(key) for key in c.keys) for c in _real_run().clusters)
    assert clusters == ROLE_PATH_CLUSTERS


def test_account_wide_checks_sit_on_account_keys() -> None:
    keys = set(ProwlerParser().parse(REAL / "prowler.json").resources)
    assert ACCOUNT_KEYS <= keys
    assert not keys & PSEUDO_KEYS


def test_a_name_equal_to_the_account_id_is_not_an_identifier() -> None:
    facts = ProwlerParser().parse(REAL / "prowler.json").bridge_facts
    assert facts
    assert not [f for f in facts if f.evidence.endswith(f"name={ACCOUNT}")]


def test_resource_arns_keep_their_type(tmp_path: Path) -> None:
    # A bucket ARN has no account; an SNS topic ARN has no "/" but its own name;
    # a volume ARN names its volume even when `name` is the account ID.
    entries = json.loads((REAL / "prowler.json").read_text(encoding="utf-8"))
    entry = next(e for e in entries if e["status_code"] == "FAIL")
    entry = json.loads(json.dumps(entry))
    entry["resources"] = [
        {"uid": "arn:aws:s3:::datalake-raw", "type": "AwsS3Bucket", "name": "datalake-raw"},
        {
            "uid": f"arn:aws:sns:us-east-2:{ACCOUNT}:alerts",
            "type": "AwsSnsTopic",
            "name": "alerts",
        },
        {
            "uid": f"arn:aws:ec2:us-east-2:{ACCOUNT}:volume/vol-0abc",
            "type": "AwsEc2Volume",
            "name": ACCOUNT,
        },
    ]
    path = tmp_path / "prowler.json"
    path.write_text(json.dumps([entry]), encoding="utf-8")
    keys = set(ProwlerParser().parse(path).resources)
    assert keys == {
        "aws:s3:bucket:datalake-raw",
        "aws:sns:resource:alerts",
        "aws:ec2:volume:vol-0abc",
    }


def test_the_account_key_names_the_account_in_the_arn(tmp_path: Path) -> None:
    other = "111122223333"
    entries = json.loads((REAL / "prowler.json").read_text(encoding="utf-8"))
    entry = json.loads(json.dumps(next(e for e in entries if e["status_code"] == "FAIL")))
    entry["resources"] = [
        {
            "uid": f"arn:aws:s3:us-east-2:{other}:account",
            "type": "AwsS3AccountPublicAccessBlock",
            "name": other,
        }
    ]
    path = tmp_path / "prowler.json"
    path.write_text(json.dumps([entry]), encoding="utf-8")
    assert set(ProwlerParser().parse(path).resources) == {f"aws:s3:account:{other}"}


def test_contract_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "A Prowler check of an account-wide setting" in text
    assert "`aws:<service>:account:<account ID>`" in text
