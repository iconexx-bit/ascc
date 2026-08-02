from __future__ import annotations

import pytest

from ascc.schema.identity import RefScheme, ResourceRef, resolve


def test_terraform_and_arn_collapse_to_same_key() -> None:
    arn_resolution = resolve(
        ResourceRef(scheme=RefScheme.ARN, value="arn:aws:s3:::datalake-raw", scanner="prowler")
    )
    tf_resolution = resolve(
        ResourceRef(
            scheme=RefScheme.TERRAFORM, value="aws_s3_bucket.datalake_raw", scanner="checkov"
        )
    )
    assert arn_resolution is not None
    assert tf_resolution is not None
    assert arn_resolution.key == tf_resolution.key
    assert arn_resolution.confidence == 1.0
    assert tf_resolution.confidence == 1.0


def test_iam_role_collapses() -> None:
    arn_resolution = resolve(
        ResourceRef(
            scheme=RefScheme.ARN,
            value="arn:aws:iam::123456789012:role/datalake-etl-role",
            scanner="prowler",
        )
    )
    tf_resolution = resolve(
        ResourceRef(
            scheme=RefScheme.TERRAFORM,
            value="aws_iam_role.datalake_etl_role",
            scanner="checkov",
        )
    )
    assert arn_resolution is not None
    assert tf_resolution is not None
    assert arn_resolution.key == tf_resolution.key
    assert arn_resolution.confidence == 1.0
    assert tf_resolution.confidence == 1.0


def test_ec2_generated_id_does_not_collapse() -> None:
    """EC2-инстанс — generated-id ресурс: cloud-ID (i-0a1b2...) не выводится
    из terraform-имени (datalake_etl) без bridging-факта (тег Name,
    terraform state). Это зафиксированное ограничение (known limitation из
    README фикстуры leaky_data_lake), а не баг. Тест защищает его от
    случайной "починки" через более агрессивную нормализацию идентификаторов.
    """
    arn_resolution = resolve(
        ResourceRef(
            scheme=RefScheme.ARN,
            value="arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f67890",
            scanner="prowler",
        )
    )
    tf_resolution = resolve(
        ResourceRef(
            scheme=RefScheme.TERRAFORM, value="aws_instance.datalake_etl", scanner="checkov"
        )
    )
    assert arn_resolution is not None
    assert tf_resolution is not None
    assert arn_resolution.key != tf_resolution.key
    assert tf_resolution.confidence == 0.4
    assert tf_resolution.method == "terraform_generated_id_unbridged"


def test_security_group_generated_id_does_not_collapse() -> None:
    """Security Group — тоже generated-id ресурс: то же ограничение, что и
    у EC2-инстанса в test_ec2_generated_id_does_not_collapse.
    """
    arn_resolution = resolve(
        ResourceRef(
            scheme=RefScheme.ARN,
            value="arn:aws:ec2:us-east-1:123456789012:security-group/sg-0f9e8d7c6b5a43210",
            scanner="prowler",
        )
    )
    tf_resolution = resolve(
        ResourceRef(
            scheme=RefScheme.TERRAFORM,
            value="aws_security_group.datalake_etl_sg",
            scanner="checkov",
        )
    )
    assert arn_resolution is not None
    assert tf_resolution is not None
    assert arn_resolution.key != tf_resolution.key
    assert tf_resolution.confidence == 0.4
    assert tf_resolution.method == "terraform_generated_id_unbridged"


def test_unknown_terraform_type_returns_none() -> None:
    resolution = resolve(
        ResourceRef(scheme=RefScheme.TERRAFORM, value="aws_lambda_function.foo", scanner="checkov")
    )
    assert resolution is None


@pytest.mark.parametrize("value", ["not-an-arn", "arn:incomplete", ""])
def test_malformed_arn_returns_none(value: str) -> None:
    resolution = resolve(ResourceRef(scheme=RefScheme.ARN, value=value, scanner="prowler"))
    assert resolution is None
