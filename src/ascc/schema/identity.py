"""Identity resolution. Ядро дифференциации ASCC."""
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum
import re


class RefScheme(StrEnum):
    ARN = "arn"
    TERRAFORM = "terraform"
    CLOUD_ID = "cloud_id"
    NAME = "name"


class IdentityClass(StrEnum):
    NATURAL_NAME = "natural_name"   # имя ресурса совпадает с идентификатором в ARN
    GENERATED_ID = "generated_id"   # cloud-ID не выводится из имени


TF_TYPE_MAP: dict[str, tuple[str, str, IdentityClass]] = {
    "aws_s3_bucket":      ("s3",  "bucket",         IdentityClass.NATURAL_NAME),
    "aws_iam_role":       ("iam", "role",           IdentityClass.NATURAL_NAME),
    "aws_instance":       ("ec2", "instance",       IdentityClass.GENERATED_ID),
    "aws_security_group": ("ec2", "security-group", IdentityClass.GENERATED_ID),
}

ARN_RE = re.compile(
    r"^arn:(?P<partition>[^:]*):(?P<service>[^:]*):(?P<region>[^:]*):"
    r"(?P<account>[^:]*):(?P<tail>.+)$"
)


@dataclass(frozen=True, slots=True)
class ResourceRef:
    """Как конкретный сканер назвал ресурс. Сырое, без нормализации."""
    scheme: RefScheme
    value: str
    scanner: str


@dataclass(frozen=True, slots=True)
class MatchKey:
    """Канонический ключ: aws:s3:bucket:datalake-raw"""
    partition: str
    service: str
    resource_type: str
    identifier: str

    def __str__(self) -> str:
        return f"{self.partition}:{self.service}:{self.resource_type}:{self.identifier}"


@dataclass(frozen=True, slots=True)
class Resolution:
    """Результат резолва плюс провенанс. Не выбрасывай method и confidence:
    без них нельзя объяснить, почему два finding слиты."""
    key: MatchKey
    confidence: float
    method: str
    identity_class: IdentityClass


def _normalize_identifier(raw: str) -> str:
    return raw.strip().lower().replace("_", "-")


def resolve(ref: ResourceRef) -> Resolution | None:
    if ref.scheme is RefScheme.ARN:
        return _from_arn(ref.value)
    if ref.scheme is RefScheme.TERRAFORM:
        return _from_terraform(ref.value)
    return None


def _from_arn(arn: str) -> Resolution | None:
    m = ARN_RE.match(arn)
    if not m:
        return None
    tail = m["tail"]
    if "/" in tail:
        rtype, ident = tail.split("/", 1)
    else:
        rtype = {"s3": "bucket"}.get(m["service"], "resource")
        ident = tail
    return Resolution(
        key=MatchKey(m["partition"] or "aws", m["service"], rtype,
                     _normalize_identifier(ident)),
        confidence=1.0,
        method="arn_parse",
        identity_class=IdentityClass.NATURAL_NAME,
    )


def _from_terraform(address: str) -> Resolution | None:
    if "." not in address:
        return None
    tf_type, tf_name = address.split(".", 1)
    mapped = TF_TYPE_MAP.get(tf_type)
    if mapped is None:
        return None
    service, rtype, ident_class = mapped
    key = MatchKey("aws", service, rtype, _normalize_identifier(tf_name))

    if ident_class is IdentityClass.NATURAL_NAME:
        return Resolution(key, 1.0, "terraform_natural_name", ident_class)

    # generated-id: без мостового факта (тег Name, terraform state)
    # этот ключ НЕ схлопнется с ARN. Низкая уверенность — сигнал для correlate/.
    return Resolution(key, 0.4, "terraform_generated_id_unbridged", ident_class)
