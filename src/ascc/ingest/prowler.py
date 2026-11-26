from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ascc.schema.identity import (
    ARN_RE,
    IdentityClass,
    MatchKey,
    RefScheme,
    Resolution,
    ResourceRef,
    resolve,
)
from ascc.schema.models import BridgeFact, Finding, Resource, ScanRun
from ascc.schema.taxonomy import Category, Severity

from .base import ScannerParser

_EVENT_CATEGORY: dict[str, Category] = {
    "s3_bucket_level_public_access_block": Category.PUBLIC_ACCESS,
    "s3_bucket_default_encryption": Category.ENCRYPTION_AT_REST,
    "s3_bucket_server_access_logging_enabled": Category.LOGGING_DISABLED,
    "iam_inline_policy_no_administrative_privileges": Category.EXCESSIVE_PRIVILEGE,
    "ec2_securitygroup_allow_ingress_from_internet_to_port_22": Category.NETWORK_EXPOSURE,
    "ec2_instance_public_ip": Category.NETWORK_EXPOSURE,
    # Current Prowler IDs of the same entries (real output, 5.46); the full
    # table of real IDs is O48.
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": Category.NETWORK_EXPOSURE,
    "ec2_instance_port_ssh_exposed_to_internet": Category.NETWORK_EXPOSURE,
}

_PROWLER_TYPE_TO_TF_TYPE: dict[str, str] = {
    "AwsS3Bucket": "aws_s3_bucket",
    "AwsEc2Instance": "aws_instance",
    "AwsIamRole": "aws_iam_role",
    "AwsEc2SecurityGroup": "aws_security_group",
}


def _parse_timestamp(raw: float | str) -> datetime:
    # Current OCSF output carries epoch seconds; older output and the
    # synthetic fixture an ISO 8601 string.
    if isinstance(raw, bool):
        raise TypeError("created_time must be epoch seconds or an ISO 8601 string")
    if isinstance(raw, int | float):
        return datetime.fromtimestamp(raw, tz=UTC)
    return datetime.fromisoformat(raw)


def _account_of(entry: dict) -> str | None:
    cloud = entry.get("cloud")
    account = cloud.get("account") if isinstance(cloud, dict) else None
    uid = account.get("uid") if isinstance(account, dict) else None
    return uid if isinstance(uid, str) and uid else None


def _account_scope(uid: str, name: object) -> Resolution | None:
    """A check of an account-wide setting names the account, not a resource.

    Prowler gives such a check a pseudo-ARN in the account (`...:account`,
    `...:root`, `...:password-policy`, a bare `...:volume`) and the account ID
    as the name. An ARN with an account ID whose resource part has no "/" and
    no ":", and that is `account` or `root` or carries that account ID as its
    name, resolves to aws:<service>:account:<account ID of the ARN>
    (CLAUDE.md, "Contracts"; runbook O50). An SNS topic or an S3 bucket keeps
    its type.
    """
    m = ARN_RE.match(uid)
    if m is None or not m["account"]:
        return None
    tail = m["tail"]
    if "/" in tail or ":" in tail:
        return None
    if tail not in ("account", "root") and name != m["account"]:
        return None
    return Resolution(
        key=MatchKey(m["partition"] or "aws", m["service"], "account", m["account"]),
        confidence=1.0,
        method="arn_parse",
        identity_class=IdentityClass.NATURAL_NAME,
    )


def _tags_dict(tags: list[dict[str, str]]) -> dict[str, str]:
    return {tag["key"]: tag["value"] for tag in tags}


def _resource_tags(resource_data: dict) -> dict[str, str]:
    # Synthetic fixture: resources[].tags as [{key, value}]. Current OCSF:
    # resources[].tags is absent or null, tags are data.metadata.tags as
    # [{Key, Value}] (CLAUDE.md, "Graph and chains (A2)").
    tags = _tags_dict(resource_data.get("tags") or [])
    data = resource_data.get("data")
    metadata = data.get("metadata") if isinstance(data, dict) else None
    for tag in (metadata.get("tags") if isinstance(metadata, dict) else None) or ():
        if (
            isinstance(tag, dict)
            and isinstance(tag.get("Key"), str)
            and isinstance(tag.get("Value"), str)
        ):
            tags.setdefault(tag["Key"], tag["Value"])
    return tags


class ProwlerParser(ScannerParser):
    @property
    def scanner_name(self) -> str:
        return "prowler"

    @classmethod
    def sniff(cls, data: dict | list) -> bool:
        return (
            isinstance(data, list)
            and bool(data)
            and isinstance(data[0], dict)
            and "finding_info" in data[0]
            and "status_code" in data[0]
        )

    def parse(self, path: str | Path) -> ScanRun:
        path = Path(path)
        entries = json.loads(path.read_text(encoding="utf-8"))
        started_at = min(_parse_timestamp(e["finding_info"]["created_time"]) for e in entries)
        resources: dict[str, Resource] = {}
        bridge_facts: list[BridgeFact] = []
        findings = [
            self._finding(entry, resources, bridge_facts)
            for entry in entries
            if entry["status_code"] == "FAIL"
        ]
        return ScanRun(
            scanner=self.scanner_name,
            started_at=started_at,
            findings=findings,
            resources=resources,
            bridge_facts=bridge_facts,
        )

    def _finding(
        self, entry: dict, resources: dict[str, Resource], bridge_facts: list[BridgeFact]
    ) -> Finding:
        rule_id = entry["metadata"]["event_code"]
        account = _account_of(entry)
        resource_ids: list[str] = []
        resolutions: list[Resolution] = []
        for resource_data in entry["resources"]:
            ref = ResourceRef(
                scheme=RefScheme.ARN, value=resource_data["uid"], scanner=self.scanner_name
            )
            resolution = _account_scope(resource_data["uid"], resource_data.get("name"))
            if resolution is None:
                resolution = resolve(ref)
            if resolution is None:
                continue
            resource_ids.append(str(resolution.key))
            resolutions.append(resolution)
            self._record_resource(resources, resolution, ref, resource_data)
            self._record_bridge_fact(bridge_facts, resolution, resource_data, account)
        return Finding(
            scanner=self.scanner_name,
            rule_id=rule_id,
            category=_EVENT_CATEGORY.get(rule_id, Category.UNCATEGORIZED),
            severity=Severity.from_ocsf(entry["severity_id"]),
            title=entry["finding_info"]["title"],
            resource_ids=resource_ids,
            resolutions=resolutions,
            cve=None,
            raw=entry,
        )

    def _record_resource(
        self,
        resources: dict[str, Resource],
        resolution: Resolution,
        ref: ResourceRef,
        resource_data: dict,
    ) -> None:
        key_str = str(resolution.key)
        tags = _resource_tags(resource_data)
        existing = resources.get(key_str)
        if existing is None:
            resources[key_str] = Resource(
                key=resolution.key,
                refs=[ref],
                resolutions=[resolution],
                tags=tags,
            )
            return
        existing.refs.append(ref)
        existing.resolutions.append(resolution)
        existing.tags.update(tags)

    def _record_bridge_fact(
        self,
        bridge_facts: list[BridgeFact],
        uid_resolution: Resolution,
        resource_data: dict,
        account: str | None = None,
    ) -> None:
        """uid и name наблюдены Prowler в одной записи resources[] — это
        свидетельство, что оба идентификатора называют один ресурс.

        ResourceRef(scheme=TERRAFORM, ...) здесь собран из name, который
        дал Prowler, а не из настоящего Terraform — Prowler никакого
        Terraform не видел. Это зонд: "какой ключ построил бы Trivy из
        этого имени", нужен только ради .key для сравнения с
        uid_resolution.key. Сам name_resolution (объект Resolution)
        никуда не сохраняется — ни в Finding.resolutions, ни в Resource.
        """
        name = resource_data.get("name")
        tf_type = _PROWLER_TYPE_TO_TF_TYPE.get(resource_data.get("type", ""))
        if not name or tf_type is None:
            return
        if name == account:
            # Account-wide checks carry the account ID as the name: it names
            # the account, not a second identifier of the resource (O50).
            return
        name_ref = ResourceRef(
            scheme=RefScheme.TERRAFORM, value=f"{tf_type}.{name}", scanner=self.scanner_name
        )
        name_resolution = resolve(name_ref)
        if name_resolution is None or name_resolution.key == uid_resolution.key:
            return
        fact = BridgeFact(
            left=uid_resolution.key,
            right=name_resolution.key,
            method="observed_together",
            confidence=0.95,
            source=self.scanner_name,
            evidence=f"{resource_data['uid']} name={name}",
        )
        if fact not in bridge_facts:
            bridge_facts.append(fact)
