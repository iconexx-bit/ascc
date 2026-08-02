from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ascc.schema.identity import RefScheme, Resolution, ResourceRef, resolve
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
}

_PROWLER_TYPE_TO_TF_TYPE: dict[str, str] = {
    "AwsS3Bucket": "aws_s3_bucket",
    "AwsEc2Instance": "aws_instance",
    "AwsIamRole": "aws_iam_role",
    "AwsEc2SecurityGroup": "aws_security_group",
}


def _parse_timestamp(raw: str) -> datetime:
    return datetime.fromisoformat(raw)


def _tags_dict(tags: list[dict[str, str]]) -> dict[str, str]:
    return {tag["key"]: tag["value"] for tag in tags}


class ProwlerParser(ScannerParser):
    @property
    def scanner_name(self) -> str:
        return "prowler"

    def parse(self, path: str | Path) -> ScanRun:
        path = Path(path)
        entries = json.loads(path.read_text())
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
        resource_ids: list[str] = []
        resolutions: list[Resolution] = []
        for resource_data in entry["resources"]:
            ref = ResourceRef(
                scheme=RefScheme.ARN, value=resource_data["uid"], scanner=self.scanner_name
            )
            resolution = resolve(ref)
            if resolution is None:
                continue
            resource_ids.append(str(resolution.key))
            resolutions.append(resolution)
            self._record_resource(resources, resolution, ref, resource_data)
            self._record_bridge_fact(bridge_facts, resolution, resource_data)
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
        tags = _tags_dict(resource_data.get("tags", []))
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
