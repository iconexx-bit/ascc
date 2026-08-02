from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ascc.schema.identity import RefScheme, Resolution, ResourceRef, resolve
from ascc.schema.models import Finding, Resource, ScanRun
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


def _parse_timestamp(raw: str) -> datetime:
    return datetime.fromisoformat(raw)


def _tags_dict(tags: list[dict[str, str]]) -> dict[str, str]:
    return {tag["key"]: tag["value"] for tag in tags}


class ProwlerParser(ScannerParser):
    @property
    def scanner_name(self) -> str:
        return "prowler"

    def parse(self, path: Path) -> ScanRun:
        entries = json.loads(path.read_text())
        started_at = min(_parse_timestamp(e["finding_info"]["created_time"]) for e in entries)
        resources: dict[str, Resource] = {}
        findings = [
            self._finding(entry, resources) for entry in entries if entry["status_code"] == "FAIL"
        ]
        return ScanRun(
            scanner=self.scanner_name,
            started_at=started_at,
            findings=findings,
            resources=resources,
        )

    def _finding(self, entry: dict, resources: dict[str, Resource]) -> Finding:
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
