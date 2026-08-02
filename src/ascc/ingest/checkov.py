from __future__ import annotations

import json
from pathlib import Path

from ascc.schema.identity import RefScheme, Resolution, ResourceRef, resolve
from ascc.schema.models import Finding, Resource, ScanRun
from ascc.schema.taxonomy import Category, Severity

from .base import ScannerParser

_CHECK_CATEGORY: dict[str, Category] = {
    "CKV_AWS_20": Category.PUBLIC_ACCESS,
    "CKV_AWS_19": Category.ENCRYPTION_AT_REST,
    "CKV_AWS_18": Category.LOGGING_DISABLED,
    "CKV_AWS_40": Category.EXCESSIVE_PRIVILEGE,
}


class CheckovParser(ScannerParser):
    @property
    def scanner_name(self) -> str:
        return "checkov"

    @classmethod
    def sniff(cls, data: dict | list) -> bool:
        return isinstance(data, dict) and "check_type" in data and "results" in data

    def parse(self, path: str | Path) -> ScanRun:
        path = Path(path)
        data = json.loads(path.read_text())
        resources: dict[str, Resource] = {}
        findings = [
            self._finding(check, resources)
            for check in data.get("results", {}).get("failed_checks", [])
        ]
        return ScanRun(scanner=self.scanner_name, findings=findings, resources=resources)

    def _finding(self, check: dict, resources: dict[str, Resource]) -> Finding:
        rule_id = check["check_id"]
        resource_ids: list[str] = []
        resolutions: list[Resolution] = []
        address = check.get("resource_address")
        if address:
            ref = ResourceRef(scheme=RefScheme.TERRAFORM, value=address, scanner=self.scanner_name)
            resolution = resolve(ref)
            if resolution is not None:
                resource_ids.append(str(resolution.key))
                resolutions.append(resolution)
                self._record_resource(resources, ref, resolution)
        return Finding(
            scanner=self.scanner_name,
            rule_id=rule_id,
            category=_CHECK_CATEGORY.get(rule_id, Category.UNCATEGORIZED),
            severity=Severity.from_severity_string(check["severity"]),
            title=check["check_name"],
            resource_ids=resource_ids,
            resolutions=resolutions,
            cve=None,
            raw=check,
        )

    def _record_resource(
        self, resources: dict[str, Resource], ref: ResourceRef, resolution: Resolution
    ) -> None:
        key_str = str(resolution.key)
        existing = resources.get(key_str)
        if existing is None:
            resources[key_str] = Resource(key=resolution.key, refs=[ref], resolutions=[resolution])
            return
        existing.refs.append(ref)
        existing.resolutions.append(resolution)
