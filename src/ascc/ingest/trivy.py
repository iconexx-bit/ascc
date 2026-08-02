from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path, PurePosixPath

from ascc.schema.identity import RefScheme, Resolution, ResourceRef, resolve
from ascc.schema.models import Finding, ScanRun
from ascc.schema.taxonomy import Category, Severity

from .base import ScannerParser

_MISCONFIG_CATEGORY: dict[str, Category] = {
    "AVD-AWS-0028": Category.ENCRYPTION_AT_REST,
    "AVD-AWS-0107": Category.NETWORK_EXPOSURE,
}

_FRACTIONAL_SECONDS_RE = re.compile(r"(\.\d{6})\d*Z$")


def _parse_timestamp(raw: str) -> datetime:
    trimmed = _FRACTIONAL_SECONDS_RE.sub(r"\1Z", raw)
    return datetime.fromisoformat(trimmed)


class TrivyParser(ScannerParser):
    @property
    def scanner_name(self) -> str:
        return "trivy"

    def parse(self, path: Path) -> ScanRun:
        data = json.loads(path.read_text())
        host_resolution = self._resolve_host(data)
        findings: list[Finding] = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append(self._vulnerability_finding(result, vuln, host_resolution))
            for misconfig in result.get("Misconfigurations", []):
                findings.append(self._misconfig_finding(misconfig))
        return ScanRun(
            scanner=self.scanner_name,
            started_at=_parse_timestamp(data["CreatedAt"]),
            findings=findings,
        )

    def _resolve_host(self, data: dict) -> Resolution | None:
        if data.get("ArtifactType") != "filesystem":
            return None
        hostname = PurePosixPath(data.get("ArtifactName", "")).name
        ref = ResourceRef(scheme=RefScheme.NAME, value=hostname, scanner=self.scanner_name)
        return resolve(ref)

    def _vulnerability_finding(
        self, result: dict, vuln: dict, host_resolution: Resolution | None
    ) -> Finding:
        resolution = host_resolution
        if resolution is None:
            instance_id = result["Target"].split(" ", 1)[0]
            ref = ResourceRef(
                scheme=RefScheme.CLOUD_ID, value=instance_id, scanner=self.scanner_name
            )
            resolution = resolve(ref)
        return Finding(
            scanner=self.scanner_name,
            rule_id=vuln["VulnerabilityID"],
            category=Category.VULNERABILITY,
            severity=Severity.from_trivy(vuln["Severity"]),
            title=vuln["Title"],
            resource_ids=[str(resolution.key)] if resolution else [],
            resolutions=[resolution] if resolution else [],
            cve=vuln["VulnerabilityID"],
            raw=vuln,
        )

    def _misconfig_finding(self, misconfig: dict) -> Finding:
        rule_id = misconfig.get("AVDID") or misconfig["ID"]
        cause = misconfig.get("CauseMetadata", {})
        resolution = None
        if resource := cause.get("Resource"):
            ref = ResourceRef(scheme=RefScheme.TERRAFORM, value=resource, scanner=self.scanner_name)
            resolution = resolve(ref)
        return Finding(
            scanner=self.scanner_name,
            rule_id=rule_id,
            category=_MISCONFIG_CATEGORY.get(rule_id, Category.UNCATEGORIZED),
            severity=Severity.from_trivy(misconfig["Severity"]),
            title=misconfig["Title"],
            resource_ids=[str(resolution.key)] if resolution else [],
            resolutions=[resolution] if resolution else [],
            cve=None,
            raw=misconfig,
        )
