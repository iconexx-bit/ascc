"""Containment lab judgement, SARIF profile clab/v1 (CLAUDE.md, "Runtime evidence (A3)").

Producer: iconexx-bit/ai-agent-containment-lab, integrations/ascc/emit.sh
(contract schemas/clab.v1.json there). One run, one resource declared by the
operator (binding.method "operator_declared"), six controls. kind "fail" is a
finding; kind "pass" is evidence that the control was verified; kind "open"
is evidence that it was NOT verified (an operator skip). Nothing is judged
here: the lab's verdict is taken as it is, and anything outside the contract
is refused with ClabFormatError instead of being read loosely.
"""

from __future__ import annotations

import json
from pathlib import Path

from ascc.schema.identity import IdentityClass, RefScheme, Resolution, ResourceRef, resolve
from ascc.schema.models import Evidence, Finding, Resource, ScanRun
from ascc.schema.taxonomy import Category, Severity

from .base import ScannerParser

SCHEMA = "clab/v1"
BINDING_METHOD = "operator_declared"
# The binding is the operator's word: no scanner observed that the lab ran on
# this resource. ascc.store.policy.MAX_CONFIDENCE["operator_declared"].
BINDING_CONFIDENCE = 0.5
_STATUS = {"pass": "verified", "open": "not_verified"}


class ClabFormatError(ValueError):
    """A clab/v1 file that breaks its contract. The CLI refuses the run (rc 70)."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ClabFormatError(reason)


class ClabParser(ScannerParser):
    @property
    def scanner_name(self) -> str:
        return "clab"

    @classmethod
    def sniff(cls, data: dict | list) -> bool:
        if not isinstance(data, dict) or data.get("version") != "2.1.0":
            return False
        runs = data.get("runs")
        if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
            return False
        props = runs[0].get("properties")
        return isinstance(props, dict) and props.get("schema") == SCHEMA

    def parse(self, path: str | Path) -> ScanRun:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        _require(self.sniff(data), f"not a {SCHEMA} SARIF log")
        _require(len(data["runs"]) == 1, "clab/v1 has exactly one run")
        run = data["runs"][0]
        props = run["properties"]
        _require(
            run.get("tool", {}).get("driver", {}).get("name") == "containment-lab",
            "tool.driver.name must be containment-lab",
        )

        binding = props.get("binding")
        _require(
            isinstance(binding, dict) and binding.get("method") == BINDING_METHOD,
            f"binding.method must be {BINDING_METHOD}",
        )
        arn = binding.get("resource_arn")
        ref = ResourceRef(scheme=RefScheme.ARN, value=str(arn), scanner=self.scanner_name)
        parsed = resolve(ref) if isinstance(arn, str) else None
        _require(
            parsed is not None
            and (parsed.key.service, parsed.key.resource_type) == ("ec2", "instance"),
            "binding.resource_arn must be an EC2 instance ARN",
        )
        resolution = Resolution(
            key=parsed.key,
            confidence=BINDING_CONFIDENCE,
            method=BINDING_METHOD,
            identity_class=IdentityClass.GENERATED_ID,
        )
        key = str(parsed.key)
        provenance = _provenance(props)

        severities: dict[str, Severity] = {}
        for rule in run["tool"]["driver"].get("rules", []):
            raw = rule.get("properties", {}).get("security-severity")
            _require(isinstance(raw, str), f"rule {rule.get('id')}: security-severity missing")
            try:
                severities[rule["id"]] = Severity.from_security_severity(float(raw))
            except ValueError:
                raise ClabFormatError(f"rule {rule.get('id')}: security-severity {raw!r}") from None

        findings: list[Finding] = []
        evidence: list[Evidence] = []
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            kind = result.get("kind")
            _require(rule_id in severities, f"result {rule_id!r} has no rule")
            locations = [
                loc["fullyQualifiedName"]
                for location in result.get("locations", [])
                for loc in location.get("logicalLocations", [])
            ]
            _require(
                locations == [arn], f"{rule_id}: located at {locations}, not at the declared ARN"
            )
            message = result.get("message", {}).get("text", "")
            control = result.get("properties", {}).get("control", "")
            if kind == "fail":
                findings.append(
                    Finding(
                        scanner=self.scanner_name,
                        rule_id=rule_id,
                        category=Category.CONTAINMENT,
                        severity=severities[rule_id],
                        title=message,
                        resource_ids=[key],
                        resolutions=[resolution],
                        raw=result,
                    )
                )
            elif kind in _STATUS:
                evidence.append(
                    Evidence(
                        resource_id=key,
                        scanner=self.scanner_name,
                        rule_id=rule_id,
                        control=control,
                        status=_STATUS[kind],
                        message=message,
                        resolution=resolution,
                        provenance=provenance,
                    )
                )
            else:
                raise ClabFormatError(f"{rule_id}: kind {kind!r} is not pass, fail or open")

        return ScanRun(
            scanner=self.scanner_name,
            findings=findings,
            resources={key: Resource(key=parsed.key, refs=[ref], resolutions=[resolution])},
            evidence=evidence,
        )


def _provenance(props: dict) -> tuple[tuple[str, str], ...]:
    """Where the judgement came from, as the lab recorded it (sha256 of its inputs)."""
    out: list[tuple[str, str]] = []
    probe = props.get("probe") or {}
    for name, value in (
        ("probe_ts", probe.get("ts")),
        ("probe_sha256", probe.get("sha256")),
        ("ttc_sha256", (props.get("ttc") or {}).get("sha256")),
        ("verdict", props.get("verdict")),
    ):
        if isinstance(value, str):
            out.append((name, value))
    return tuple(out)
