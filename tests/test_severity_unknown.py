"""A severity the scanner did not give is unknown, never INFO.

Open-source Checkov (run without a platform API key) reports `severity: null`
on every check; Trivy can report the string "UNKNOWN"; OCSF has severity_id 0
(Unknown) and 99 (Other). Before this, `null` stopped CheckovParser with an
AttributeError (exit 70 on every real Checkov file), and the others became
INFO without a trace. All of them, and any value ASCC does not recognise, now
become Severity.UNKNOWN. In SARIF the result keeps level "warning" (the check
failed; "none" would say there is no problem), and the rule carries
`ascc/severity: unknown` and no `security-severity`, so GitHub code scanning
shows no score the scanner never gave.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.trivy import TrivyParser
from ascc.schema.taxonomy import Severity

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL = REPO_ROOT / "fixtures" / "leaky_data_lake_real"
SCHEMA_PATH = REPO_ROOT / "tests" / "schemas" / "sarif-2.1.0.json"


def _load(path: Path) -> dict | list:
    return json.loads(path.read_text(encoding="utf-8"))


def test_real_checkov_output_parses_with_unknown_severity() -> None:
    failed = _load(REAL / "checkov.json")["results"]["failed_checks"]
    assert failed and all(check["severity"] is None for check in failed)
    findings = CheckovParser().parse(REAL / "checkov.json").findings
    assert len(findings) == len(failed)
    assert {finding.severity for finding in findings} == {Severity.UNKNOWN}


def test_trivy_unknown_string_is_unknown(tmp_path: Path) -> None:
    data = _load(REAL / "trivy-config.json")
    for result in data["Results"]:
        for misconfig in result.get("Misconfigurations", []):
            misconfig["Severity"] = "UNKNOWN"
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    findings = TrivyParser().parse(path).findings
    assert findings
    assert {finding.severity for finding in findings} == {Severity.UNKNOWN}


def test_ocsf_unknown_and_other_are_unknown(tmp_path: Path) -> None:
    entries = _load(REAL / "prowler.json")
    for index, entry in enumerate(entries):
        entry["severity_id"] = 0 if index % 2 else 99
    path = tmp_path / "prowler.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    findings = ProwlerParser().parse(path).findings
    assert findings
    assert {finding.severity for finding in findings} == {Severity.UNKNOWN}


def test_known_severities_map_as_before() -> None:
    members = list(Severity)
    assert members[0] is Severity.INFO
    strings = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "high")
    assert [Severity.from_severity_string(value) for value in strings] == [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
        Severity.HIGH,
    ]
    assert [Severity.from_ocsf(value) for value in (1, 2, 3, 4, 5, 6)] == [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
        Severity.CRITICAL,
    ]


def test_unrecognised_values_are_unknown() -> None:
    assert Severity.from_severity_string("SEVERE") is Severity.UNKNOWN
    assert Severity.from_ocsf(7) is Severity.UNKNOWN


def test_non_string_severity_is_refused() -> None:
    with pytest.raises(TypeError, match="string or null"):
        Severity.from_severity_string(3)  # type: ignore[arg-type]


def test_cli_reports_unknown_without_a_score(tmp_path: Path) -> None:
    inputs = tmp_path / "in"
    inputs.mkdir()
    shutil.copy(REAL / "checkov.json", inputs / "checkov.json")
    sarif = tmp_path / "out.sarif.json"
    proc = subprocess.run(
        [sys.executable, "-m", "ascc", "correlate", "--input", str(inputs), "--output", str(sarif)],
        cwd=REPO_ROOT,
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    doc = _load(sarif)
    run = doc["runs"][0]
    failed = _load(REAL / "checkov.json")["results"]["failed_checks"]
    assert len(run["results"]) == len(failed)
    assert {result["level"] for result in run["results"]} == {"warning"}
    rules = run["tool"]["driver"]["rules"]
    assert rules
    for rule in rules:
        assert "security-severity" not in rule["properties"], rule["id"]
        assert rule["properties"]["ascc/severity"] == "unknown", rule["id"]
    validator = Draft7Validator(_load(SCHEMA_PATH))
    assert [error.message for error in validator.iter_errors(doc)] == []


def test_contract_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "A severity the scanner did not give is `UNKNOWN`, never INFO" in text
