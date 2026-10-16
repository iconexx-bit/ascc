"""SARIF 2.1.0 schema validity of ASCC output.

README states the export is "valid against SARIF 2.1.0". This test is the
contract behind that sentence: it validates both the committed golden
baseline and a live `ascc correlate --output` run against the official
OASIS schema vendored in tests/schemas/ (draft-07).

The live run matters: the golden file only proves what was true when it was
last regenerated. test_validator_rejects_invalid_level is the negative
control -- a validator wired wrongly (empty schema, wrong draft, swallowed
errors) would pass every positive case, so the suite must be able to fail.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "tests" / "schemas" / "sarif-2.1.0.json"
GOLDEN_PATH = REPO_ROOT / "tests" / "data" / "leaky_data_lake.sarif.json"
FIXTURE_REL = Path("fixtures") / "leaky_data_lake"


@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def _errors(validator: Draft7Validator, doc: dict) -> list[str]:
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    ]


def test_golden_baseline_is_valid_sarif(validator: Draft7Validator) -> None:
    doc = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"], "golden baseline has no results -- vacuous check"
    assert _errors(validator, doc) == []


def test_live_correlate_output_is_valid_sarif(validator: Draft7Validator, tmp_path: Path) -> None:
    out = tmp_path / "live.sarif.json"
    cmd = [
        sys.executable,
        "-m",
        "ascc",
        "correlate",
        "--input",
        str(FIXTURE_REL),
        "--output",
        str(out),
    ]
    subprocess.run(cmd, check=True, cwd=REPO_ROOT, env={**os.environ}, capture_output=True)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"], "live run produced no results -- vacuous check"
    assert _errors(validator, doc) == []


def test_validator_rejects_invalid_level(validator: Draft7Validator) -> None:
    doc = copy.deepcopy(json.loads(GOLDEN_PATH.read_text(encoding="utf-8")))
    doc["runs"][0]["results"][0]["level"] = "critical"  # not in the SARIF enum
    errors = _errors(validator, doc)
    assert any("'critical' is not one of" in e for e in errors), errors
