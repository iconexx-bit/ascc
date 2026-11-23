"""CheckovParser ties real open-source Checkov findings to resources.

Open-source Checkov 3.3.30 leaves `resource_address` null on every check; the
Terraform address is in `resource`. CheckovParser read only
`resource_address`, so none of the 22 real findings was tied to a resource
and Checkov correlated with no other scanner, without a trace. The parser now
falls back to `resource` when `resource_address` is null (`resource_address`
still wins when present), and the CLI names the findings that remain tied to
no resource: here the Terraform types ASCC does not map yet.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from ascc.ingest.checkov import CheckovParser
from ascc.ingest.trivy import TrivyParser
from ascc.schema.identity import RefScheme, ResourceRef, resolve

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL = REPO_ROOT / "fixtures" / "leaky_data_lake_real"
SYNTHETIC = REPO_ROOT / "fixtures" / "leaky_data_lake"
BOUND = 11  # real failed checks whose `resource` resolves to a resource key


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _failed(path: Path) -> list[dict]:
    return _load(path)["results"]["failed_checks"]


def _key(address: str) -> list[str]:
    resolution = resolve(ResourceRef(scheme=RefScheme.TERRAFORM, value=address, scanner="checkov"))
    return [] if resolution is None else [str(resolution.key)]


def _cli(inputs: Path, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "ascc",
            "correlate",
            "--input",
            str(inputs),
            "--output",
            str(tmp_path / "out.sarif.json"),
        ],
        cwd=REPO_ROOT,
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )


def test_null_resource_address_falls_back_to_resource() -> None:
    checks = _failed(REAL / "checkov.json")
    assert checks and all(c["resource_address"] is None and c["resource"] for c in checks)
    findings = CheckovParser().parse(REAL / "checkov.json").findings
    expected = [_key(check["resource"]) for check in checks]
    assert [finding.resource_ids for finding in findings] == expected
    assert sum(1 for ids in expected if ids) == BOUND


def test_resource_address_wins_when_present(tmp_path: Path) -> None:
    data = _load(SYNTHETIC / "checkov.json")
    check = data["results"]["failed_checks"][0]
    assert check["resource_address"]
    check["resource"] = "aws_s3_bucket.somewhere_else"
    path = tmp_path / "checkov.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    finding = CheckovParser().parse(path).findings[0]
    assert finding.resource_ids == _key(check["resource_address"])


def test_checkov_meets_trivy_on_real_resources() -> None:
    checkov = CheckovParser().parse(REAL / "checkov.json").findings
    trivy = TrivyParser().parse(REAL / "trivy-config.json").findings
    shared = {key for f in checkov for key in f.resource_ids} & {
        key for f in trivy for key in f.resource_ids
    }
    assert shared == {"aws:s3:bucket:datalake-raw", "aws:ec2:security-group:datalake-etl-sg"}


def test_cli_names_findings_tied_to_no_resource(tmp_path: Path) -> None:
    proc = _cli(REAL, tmp_path)
    assert proc.returncode == 0, proc.stderr[-2000:]
    total = len(_failed(REAL / "checkov.json"))
    line = f"Findings tied to no resource: {total - BOUND} (checkov {total - BOUND})"
    assert line in proc.stdout, proc.stdout[:2000]


def test_cli_says_nothing_when_every_finding_has_a_resource(tmp_path: Path) -> None:
    proc = _cli(SYNTHETIC, tmp_path)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "tied to no resource" not in proc.stdout


def test_fixture_readme_states_how_many_resolve() -> None:
    text = " ".join((SYNTHETIC / "README.md").read_text(encoding="utf-8").split())
    total = len(_failed(REAL / "checkov.json"))
    assert f"{BOUND} of {total} real Checkov findings resolve to a resource" in text


def test_contract_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "Checkov `resource_address` is null in open-source output" in text
