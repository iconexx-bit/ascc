"""A3-I3b contract: runtime evidence from the containment lab (CLAUDE.md, "Runtime evidence (A3)").

The lab emits SARIF clab/v1; kind fail is a finding, kind pass/open is
evidence on the node of the declared resource. The binding is declared by the
operator (operator_declared, confidence 0.5) and is said so in every output.
Evidence adds no result and changes no chain; outputs without a lab file stay
byte-identical (tests/test_cli_golden.py).
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from ascc.correlate.run import correlate
from ascc.export.sarif import to_sarif
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.registry import parser_for
from ascc.ingest.trivy import TrivyParser
from ascc.schema.taxonomy import Category, Severity
from ascc.store.policy import MAX_CONFIDENCE, TTL

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE = REPO_ROOT / "fixtures" / "leaky_data_lake"
CONTAINED = REPO_ROOT / "fixtures" / "leaky_data_lake_contained"
LAB_FILE = CONTAINED / "clab.sarif.json"
LAB_SHA256 = "93d2c6e9d33495e4773b2c1d6b789de13182a864fd7d752925bfa3e819a40b86"
GOLDEN = REPO_ROOT / "tests" / "data" / "leaky_data_lake_contained.sarif.json"
BASE_GOLDEN = REPO_ROOT / "tests" / "data" / "leaky_data_lake.sarif.json"
SARIF_SCHEMA = REPO_ROOT / "tests" / "schemas" / "sarif-2.1.0.json"
INSTANCE = "aws:ec2:instance:i-0a1b2c3d4e5f67890"
RULES = [
    "CLAB-CANARY-001",
    "CLAB-EGRESS-001",
    "CLAB-SIGMA-001",
    "CLAB-SIMCA-001",
    "CLAB-TRIPWIRE-001",
    "CLAB-TTC-001",
]
CLI_LINE = (
    "Runtime evidence: 6 (6 verified, 0 not verified; 6 on chain nodes; "
    "binding declared, not observed)"
)


def _clab():
    """Imported per test: on a tree without the module every test fails on its own."""
    return importlib.import_module("ascc.ingest.clab")


def _lab() -> dict:
    return json.loads(LAB_FILE.read_text(encoding="utf-8"))


def _write(tmp_path: Path, doc: dict, name: str = "clab.sarif.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _with_kind(doc: dict, rule_id: str, kind: str, level: str) -> dict:
    doc = copy.deepcopy(doc)
    [result] = [r for r in doc["runs"][0]["results"] if r["ruleId"] == rule_id]
    result["kind"], result["level"] = kind, level
    return doc


def _scanners(lab_path: Path) -> list:
    return [
        TrivyParser().parse(BASE / "trivy.json"),
        CheckovParser().parse(BASE / "checkov.json"),
        ProwlerParser().parse(BASE / "prowler.json"),
        _clab().ClabParser().parse(lab_path),
    ]


def _run0(lab_path: Path) -> dict:
    return to_sarif(correlate(_scanners(lab_path)))["runs"][0]


def _base_run0() -> dict:
    runs = [
        TrivyParser().parse(BASE / "trivy.json"),
        CheckovParser().parse(BASE / "checkov.json"),
        ProwlerParser().parse(BASE / "prowler.json"),
    ]
    return to_sarif(correlate(runs))["runs"][0]


def _cli(input_dir: Path, out: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "ascc",
            "correlate",
            "--input",
            str(input_dir),
            "--output",
            str(out),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=dict(os.environ, ASCC_CONSOLE_WIDTH="200"),
        check=False,
    )


def test_contained_fixture_is_the_base_plus_the_lab_file() -> None:
    for name in ("trivy.json", "prowler.json", "checkov.json"):
        assert (CONTAINED / name).read_bytes() == (BASE / name).read_bytes(), name
    assert hashlib.sha256(LAB_FILE.read_bytes()).hexdigest() == LAB_SHA256


def test_sniff_recognises_clab_v1_only() -> None:
    clab = _clab()
    assert parser_for(_lab()) is clab.ClabParser
    for name in ("trivy.json", "prowler.json", "checkov.json"):
        assert not clab.ClabParser.sniff(json.loads((BASE / name).read_text()))
    assert not clab.ClabParser.sniff(json.loads(BASE_GOLDEN.read_text()))
    other = _lab()
    other["runs"][0]["properties"]["schema"] = "clab/v2"
    assert not clab.ClabParser.sniff(other)


def test_all_pass_is_evidence_not_findings() -> None:
    clab = _clab()
    run = clab.ClabParser().parse(LAB_FILE)
    assert run.scanner == "clab" and run.findings == []
    assert sorted(e.rule_id for e in run.evidence) == RULES
    assert {e.status for e in run.evidence} == {"verified"}
    assert {e.resource_id for e in run.evidence} == {INSTANCE}
    [resolution] = {e.resolution for e in run.evidence}
    assert (resolution.method, resolution.confidence) == ("operator_declared", 0.5)
    assert str(resolution.identity_class) == "generated_id"
    assert list(run.resources) == [INSTANCE]


def test_operator_declared_is_a_policy_method() -> None:
    assert _clab().BINDING_CONFIDENCE == MAX_CONFIDENCE["operator_declared"] == 0.5
    assert TTL["operator_declared"].days == 7


def test_fail_is_a_containment_finding(tmp_path: Path) -> None:
    path = _write(tmp_path, _with_kind(_lab(), "CLAB-EGRESS-001", "fail", "error"))
    run = _clab().ClabParser().parse(path)
    [finding] = run.findings
    assert (finding.rule_id, finding.category, finding.severity) == (
        "CLAB-EGRESS-001",
        Category.CONTAINMENT,
        Severity.HIGH,
    )
    assert finding.resource_ids == [INSTANCE]
    assert finding.title.startswith("egress_blocked:")
    assert len(run.evidence) == 5


def test_open_is_not_verified_evidence(tmp_path: Path) -> None:
    path = _write(tmp_path, _with_kind(_lab(), "CLAB-SIMCA-001", "open", "none"))
    run = _clab().ClabParser().parse(path)
    status = {e.rule_id: e.status for e in run.evidence}
    assert status["CLAB-SIMCA-001"] == "not_verified" and run.findings == []
    assert sum(s == "verified" for s in status.values()) == 5


def _break(doc: dict, how: str) -> dict:
    doc = copy.deepcopy(doc)
    run = doc["runs"][0]
    if how == "binding-method":
        run["properties"]["binding"]["method"] = "arn_parse"
    elif how == "bucket-arn":
        run["properties"]["binding"]["resource_arn"] = "arn:aws:s3:::datalake-raw"
    elif how == "location":
        loc = run["results"][0]["locations"][0]["logicalLocations"][0]
        loc["fullyQualifiedName"] = loc["fullyQualifiedName"].replace("i-0a1b", "i-0b1b")
    elif how == "kind":
        run["results"][0]["kind"] = "review"
    elif how == "severity":
        del run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    elif how == "driver":
        run["tool"]["driver"]["name"] = "something-else"
    return doc


@pytest.mark.parametrize(
    "how", ["binding-method", "bucket-arn", "location", "kind", "severity", "driver"]
)
def test_contract_violations_are_refused(tmp_path: Path, how: str) -> None:
    clab = _clab()
    with pytest.raises(clab.ClabFormatError):
        clab.ClabParser().parse(_write(tmp_path, _break(_lab(), how)))


def test_evidence_lands_on_the_instance_node_and_changes_nothing_else() -> None:
    run0, base = _run0(LAB_FILE), _base_run0()
    assert run0["results"] == base["results"]
    [chain], [base_chain] = run0["properties"]["chains"], base["properties"]["chains"]
    assert (chain["id"], chain["confidence"], chain["edges"]) == (
        base_chain["id"],
        base_chain["confidence"],
        base_chain["edges"],
    )
    with_evidence = [n for n in chain["nodes"] if "evidence" in n]
    assert [n["key"] for n in with_evidence] == [INSTANCE]
    items = with_evidence[0]["evidence"]
    assert [e["rule_id"] for e in items] == RULES
    assert all(e["binding"] == {"method": "operator_declared", "confidence": 0.5} for e in items)
    assert all(e["source"] == "clab" and e["status"] == "verified" for e in items)
    assert items[0]["provenance"]["probe_ts"] == "2026-10-27T05:08:35Z"
    assert run0["properties"]["graph_stats"]["evidence"] == {
        "total": 6,
        "verified": 6,
        "not_verified": 0,
        "on_chain_nodes": 6,
    }


def test_failed_control_is_a_result_on_the_chain(tmp_path: Path) -> None:
    path = _write(tmp_path, _with_kind(_lab(), "CLAB-EGRESS-001", "fail", "error"))
    run0 = _run0(path)
    [chain] = run0["properties"]["chains"]
    [result] = [r for r in run0["results"] if r["ruleId"] == "clab/CLAB-EGRESS-001"]
    assert result["level"] == "error"
    assert result["properties"]["chain_ids"] == [chain["id"]]
    assert result["properties"]["binding"] == {"method": "operator_declared", "confidence": 0.5}
    instance = next(n for n in chain["nodes"] if n["key"] == INSTANCE)
    assert not any(e.startswith("clab:") for e in instance["entry_findings"])
    assert len(run0["results"]) == len(_base_run0()["results"]) + 1


def test_evidence_off_every_chain_is_counted(tmp_path: Path) -> None:
    doc = json.loads(LAB_FILE.read_text().replace("i-0a1b2c3d4e5f67890", "i-0123456789abcdef0"))
    run0 = _run0(_write(tmp_path, doc))
    [chain] = run0["properties"]["chains"]
    assert not any("evidence" in n for n in chain["nodes"])
    assert run0["properties"]["graph_stats"]["evidence"]["total"] == 6
    assert run0["properties"]["graph_stats"]["evidence"]["on_chain_nodes"] == 0


def test_cli_matches_the_contained_golden(tmp_path: Path) -> None:
    out = tmp_path / "out.sarif.json"
    proc = _cli(CONTAINED, out)
    assert proc.returncode == 0, proc.stderr
    assert CLI_LINE in proc.stdout.splitlines()
    assert out.read_bytes() == GOLDEN.read_bytes()


def test_contained_golden_is_valid_sarif() -> None:
    validator = Draft7Validator(json.loads(SARIF_SCHEMA.read_text(encoding="utf-8")))
    errors = list(validator.iter_errors(json.loads(GOLDEN.read_text(encoding="utf-8"))))
    assert errors == []


def test_cli_refuses_a_broken_lab_file(tmp_path: Path) -> None:
    for name in ("trivy.json", "prowler.json", "checkov.json"):
        (tmp_path / name).write_bytes((BASE / name).read_bytes())
    _write(tmp_path, _break(_lab(), "binding-method"))
    out = tmp_path / "out" / "x.sarif.json"
    out.parent.mkdir()
    proc = _cli(tmp_path, out)
    assert proc.returncode == 70
    assert "Invalid clab.sarif.json" in proc.stderr
    assert not out.exists()
