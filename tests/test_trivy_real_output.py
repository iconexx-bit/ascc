"""TrivyParser finds the category of a current Trivy misconfiguration ID.

Trivy 0.76 reports misconfigurations with `ID` = `AWS-NNNN` and no `AVDID`;
the category table was keyed by the older `AVD-AWS-NNNN`, so on real output
every misconfiguration became UNCATEGORIZED without a trace, and the open SSH
rule (AWS-0107) was not an entry. The lookup now ignores the `AVD-` prefix;
`rule_id` stays exactly as the scanner gave it, so fingerprints and the golden
SARIF do not change.
"""

from __future__ import annotations

from pathlib import Path

from ascc.correlate.graph import build_graph
from ascc.correlate.run import correlate
from ascc.ingest.trivy import TrivyParser
from ascc.schema.taxonomy import Category

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL = REPO_ROOT / "fixtures" / "leaky_data_lake_real" / "trivy-config.json"
SYNTHETIC = REPO_ROOT / "fixtures" / "leaky_data_lake" / "trivy.json"
IAC_SG = "aws:ec2:security-group:datalake-etl-sg"


def _by_rule(path: Path) -> dict:
    return {f.rule_id: f for f in TrivyParser().parse(path).findings}


def test_real_id_without_avdid_finds_its_category() -> None:
    assert _by_rule(REAL)["AWS-0107"].category is Category.NETWORK_EXPOSURE


def test_rule_id_is_kept_as_the_scanner_gave_it() -> None:
    assert "AWS-0107" in _by_rule(REAL)
    assert "AVD-AWS-0107" in _by_rule(SYNTHETIC)


def test_avdid_form_still_finds_its_category() -> None:
    findings = _by_rule(SYNTHETIC)
    assert findings["AVD-AWS-0028"].category is Category.ENCRYPTION_AT_REST
    assert findings["AVD-AWS-0107"].category is Category.NETWORK_EXPOSURE


def test_real_open_ssh_rule_makes_its_node_an_entry() -> None:
    graph = build_graph(correlate([TrivyParser().parse(REAL)]))
    node = next(n for n in graph.nodes if str(n.key) == IAC_SG)
    assert "trivy:AWS-0107" in node.entry_findings


def test_contract_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "the category lookup ignores the `AVD-` prefix" in text
