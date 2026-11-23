"""The synthetic fixtures use the field layout of real scanner output.

Every JSON path in fixtures/leaky_data_lake and fixtures/leaky_data_lake_contained
(list positions collapsed to `[]`) also appears in fixtures/leaky_data_lake_real,
so a parser that reads the fixture reads the same fields on real output. Before
this, the Prowler fixture kept resource attributes flat in `resources[].data`
and the graph drew no edge on real output (O47), and the Trivy fixture carried
`AVDID`, which current Trivy no longer writes (O36). One exception: the real
filesystem scan found no CVE, so the Trivy `Vulnerabilities` paths have no real
counterpart until a real sample with CVEs exists (runbook O52).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"
REAL = FIXTURES / "leaky_data_lake_real"
REAL_FILES = {
    "checkov": ("checkov.json",),
    "prowler": ("prowler.json",),
    "trivy": ("trivy-config.json", "trivy-rootfs.json"),
}
SYNTHETIC = ("leaky_data_lake", "leaky_data_lake_contained")
# The real Trivy run reported no CVE: these paths cannot be compared yet (O52).
CVE_PATHS = "Results[].Vulnerabilities"


def _paths(node: object, prefix: str = "") -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else key
            found.add(path)
            found |= _paths(value, path)
    elif isinstance(node, list):
        for item in node:
            found |= _paths(item, f"{prefix}[]")
    return found


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _real(scanner: str) -> set[str]:
    found: set[str] = set()
    for name in REAL_FILES[scanner]:
        found |= _paths(_load(REAL / name))
    return found


def _not_in_real(fixture: str, scanner: str) -> set[str]:
    return _paths(_load(FIXTURES / fixture / f"{scanner}.json")) - _real(scanner)


@pytest.mark.parametrize("scanner", sorted(REAL_FILES))
@pytest.mark.parametrize("fixture", SYNTHETIC)
def test_every_fixture_path_is_in_real_output(fixture: str, scanner: str) -> None:
    missing = {p for p in _not_in_real(fixture, scanner) if not p.startswith(CVE_PATHS)}
    assert missing == set()


def test_the_only_exception_is_the_trivy_cve_fields() -> None:
    assert not any(p.startswith(CVE_PATHS) for p in _real("trivy"))
    for fixture in SYNTHETIC:
        missing = _not_in_real(fixture, "trivy")
        assert missing, f"{fixture}: no CVE paths left to except; drop the exception"
        assert all(p.startswith(CVE_PATHS) for p in missing), sorted(missing)


def test_fixture_readme_says_the_layout_is_pinned() -> None:
    text = " ".join((FIXTURES / "leaky_data_lake" / "README.md").read_text("utf-8").split())
    assert "## How close it is to real scanner output" not in text
    assert "every JSON path in the three files also appears in" in text
    assert "`tests/test_fixture_layout.py`" in text


def test_contract_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "every JSON path also appears in fixtures/leaky_data_lake_real/" in text
    assert "Pinned by tests/test_fixture_layout.py." in text
