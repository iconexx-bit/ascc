"""fixtures/leaky_data_lake_real is real scanner output, sanitised and trimmed.

The files come from run 2 of the AWS spike (2026-10-30). The fixture README
says which tools produced them, what was replaced and which records were kept;
these tests hold the README to the files, so the description cannot drift from
the data. Repository-wide sanitising (account IDs, home directories) is pinned
by tests/test_repo_hygiene.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "fixtures" / "leaky_data_lake_real"
DATA_FILES = ("checkov.json", "prowler.json", "trivy-config.json", "trivy-rootfs.json")


def _readme() -> str:
    return " ".join((FIXTURE / "README.md").read_text(encoding="utf-8").split())


def _load(name: str) -> Any:
    return json.loads((FIXTURE / name).read_text(encoding="utf-8"))


def test_directory_holds_exactly_the_described_files() -> None:
    assert sorted(p.name for p in FIXTURE.iterdir()) == sorted(("README.md", *DATA_FILES))


@pytest.mark.parametrize("name", DATA_FILES)
def test_data_file_is_utf8_json(name: str) -> None:
    _load(name)


@pytest.mark.parametrize("name", DATA_FILES)
def test_no_sanitising_marker_is_left(name: str) -> None:
    assert "<account>" not in (FIXTURE / name).read_text(encoding="utf-8")


def test_readme_names_the_tool_versions() -> None:
    # One version per tool: unpacking fails loudly if the files disagree.
    (prowler,) = {f["metadata"]["product"]["version"] for f in _load("prowler.json")}
    (trivy,) = {_load(n)["Trivy"]["Version"] for n in ("trivy-config.json", "trivy-rootfs.json")}
    checkov = _load("checkov.json")["summary"]["checkov_version"]
    text = _readme()
    assert f"Prowler {prowler}" in text
    assert f"Trivy {trivy}" in text
    assert f"Checkov {checkov}" in text


def test_readme_names_the_region() -> None:
    (region,) = {f["cloud"]["region"] for f in _load("prowler.json")}
    assert f"`{region}`" in _readme()


def test_prowler_records_match_the_readme() -> None:
    status = [f["status_code"] for f in _load("prowler.json")]
    failed, passed = status.count("FAIL"), status.count("PASS")
    assert failed + passed == len(status)
    assert (
        f"the {failed} FAIL findings of the run and its first {passed} PASS findings" in _readme()
    )


def test_trivy_rootfs_matches_the_readme() -> None:
    results = _load("trivy-rootfs.json")["Results"]
    assert len(results) == 1
    assert not results[0].get("Vulnerabilities")
    packages = len(results[0]["Packages"])
    assert f"the first {packages} packages of the package list" in _readme()
    assert "the scan found no vulnerabilities" in _readme()


def test_whole_files_match_the_readme() -> None:
    checkov = _load("checkov.json")
    failed = len(checkov["results"]["failed_checks"])
    passed = len(checkov["results"]["passed_checks"])
    assert (failed, passed) == (checkov["summary"]["failed"], checkov["summary"]["passed"])
    misconfigs = sum(
        len(r.get("Misconfigurations") or []) for r in _load("trivy-config.json")["Results"]
    )
    text = _readme()
    assert f"`checkov.json` ({failed} failed and {passed} passed checks)" in text
    assert f"`trivy-config.json` ({misconfigs} misconfigurations)" in text
