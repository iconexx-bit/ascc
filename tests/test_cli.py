from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ascc.cli import app

runner = CliRunner()


@pytest.fixture(scope="module")
def result(fixtures_dir: Path):
    os.environ["ASCC_CONSOLE_WIDTH"] = "200"
    try:
        return runner.invoke(app, ["correlate", "--input", str(fixtures_dir)])
    finally:
        os.environ.pop("ASCC_CONSOLE_WIDTH", None)


def test_exit_code_zero(result) -> None:
    assert result.exit_code == 0


def test_shows_both_ec2_keys(result) -> None:
    assert "aws:ec2:instance:datalake-etl" in result.output
    assert "aws:ec2:instance:i-0a1b2c3d4e5f67890" in result.output


def test_shows_bridge_composition(result) -> None:
    assert "0.475" in result.output


def test_shows_checkov_findings(result) -> None:
    assert "CKV_AWS_40" in result.output


def test_warns_about_skipped_readme(result) -> None:
    assert "README.md" in result.output
    assert "not valid JSON" in result.output


def test_exit_one_when_nothing_recognized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASCC_CONSOLE_WIDTH", "200")
    (tmp_path / "not_a_scanner.json").write_text("{}")
    result = runner.invoke(app, ["correlate", "--input", str(tmp_path)])
    assert result.exit_code == 1
