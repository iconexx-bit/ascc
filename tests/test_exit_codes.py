"""Якорь контракта кодов возврата. Меняется только осознанно."""

import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parents[1] / "fixtures" / "leaky_data_lake"
CMD = [sys.executable, "-m", "ascc"]


def _run(*args: str) -> int:
    return subprocess.run([*CMD, *args], capture_output=True, check=False).returncode


def test_help_succeeds():
    assert _run("--help") == 0


def test_missing_input_is_usage_error():
    assert _run("correlate", "--input", "/nonexistent") == 2


def test_no_recognized_files(tmp_path):
    assert _run("correlate", "--input", str(tmp_path)) == 3


def test_valid_fixtures_succeed():
    assert _run("correlate", "--input", "fixtures/leaky_data_lake") == 0
