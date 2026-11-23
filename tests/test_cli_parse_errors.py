"""A scanner file its parser cannot read stops the run with INTERNAL.

Before this contract an exception inside a parser escaped the CLI: Python
exited 1, which is ExitCode.FINDINGS (reserved for --fail-on), stderr carried
a traceback, and one broken file hid every other scanner's result. The input
here is Prowler-shaped (it sniffs as Prowler) but carries no finding_info
object, so no version of the parser can read it. Real cases that hit this
path on 2026-11-22: current Prowler OCSF (integer created_time) and
open-source Checkov (null severity).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "fixtures" / "leaky_data_lake"
EXIT_INTERNAL = 70  # ExitCode.INTERNAL, pinned as a number: shell-facing contract
BROKEN = "zz-broken.json"  # no scanner name in it: stderr must supply one


def _broken_prowler(directory: Path) -> Path:
    path = directory / BROKEN
    path.write_text(json.dumps([{"finding_info": None, "status_code": "FAIL"}]))
    return path


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "ascc", "correlate", *args]
    return subprocess.run(cmd, check=False, cwd=REPO_ROOT, capture_output=True, text=True)


def test_unreadable_scanner_file_exits_internal_and_names_it(tmp_path: Path) -> None:
    _broken_prowler(tmp_path)
    proc = _run("--input", str(tmp_path))
    assert proc.returncode == EXIT_INTERNAL, f"rc={proc.returncode}\n{proc.stderr}"
    assert BROKEN in proc.stderr, proc.stderr
    assert "prowler" in proc.stderr, proc.stderr


def test_unreadable_scanner_file_prints_no_traceback(tmp_path: Path) -> None:
    _broken_prowler(tmp_path)
    proc = _run("--input", str(tmp_path))
    assert "Traceback" not in proc.stderr + proc.stdout, proc.stderr


def test_unreadable_file_beside_good_ones_writes_nothing(tmp_path: Path) -> None:
    inputs = tmp_path / "in"
    shutil.copytree(FIXTURE, inputs)
    _broken_prowler(inputs)
    sarif = tmp_path / "out.sarif.json"
    store = tmp_path / "store"
    proc = _run("--input", str(inputs), "--output", str(sarif), "--store", str(store))
    assert proc.returncode == EXIT_INTERNAL, f"rc={proc.returncode}\n{proc.stderr}"
    assert not sarif.exists()
    assert not store.exists()


def test_contract_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "a recognised scanner file that its parser cannot read stops the run" in text
