"""Tests that assert on CLI output do not depend on the caller's console.

The CLI prints through Rich, which takes the console width from COLUMNS or from
the terminal the process inherits, stdin included. A test run started from a
narrow terminal wrapped "Attack chains: ..." over two lines and failed two tests
that pass in CI. tests/conftest.py pins ASCC_CONSOLE_WIDTH for every test; this
test runs those two tests under COLUMNS=40 and expects them to pass.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PRINTED_LINE_TESTS = (
    "tests/test_sarif_chains.py::test_cli_prints_chain_count",
    "tests/test_readme_demo.py::test_cli_line_matches_a_live_run",
)


def test_printed_line_tests_pass_in_a_narrow_console() -> None:
    env = {k: v for k, v in os.environ.items() if k != "ASCC_CONSOLE_WIDTH"}
    env["COLUMNS"] = "40"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *PRINTED_LINE_TESTS],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout[-3000:]
