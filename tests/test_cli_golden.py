"""Golden baseline test for `ascc correlate --output`.

Raw byte comparison is valid here because the SARIF output has no
volatile fields: no timestamps, no guids, no package version, no
absolute paths. Two runs over the same fixtures produce the same bytes,
so the CLI's current output can be pinned against a checked-in baseline
without normalization.

The baseline (tests/data/leaky_data_lake.sarif.json) is generated
manually, not by this test -- see the skip message below for the command.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path(__file__).parent / "data" / "leaky_data_lake.sarif.json"


def test_matches_golden(tmp_path: Path) -> None:
    if not BASELINE.exists():
        pytest.skip(
            f"Baseline missing: {BASELINE}. Regenerate with: "
            f"uv run python -m ascc correlate --input fixtures/leaky_data_lake "
            f"--output {BASELINE}"
        )

    tmp_out = tmp_path / "leaky_data_lake.sarif.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "ascc",
            "correlate",
            "--input",
            "fixtures/leaky_data_lake",
            "--output",
            str(tmp_out),
        ],
        check=True,
        cwd=REPO_ROOT,
        capture_output=True,
    )

    assert tmp_out.read_bytes() == BASELINE.read_bytes()
