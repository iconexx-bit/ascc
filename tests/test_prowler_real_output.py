"""ProwlerParser reads current Prowler output (OCSF, Prowler 5.46.0).

Current OCSF output carries `finding_info.created_time` as epoch seconds (an
integer); older output and the synthetic fixture carry an ISO 8601 string.
Both become an aware UTC `started_at`. Before this, the integer ended in
`TypeError` inside `datetime.fromisoformat`, and the CLI stopped with exit 70
on every real Prowler file (tests/test_cli_parse_errors.py pins that boundary).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ascc.ingest.prowler import ProwlerParser

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL = REPO_ROOT / "fixtures" / "leaky_data_lake_real" / "prowler.json"
SYNTHETIC = REPO_ROOT / "fixtures" / "leaky_data_lake" / "prowler.json"


def _entries(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_real_output_parses_with_every_fail_finding() -> None:
    fails = sum(1 for e in _entries(REAL) if e["status_code"] == "FAIL")
    assert len(ProwlerParser().parse(REAL).findings) == fails


def test_epoch_created_time_becomes_utc_started_at() -> None:
    first = min(e["finding_info"]["created_time"] for e in _entries(REAL))
    started_at = ProwlerParser().parse(REAL).started_at
    assert started_at == datetime.fromtimestamp(first, tz=UTC)
    assert started_at is not None and started_at.utcoffset() == timedelta(0)


def test_iso_created_time_still_parses() -> None:
    first = min(
        datetime.fromisoformat(e["finding_info"]["created_time"]) for e in _entries(SYNTHETIC)
    )
    assert ProwlerParser().parse(SYNTHETIC).started_at == first


def test_cli_reads_the_real_prowler_file(tmp_path: Path) -> None:
    inputs = tmp_path / "in"
    inputs.mkdir()
    shutil.copy(REAL, inputs / "prowler.json")
    sarif = tmp_path / "out.sarif.json"
    proc = subprocess.run(
        [sys.executable, "-m", "ascc", "correlate", "--input", str(inputs), "--output", str(sarif)],
        cwd=REPO_ROOT,
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert sarif.exists()


def test_contract_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "Prowler `finding_info.created_time` is epoch seconds" in text
