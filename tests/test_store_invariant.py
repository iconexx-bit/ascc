"""Output-neutrality invariant for `ascc correlate --store`.

CLAUDE.md, "Store": `--store` is orthogonal to `--input`; absent or
present, the SARIF output must be byte-identical to the golden baseline.
Persistence is not allowed to leak into the product artifact.

Raw byte comparison, matching test_cli_golden.py: the SARIF output has no
volatile fields, so normalization would only weaken the assertion.

Written before any store code exists (TDD red). test_store_writes_nothing
is deliberately a tripwire for the next PR: the first implementation that
persists a Fact must change it consciously, not silently.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_REL = "fixtures/leaky_data_lake"


def _run_correlate(
    output: Path, *, store: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    cmd = [
        sys.executable,
        "-m",
        "ascc",
        "correlate",
        "--input",
        FIXTURE_REL,
        "--output",
        str(output),
    ]
    if store is not None:
        cmd += ["--store", str(store)]
    return subprocess.run(cmd, check=False, cwd=REPO_ROOT, capture_output=True)


def test_store_flag_is_output_neutral(tmp_path: Path) -> None:
    without = tmp_path / "without.sarif.json"
    with_ = tmp_path / "with.sarif.json"
    store = tmp_path / "facts"

    base = _run_correlate(without)
    assert base.returncode == 0, f"baseline run failed: {base.stderr.decode()}"

    stored = _run_correlate(with_, store=store)
    assert stored.returncode == 0, (
        f"--store run failed: rc={stored.returncode}\n{stored.stderr.decode()}"
    )

    assert with_.read_bytes() == without.read_bytes()


def test_store_writes_nothing(tmp_path: Path) -> None:
    store = tmp_path / "facts"
    proc = _run_correlate(tmp_path / "out.sarif.json", store=store)
    assert proc.returncode == 0, f"--store run failed: rc={proc.returncode}\n{proc.stderr.decode()}"

    assert not store.exists() or not any(store.iterdir())
