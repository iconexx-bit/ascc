"""Store invariants for `ascc correlate --store`.

CLAUDE.md, "Store": an ABSENT or EMPTY store produces byte-identical SARIF.
The flag alone never leaks persistence into the artifact. A populated store
legitimately changes output; that is Step 6, not a violation.
test_store_flag_is_output_neutral tests exactly this form: it points --store
at a fresh, empty tmp directory.

Raw byte comparison, matching test_cli_golden.py: the SARIF output has no
volatile fields, so normalization would only weaken the assertion.

test_store_persists_facts replaces test_store_writes_nothing, the tripwire
Step 1 laid for this change. Inverted in the red commit, not by the
implementation agent, as its docstring required: the first implementation
that persists a Fact changes it consciously.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ascc.store import JsonlFactRepository

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_REL = "fixtures/leaky_data_lake"

# Pairs ProwlerParser observes in fixtures/leaky_data_lake, verified 2026-09-10.
# The exact set is the oracle: a count of two survives persisting the wrong two.
EXPECTED_KEYS = {
    ("aws:ec2:instance:datalake-etl", "aws:ec2:instance:i-0a1b2c3d4e5f67890"),
    (
        "aws:ec2:security-group:datalake-etl-sg",
        "aws:ec2:security-group:sg-0f9e8d7c6b5a43210",
    ),
}


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


def test_store_persists_facts(tmp_path: Path) -> None:
    """Inverted tripwire: the flag writes now, and what it writes is pinned.

    Exactly the pairs Prowler observes in the fixture reach the store, each
    under its canonical key; the exact set, not a count, since a count of two
    survives persisting the wrong two. Only observed_together is emitted.
    payload carries the source and evidence that Fact has no field for.
    observed_at is the clock the CLI injected during this run; one second of
    slack absorbs serialisation precision, not skew: both clocks are this
    host's.
    """
    store = tmp_path / "facts"
    before = datetime.now(UTC)
    proc = _run_correlate(tmp_path / "out.sarif.json", store=store)
    after = datetime.now(UTC)
    assert proc.returncode == 0, f"--store run failed: rc={proc.returncode}\n{proc.stderr.decode()}"

    facts = list(JsonlFactRepository(store).all(now=after))
    assert facts, "store is empty after a --store run"
    assert {f.key for f in facts} == EXPECTED_KEYS
    for f in facts:
        assert f.method == "observed_together", f.method
        assert set(f.payload) == {"source", "evidence"}, f.payload
        assert before - timedelta(seconds=1) <= f.observed_at <= after
