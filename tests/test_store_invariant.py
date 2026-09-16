"""Store invariants for `ascc correlate --store`.

CLAUDE.md, "Store": an ABSENT or EMPTY store produces byte-identical SARIF.
The flag alone never leaks persistence into the artifact. A populated store
legitimately changes output; that is Step 7 (to_sarif reads
CorrelationRun.clusters), not a violation — Step 6 only reached
CorrelationRun.clusters, and measurably left SARIF bytes untouched (see
CLAUDE.md, "Step 6: store consumer", DoD note). test_store_flag_is_output_neutral
tests exactly the neutral form: it points --store at a fresh, empty tmp
directory.  test_populated_store_exposes_ghost_membership_in_sarif is the
companion on the other side of that line: same fixture, a store the first
run actually populated, and it must NOT be byte-identical to the neutral case.

Raw byte comparison, matching test_cli_golden.py: the SARIF output has no
volatile fields, so normalization would only weaken the assertion.

test_store_persists_facts replaces test_store_writes_nothing, the tripwire
Step 1 laid for this change. Inverted in the red commit, not by the
implementation agent, as its docstring required: the first implementation
that persists a Fact changes it consciously.
test_store_persists_facts is widened again for payload v1 in the Step 6 red
commit — same rule, same reason: the first implementation that writes the new
payload changes this assertion consciously, not the implementation agent.
"""

from __future__ import annotations

import json
import shutil
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
# payload v1 (CLAUDE.md, "### Step 6: store consumer"). Fact.payload is
# Mapping[str, str], so endpoints are flat prefixed keys, never nested.
EXPECTED_PAYLOAD_KEYS = {
    "payload_v",
    "source",
    "evidence",
    "left.partition",
    "left.service",
    "left.resource_type",
    "left.identifier",
    "right.partition",
    "right.service",
    "right.resource_type",
    "right.identifier",
}


def _run_correlate(
    output: Path, *, store: Path | None = None, input_dir: str | Path = FIXTURE_REL
) -> subprocess.CompletedProcess[bytes]:
    cmd = [
        sys.executable,
        "-m",
        "ascc",
        "correlate",
        "--input",
        str(input_dir),
        "--output",
        str(output),
    ]
    if store is not None:
        cmd += ["--store", str(store)]
    return subprocess.run(cmd, check=False, cwd=REPO_ROOT, capture_output=True)


def _fixture_without_prowler(tmp_path: Path) -> Path:
    """A copy of the fixture missing prowler.json.

    Only Prowler ever observes the generated-id ARNs for the EC2 instance
    (`i-0a1b2c3d4e5f67890`) and its security group (`sg-0f9e8d7c6b5a43210`)
    -- verified by grep against the raw fixtures. Dropping its file removes
    those two keys from THIS run's own `resources` while Trivy's natural-name
    keys (`datalake-etl`, `datalake-etl-sg`) stay put: exactly the shape of a
    ghost node reintroduced from a store the first run already populated.
    """
    reduced = tmp_path / "reduced"
    reduced.mkdir()
    for file in (REPO_ROOT / FIXTURE_REL).iterdir():
        if file.is_file() and file.name != "prowler.json":
            shutil.copy2(file, reduced / file.name)
    return reduced


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
        assert set(f.payload) == EXPECTED_PAYLOAD_KEYS, f.payload
        assert f.payload["payload_v"] == "1", f.payload
        assert before - timedelta(seconds=1) <= f.observed_at <= after


def test_populated_store_exposes_ghost_membership_in_sarif(tmp_path: Path) -> None:
    """CLAUDE.md Step 7: a populated store legitimately changes SARIF bytes.

    Run 1 (full fixture) persists Prowler's observed_together facts. Run 2
    reads that history back over a fixture copy missing prowler.json, so the
    generated-id ARNs it bridges to are ghosts -- present only via history,
    absent from run 2's own resources -- and must show up in
    properties.ghost_members on the Trivy result that shares their cluster.
    """
    store = tmp_path / "facts"

    run1 = _run_correlate(tmp_path / "run1.sarif.json", store=store)
    assert run1.returncode == 0, f"run 1 failed: {run1.stderr.decode()}"

    reduced_input = _fixture_without_prowler(tmp_path)
    run2_out = tmp_path / "run2.sarif.json"
    run2 = _run_correlate(run2_out, store=store, input_dir=reduced_input)
    assert run2.returncode == 0, f"run 2 failed: {run2.stderr.decode()}"

    results = json.loads(run2_out.read_bytes())["runs"][0]["results"]
    log4shell = next(r for r in results if "CVE-2021-44228" in r["ruleId"])
    assert log4shell["properties"]["ghost_members"] == ["aws:ec2:instance:i-0a1b2c3d4e5f67890"]
    assert log4shell["properties"]["cluster_members"] == [
        "aws:ec2:instance:datalake-etl",
        "aws:ec2:instance:i-0a1b2c3d4e5f67890",
    ]

    ssh_open = next(r for r in results if "AVD-AWS-0107" in r["ruleId"])
    assert ssh_open["properties"]["ghost_members"] == [
        "aws:ec2:security-group:sg-0f9e8d7c6b5a43210"
    ]
