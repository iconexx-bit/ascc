"""Step 5 contract for `ascc correlate --store`: CLI wiring and the mapper.

CLAUDE.md, "Store" -> "CLI wiring + producer". test_store_invariant.py pins
what a --store run persists; this file pins what it cannot see:

- A store-only run (no --output) is legitimate. The store block sits after
  the --output block, positionally, never nested under it.
- The Fact key is the sorted pair of the sides' string forms, so any caller,
  Step 6's get() included, can rebuild it from an unordered pair without
  constructing a BridgeFact.
- A store write failure after the SARIF is on disk warns on stderr and keeps
  ExitCode.OK: the artifact already succeeded. Without --output the store is
  the only product, and the same failure exits ExitCode.INTERNAL.

The mapper is fed a stand-in rather than a real BridgeFact: __post_init__
already orders a real pair by the same str comparison, so no real BridgeFact
can reach the mapper unsorted. Only a stand-in makes the mapper's own sort
observable, and it spares the test MatchKey's constructor.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from ascc.store import JsonlFactRepository

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_REL = "fixtures/leaky_data_lake"
T0 = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
EXIT_INTERNAL = 70  # ExitCode.INTERNAL, pinned as a number: shell-facing contract


def _run_correlate(*extra: str) -> subprocess.CompletedProcess[bytes]:
    cmd = [sys.executable, "-m", "ascc", "correlate", "--input", FIXTURE_REL, *extra]
    return subprocess.run(cmd, check=False, cwd=REPO_ROOT, capture_output=True)


# -- wiring: the store block does not depend on --output ----------------------


def test_store_without_output_persists_facts(tmp_path: Path) -> None:
    """--store is not an adjunct of --output: a store-only run must persist.

    Kills the nesting mutation, the store block placed inside
    `if output is not None:`, which test_store_persists_facts cannot see.
    """
    store = tmp_path / "facts"
    proc = _run_correlate("--store", str(store))
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stderr.decode()}"

    facts = list(JsonlFactRepository(store).all(now=datetime.now(UTC)))
    assert facts, "store is empty after a --store run without --output"


# -- mapper: one pair, one canonical key ----------------------------------------


@dataclass(frozen=True)
class _Opaque:
    """Stands in for MatchKey: has __str__, is not a str, is not orderable."""

    text: str

    def __str__(self) -> str:
        return self.text


def _pair(left: str, right: str) -> SimpleNamespace:
    return SimpleNamespace(
        left=_Opaque(left),
        right=_Opaque(right),
        method="observed_together",
        confidence=0.95,
        source="prowler",
        evidence="uid and name in one resources[] record",
    )


def test_one_pair_yields_one_record(tmp_path: Path) -> None:
    """Both orientations of a pair map to one canonical key, hence one record.

    The import sits inside the test so that, while the mapper is missing, this
    test fails alone instead of erroring the whole module at collection.
    _Opaque makes a forgotten str() observable: sorted() on the raw sides
    raises TypeError, and a non-str element never equals the expected tuple.
    """
    from ascc.cli import _to_fact

    forward = _to_fact(_pair("key-b", "key-a"), observed_at=T0)
    reverse = _to_fact(_pair("key-a", "key-b"), observed_at=T0)
    assert forward.key == reverse.key == ("key-a", "key-b")

    repo = JsonlFactRepository(tmp_path / "facts")
    repo.put(forward, now=T0)
    repo.put(reverse, now=T0)
    assert len(list(repo.all(now=T0))) == 1


# -- store write failure: the exit code follows what the run was asked for ----


def _unwritable_store(tmp_path: Path) -> Path:
    """A regular file where the store's parent should be: mkdir fails for any
    user, root included, so these tests do not depend on permissions."""
    blocker = tmp_path / "blocker"
    blocker.write_text("")
    return blocker / "facts"


def test_store_write_failure_keeps_exit_ok(tmp_path: Path) -> None:
    """With --output the SARIF is the product, and it is already on disk."""
    store = _unwritable_store(tmp_path)
    out = tmp_path / "out.sarif.json"
    proc = _run_correlate("--output", str(out), "--store", str(store))
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stderr.decode()}"
    assert out.is_file(), "SARIF must be on disk before the store is touched"
    assert b"store" in proc.stderr.lower(), proc.stderr.decode()


def test_store_only_write_failure_exits_internal(tmp_path: Path) -> None:
    """Without --output the store is the only product: losing it is not a
    warning. Fail-open would read as "no history" to Step 6."""
    store = _unwritable_store(tmp_path)
    proc = _run_correlate("--store", str(store))
    assert proc.returncode == EXIT_INTERNAL, f"rc={proc.returncode}\n{proc.stderr.decode()}"
    assert b"store" in proc.stderr.lower(), proc.stderr.decode()
