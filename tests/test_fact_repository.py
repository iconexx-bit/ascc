"""Contract tests for ascc.store: Fact and FactRepository.

Two kinds of assertions live here.

Behavioural: Fact is immutable, FactRepository is abstract, and every
repository method takes an injected `now`. Structural: the store module
never reads the wall clock and never imports a database driver. The
structural ones are source-level greps on purpose -- a repository that
calls datetime.now() internally still passes every behavioural test
written against it, because faked time and real time are
indistinguishable from the outside. Only reading the source catches it.

Both structural invariants are recorded in CLAUDE.md ("Store"); until
now neither was machine-checked.

Written before src/ascc/store contains anything (TDD red).
"""

from __future__ import annotations

import dataclasses
import inspect
import pathlib
from datetime import UTC, datetime

import pytest

ROOT = pathlib.Path(__file__).parents[1]
STORE_DIR = ROOT / "src" / "ascc" / "store"

CLOCK_CALLS = ("datetime.now", "utcnow", "time.time", "time.monotonic")
DB_DRIVERS = ("psycopg", "asyncpg", "sqlite3", "sqlalchemy", "pymongo", "duckdb")

T0 = datetime(2026, 1, 1, tzinfo=UTC)


# --- behavioural ----------------------------------------------------------


def test_fact_is_frozen() -> None:
    from ascc.store import Fact

    fact = Fact(key=("arn:aws:s3:::bucket",), method="arn", confidence=1.0, observed_at=T0)
    assert dataclasses.is_dataclass(fact)
    with pytest.raises(dataclasses.FrozenInstanceError):
        fact.confidence = 0.5  # type: ignore[misc]


def test_fact_defaults_to_not_stale() -> None:
    from ascc.store import Fact

    fact = Fact(key=("k",), method="arn", confidence=1.0, observed_at=T0)
    assert fact.stale is False


def test_repository_is_abstract() -> None:
    from ascc.store import FactRepository

    with pytest.raises(TypeError):
        FactRepository()  # type: ignore[abstract]


@pytest.mark.parametrize("method_name", ["put", "get", "all"])
def test_repository_methods_require_injected_now(method_name: str) -> None:
    """`now` must be a keyword-only parameter with no default on every method."""
    from ascc.store import FactRepository

    sig = inspect.signature(getattr(FactRepository, method_name))
    assert "now" in sig.parameters, f"{method_name}() has no `now` parameter"
    param = sig.parameters["now"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY, (
        f"{method_name}(): `now` must be keyword-only"
    )
    assert param.default is inspect.Parameter.empty, (
        f"{method_name}(): `now` must not have a default"
    )


# --- structural -----------------------------------------------------------


def _offenders(needles: tuple[str, ...]) -> list[str]:
    return [
        f"{path.relative_to(ROOT)}:{lineno}: {needle}"
        for path in STORE_DIR.rglob("*.py")
        for lineno, line in enumerate(path.read_text().splitlines(), 1)
        for needle in needles
        if needle in line and not line.lstrip().startswith("#")
    ]


def test_store_never_reads_the_clock() -> None:
    """Time is injected. Reading it inside the store defeats the injection."""
    assert not _offenders(CLOCK_CALLS)


def test_store_imports_no_database_drivers() -> None:
    """CLAUDE.md, "Store": ascc.store must not import database drivers."""
    assert not _offenders(DB_DRIVERS)
