"""Conformance suite for FactRepository implementations.

Parametrised over every concrete repository: InMemory today, Jsonl and Postgres
later. One suite, because the ABC makes them observationally equivalent —
InMemory overwrites by key, Jsonl will append and let the last write win, and
from the outside those are the same behaviour.

Disjoint from tests/test_fact_repository.py, which covers the Fact dataclass,
the abstractness of the ABC, signature introspection and the source-level guards.
This file covers what a concrete implementation actually does.

Method literals and confidence ceilings are ground truth from
src/ascc/schema/identity.py and src/ascc/ingest/prowler.py.

Every date is year-2000: an implementation that resolves time internally instead
of using the injected `now` fails deterministically, not 99.9% of the time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ascc.store import Fact, InMemoryFactRepository, JsonlFactRepository

if TYPE_CHECKING:
    from ascc.store import FactRepository

T0 = datetime(2000, 1, 1, tzinfo=UTC)
DAY = timedelta(days=1)

# terraform_natural_name is source_bound: 30d. arn_parse never expires.
# observed_together is run_bound: 7d.
TF = "terraform_natural_name"
ARN = "arn_parse"


def _in_memory(tmp_path: Path) -> FactRepository:
    return InMemoryFactRepository()


def _jsonl(tmp_path: Path) -> FactRepository:
    return JsonlFactRepository(tmp_path)


IMPLEMENTATIONS = (_in_memory, _jsonl)


@pytest.fixture(params=IMPLEMENTATIONS, ids=lambda f: f.__name__.removeprefix("_"))
def repo(request: pytest.FixtureRequest, tmp_path: Path) -> FactRepository:
    """Every implementation is built from a directory it may ignore."""
    return request.param(tmp_path)


def make_fact(
    key: tuple[str, ...] = ("aws:s3:bucket:datalake-raw",),
    method: str = TF,
    confidence: float = 1.0,
    observed_at: datetime = T0,
    **kwargs: object,
) -> Fact:
    return Fact(key=key, method=method, confidence=confidence, observed_at=observed_at, **kwargs)


# --- basic contract --------------------------------------------------------


def test_get_missing_key_returns_none(repo: FactRepository) -> None:
    assert repo.get(("nope",), now=T0) is None


def test_put_then_get_round_trips(repo: FactRepository) -> None:
    fact = make_fact()
    repo.put(fact, now=T0)
    stored = repo.get(fact.key, now=T0)
    assert stored is not None
    assert stored.key == fact.key
    assert stored.method == fact.method
    assert stored.confidence == fact.confidence


def test_all_is_empty_on_a_fresh_repository(repo: FactRepository) -> None:
    assert list(repo.all(now=T0)) == []


def test_all_returns_every_stored_fact(repo: FactRepository) -> None:
    repo.put(make_fact(key=("a",)), now=T0)
    repo.put(make_fact(key=("b",)), now=T0)
    assert {f.key for f in repo.all(now=T0)} == {("a",), ("b",)}


# --- observed_at is the TTL anchor -----------------------------------------


def test_put_preserves_observed_at(repo: FactRepository) -> None:
    """The anchor is the caller's, not the repository's.

    A put that stamps `now` onto observed_at would launder freshness the moment
    Jsonl reloads from disk, and the TTL model becomes decorative.
    """
    fact = make_fact(observed_at=T0)
    repo.put(fact, now=T0 + timedelta(days=365))
    stored = repo.get(fact.key, now=T0 + timedelta(days=365))
    assert stored is not None
    assert stored.observed_at == T0


def test_overwrite_preserves_the_new_observed_at(repo: FactRepository) -> None:
    """Re-observation is a new put carrying its own observed_at."""
    key = ("aws:s3:bucket:x",)
    later = T0 + timedelta(days=10)
    repo.put(make_fact(key=key, observed_at=T0), now=T0)
    repo.put(make_fact(key=key, observed_at=later), now=later)
    stored = repo.get(key, now=later)
    assert stored is not None
    assert stored.observed_at == later


# --- stale is rendered at read, not stored ---------------------------------


def test_fresh_fact_reads_not_stale(repo: FactRepository) -> None:
    """Hidden-clock detector: a year-2000 fact one day old is fresh."""
    fact = make_fact(observed_at=T0)
    repo.put(fact, now=T0)
    stored = repo.get(fact.key, now=T0 + DAY)
    assert stored is not None
    assert stored.stale is False


def test_expired_fact_reads_stale_and_is_still_returned(repo: FactRepository) -> None:
    """Expiry marks; it never deletes. Provenance survives."""
    fact = make_fact(observed_at=T0, confidence=1.0)
    repo.put(fact, now=T0)
    stored = repo.get(fact.key, now=T0 + timedelta(days=31))
    assert stored is not None
    assert stored.stale is True
    assert stored.confidence == 1.0
    assert stored.observed_at == T0


def test_staleness_is_not_persisted_by_a_read(repo: FactRepository) -> None:
    """Reading with a late `now` must not mutate the stored record.

    This is the structural proof that stale is a rendering of policy at a given
    `now`, not state the repository owns.
    """
    fact = make_fact(observed_at=T0)
    repo.put(fact, now=T0)
    assert repo.get(fact.key, now=T0 + timedelta(days=31)).stale is True
    assert repo.get(fact.key, now=T0 + DAY).stale is False


def test_method_with_no_ttl_never_reads_stale(repo: FactRepository) -> None:
    """arn_parse compares strings; string comparison does not age."""
    fact = make_fact(method=ARN, observed_at=T0)
    repo.put(fact, now=T0)
    stored = repo.get(fact.key, now=T0 + timedelta(days=36500))
    assert stored is not None
    assert stored.stale is False


def test_all_renders_staleness_too(repo: FactRepository) -> None:
    """get and all must agree; expiry is not a get-only concern."""
    repo.put(make_fact(key=("old",), observed_at=T0), now=T0)
    repo.put(
        make_fact(key=("new",), observed_at=T0 + timedelta(days=30)), now=T0 + timedelta(days=30)
    )
    by_key = {f.key: f.stale for f in repo.all(now=T0 + timedelta(days=31))}
    assert by_key[("old",)] is True
    assert by_key[("new",)] is False


# --- validation lives in put -----------------------------------------------


def test_put_rejects_unknown_method(repo: FactRepository) -> None:
    """A producer without a TTL policy entry is a bug, caught on write."""
    with pytest.raises(KeyError):
        repo.put(make_fact(method="kubernetes_owner_ref"), now=T0)


def test_put_rejects_confidence_above_the_ceiling(repo: FactRepository) -> None:
    """The llm cap (0.3) becomes enforceable rather than conventional."""
    with pytest.raises(ValueError, match="confidence"):
        repo.put(make_fact(method="llm", confidence=0.9), now=T0)


def test_put_accepts_confidence_at_the_ceiling(repo: FactRepository) -> None:
    repo.put(make_fact(method="llm", confidence=0.3), now=T0)
    assert repo.get(("aws:s3:bucket:datalake-raw",), now=T0) is not None


def test_put_rejects_a_fact_from_the_future(repo: FactRepository) -> None:
    """The only legitimate use of `now` on write: reject impossible facts."""
    with pytest.raises(ValueError, match="observed_at"):
        repo.put(make_fact(observed_at=T0 + DAY), now=T0)


def test_put_accepts_observed_at_equal_to_now(repo: FactRepository) -> None:
    """Boundary: observed_at == now is the common case, not the future."""
    repo.put(make_fact(observed_at=T0), now=T0)
    assert repo.get(("aws:s3:bucket:datalake-raw",), now=T0) is not None


def test_naive_now_is_rejected(repo: FactRepository) -> None:
    """aware/naive mixing is the classic source of 'stale after three hours'."""
    repo.put(make_fact(), now=T0)
    with pytest.raises(ValueError):
        repo.get(("aws:s3:bucket:datalake-raw",), now=datetime(2000, 1, 2))  # noqa: DTZ001 — naive is the subject under test


# --- keys ------------------------------------------------------------------


def test_put_overwrites_by_key(repo: FactRepository) -> None:
    """History of observations is not kept in v1 (see CLAUDE.md Backlog)."""
    key = ("aws:s3:bucket:x",)
    repo.put(make_fact(key=key, confidence=1.0), now=T0)
    repo.put(make_fact(key=key, confidence=0.5, method="filesystem_path_heuristic"), now=T0)
    stored = repo.get(key, now=T0)
    assert stored is not None
    assert stored.confidence == 0.5
    assert len(list(repo.all(now=T0))) == 1


def test_facts_coexist_when_the_method_is_in_the_key(repo: FactRepository) -> None:
    """key does not contain method, so a producer that needs both must say so.

    Without this, an llm fact (0.3) would silently overwrite an arn_parse
    fact (1.0) about the same subject, and scanner ordering would decide
    what the store holds.
    """
    subject = "aws:s3:bucket:x"
    repo.put(make_fact(key=(ARN, subject), method=ARN, confidence=1.0), now=T0)
    repo.put(make_fact(key=("llm", subject), method="llm", confidence=0.3), now=T0)
    assert repo.get((ARN, subject), now=T0).confidence == 1.0
    assert repo.get(("llm", subject), now=T0).confidence == 0.3


def test_payload_survives_a_round_trip(repo: FactRepository) -> None:
    fact = make_fact(payload={"scanner": "prowler", "region": "eu-west-1"})
    repo.put(fact, now=T0)
    stored = repo.get(fact.key, now=T0)
    assert stored is not None
    assert dict(stored.payload) == {"scanner": "prowler", "region": "eu-west-1"}


def test_all_does_not_repeat_an_overwritten_key(repo: FactRepository) -> None:
    """Append-only storage must collapse duplicate keys on read."""
    key = ("aws:s3:bucket:datalake-raw",)
    repo.put(make_fact(key=key, confidence=0.4), now=T0)
    repo.put(make_fact(key=key, confidence=0.9), now=T0)
    facts = list(repo.all(now=T0))
    assert len(facts) == 1
    assert facts[0].confidence == 0.9
