"""Durability and on-disk format for JsonlFactRepository.

Disjoint from test_repository_conformance.py: that file covers behaviour every
implementation shares, this one covers what only a file-backed one can get wrong
— survival across instances, format stability, and reads that must not write.

T0 and make_fact are redefined locally rather than imported: this file asserts
against the serialised form, and must not drift silently when the shared
fixture changes shape.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ascc.store import Fact, JsonlFactRepository
from ascc.store.policy import ttl_for

T0 = datetime(2000, 1, 1, tzinfo=UTC)
TF = "terraform_natural_name"
RUN = "observed_together"


def make_fact(
    key=("aws:s3:bucket:datalake-raw",), method=TF, confidence=1.0, observed_at=T0, payload=None
) -> Fact:
    kwargs = {"key": key, "method": method, "confidence": confidence, "observed_at": observed_at}
    if payload is not None:
        kwargs["payload"] = payload
    return Fact(**kwargs)


def _lines(tmp_path: Path) -> list[dict]:
    [f] = [p for p in tmp_path.rglob("*") if p.is_file()]
    return [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines()]


# -- durability -------------------------------------------------------------


def test_reload_preserves_observed_at(tmp_path: Path) -> None:
    """A reload must not launder freshness by re-anchoring observed_at."""
    fact = make_fact(method=RUN, confidence=0.95, observed_at=T0)
    JsonlFactRepository(tmp_path).put(fact, now=T0)

    reloaded = JsonlFactRepository(tmp_path).get(fact.key, now=T0)
    assert reloaded.observed_at == T0

    expired_at = T0 + ttl_for(RUN)
    assert JsonlFactRepository(tmp_path).get(fact.key, now=expired_at).stale is True


def test_facts_survive_a_new_instance(tmp_path: Path) -> None:
    fact = make_fact()
    JsonlFactRepository(tmp_path).put(fact, now=T0)
    assert JsonlFactRepository(tmp_path).get(fact.key, now=T0) == fact


def test_payload_reloads_as_a_mapping(tmp_path: Path) -> None:
    fact = make_fact(payload={"region": "eu-west-1", "arn": "arn:aws:s3:::x"})
    JsonlFactRepository(tmp_path).put(fact, now=T0)
    assert JsonlFactRepository(tmp_path).get(fact.key, now=T0).payload == fact.payload


def test_directory_is_created_on_first_put(tmp_path: Path) -> None:
    """--store accepts a non-existent path; the CLI does not create it."""
    target = tmp_path / "absent" / "store"
    repo = JsonlFactRepository(target)
    assert not target.exists(), "construction must not touch the filesystem"
    repo.put(make_fact(), now=T0)
    assert target.is_dir()


# -- on-disk format ---------------------------------------------------------


def test_stale_is_not_serialised(tmp_path: Path) -> None:
    JsonlFactRepository(tmp_path).put(make_fact(), now=T0)
    assert "stale" not in _lines(tmp_path)[0]


def test_file_encodes_neither_ttl_nor_policy_version(tmp_path: Path) -> None:
    """Changing TTL numbers must never require a data migration."""
    JsonlFactRepository(tmp_path).put(make_fact(), now=T0)
    raw = json.dumps(_lines(tmp_path)[0]).lower()
    assert "ttl" not in raw and "policy" not in raw


def test_overwrite_appends_and_the_last_line_wins(tmp_path: Path) -> None:
    key = ("aws:s3:bucket:datalake-raw",)
    repo = JsonlFactRepository(tmp_path)
    repo.put(make_fact(key=key, confidence=0.4), now=T0)
    repo.put(make_fact(key=key, confidence=0.9), now=T0)
    assert len(_lines(tmp_path)) == 2, "append-only: history is the point"
    assert repo.get(key, now=T0).confidence == 0.9


# -- writes that must not happen -------------------------------------------


@pytest.mark.parametrize(
    ("fact", "now", "exc"),
    [
        (make_fact(method="not_a_method"), T0, KeyError),
        (make_fact(confidence=1.5), T0, ValueError),
        (make_fact(observed_at=T0 + timedelta(days=1)), T0, ValueError),
        (make_fact(), datetime(2000, 1, 2), TypeError),  # noqa: DTZ001 — naive is the subject under test
    ],
)
def test_a_rejected_put_writes_nothing(tmp_path: Path, fact, now, exc) -> None:
    """Validation precedes the write: no partial or invalid line on disk."""
    repo = JsonlFactRepository(tmp_path)
    repo.put(make_fact(key=("seed",)), now=T0)
    before = _lines(tmp_path)
    with pytest.raises(exc):
        repo.put(fact, now=now)
    assert _lines(tmp_path) == before


def test_a_read_does_not_write(tmp_path: Path) -> None:
    repo = JsonlFactRepository(tmp_path)
    repo.put(make_fact(method=RUN, confidence=0.95), now=T0)
    [f] = [p for p in tmp_path.rglob("*") if p.is_file()]
    before = f.read_bytes()
    repo.get(("aws:s3:bucket:datalake-raw",), now=T0 + ttl_for(RUN))
    list(repo.all(now=T0 + ttl_for(RUN)))
    assert f.read_bytes() == before, "rendered staleness must never be persisted"


def test_a_truncated_trailing_line_is_skipped(tmp_path: Path) -> None:
    """Crash mid-append costs the last fact, never the whole store."""
    repo = JsonlFactRepository(tmp_path)
    repo.put(make_fact(key=("good",)), now=T0)
    [f] = [p for p in tmp_path.rglob("*") if p.is_file()]
    f.write_text(f.read_text(encoding="utf-8") + '{"v":1,"key":["tor', encoding="utf-8")
    assert JsonlFactRepository(tmp_path).get(("good",), now=T0) is not None
