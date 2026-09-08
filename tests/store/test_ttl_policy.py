"""Red tests for ascc.store.policy — TTL & confidence policy contract.

Scope: the pure policy layer only. No repository, no I/O, no clock.
Every test uses year-2000 dates: an implementation that reaches for
datetime.now() internally fails test_fresh_before_ttl deterministically,
not 99.9% of the time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from ascc.store.policy import (
    MAX_CONFIDENCE,
    TTL,
    TTL_POLICY_VERSION,
    is_stale,
    ttl_for,
)

V = datetime(2000, 1, 1, tzinfo=UTC)
DAY = timedelta(days=1)


# --- boundary --------------------------------------------------------------


def test_fresh_before_ttl() -> None:
    """Hidden-clock detector: a year-2000 fact one day old is fresh."""
    assert is_stale("terraform", V, V + DAY) is False


def test_stale_exactly_at_ttl() -> None:
    """Boundary is >=: at exactly ttl the fact is already stale."""
    assert is_stale("terraform", V, V + timedelta(days=30)) is True


def test_stale_after_ttl() -> None:
    assert is_stale("terraform", V, V + timedelta(days=31)) is True


def test_never_stale_when_ttl_is_none() -> None:
    """arn bridges compare strings; string comparison does not age."""
    assert is_stale("arn", V, V + timedelta(days=36500)) is False


# --- contracts -------------------------------------------------------------


def test_unknown_method_raises() -> None:
    """Fail loud: a new method without a policy entry is a bug, not a default."""
    with pytest.raises(KeyError):
        is_stale("kubernetes", V, V + DAY)


@pytest.mark.parametrize(
    ("verified_at", "as_of"),
    [
        (datetime(2000, 1, 1), V + DAY),  # noqa: DTZ001 — naive is the subject under test
        (V, datetime(2000, 1, 2)),  # noqa: DTZ001 — naive is the subject under test
    ],
)
def test_naive_datetime_rejected(verified_at: datetime, as_of: datetime) -> None:
    """aware/naive mixing is the classic source of 'stale after 3 hours'."""
    with pytest.raises(ValueError):
        is_stale("terraform", verified_at, as_of)


def test_as_of_before_verified_at_is_not_stale() -> None:
    """Clock skew between CI agents is real; negative age is not expiry."""
    assert is_stale("terraform", V, V - timedelta(days=365)) is False


def test_is_stale_is_pure() -> None:
    """Same inputs, same output — no internal state, no clock."""
    args = ("terraform", V, V + timedelta(days=15))
    assert is_stale(*args) == is_stale(*args)


def test_ttl_for_returns_timedelta_or_none() -> None:
    for method in TTL:
        value = ttl_for(method)
        assert value is None or isinstance(value, timedelta)


# --- policy table ----------------------------------------------------------


def test_policy_version_is_declared() -> None:
    assert isinstance(TTL_POLICY_VERSION, int)
    assert TTL_POLICY_VERSION >= 1


def test_max_confidence_is_monotonic() -> None:
    """Trust ordering: arn >= terraform >= path >= llm. Ties are allowed."""
    assert (
        MAX_CONFIDENCE["arn"]
        >= MAX_CONFIDENCE["terraform"]
        >= MAX_CONFIDENCE["path"]
        >= MAX_CONFIDENCE["llm"]
    )


def test_llm_ceiling_is_capped() -> None:
    """LLM contribution stays <= 0.3 — documented invariant."""
    assert MAX_CONFIDENCE["llm"] <= 0.3


def test_ttl_and_confidence_cover_same_methods() -> None:
    assert set(TTL) == set(MAX_CONFIDENCE)


def test_source_bound_methods_share_one_ttl() -> None:
    """TTL models source volatility, not method trust.

    terraform, path and llm all derive from the repository tree, so they
    share a TTL. A divergence here would be trust smuggled into the
    volatility axis — the exact double-counting the contract forbids.
    """
    source_bound = ("terraform", "path", "llm")
    ttls = {ttl_for(m) for m in source_bound}
    assert len(ttls) == 1
    assert None not in ttls
