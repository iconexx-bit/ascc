"""Red tests for ascc.store.policy — TTL & confidence policy contract.

Scope: the pure policy layer only. No repository, no I/O, no clock.

Method literals and confidence values are ground truth, read from:
  src/ascc/schema/identity.py  (arn_parse, terraform_*, filesystem_path_heuristic)
  src/ascc/ingest/prowler.py   (observed_together)
"llm" is a forward contract: no producer exists yet.

Every date is year-2000: an implementation that reaches for datetime.now()
internally fails test_fresh_before_ttl deterministically, not 99.9% of the time.
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

SOURCE_BOUND = (
    "terraform_natural_name",
    "terraform_generated_id_unbridged",
    "filesystem_path_heuristic",
    "llm",
)
RESOLUTION_METHODS = (
    "arn_parse",
    "terraform_natural_name",
    "filesystem_path_heuristic",
    "terraform_generated_id_unbridged",
)


# --- boundary --------------------------------------------------------------


def test_fresh_before_ttl() -> None:
    """Hidden-clock detector: a year-2000 fact one day old is fresh."""
    assert is_stale("terraform_natural_name", V, V + DAY) is False


def test_stale_exactly_at_ttl() -> None:
    """Boundary is >=: at exactly ttl the fact is already stale."""
    assert is_stale("terraform_natural_name", V, V + timedelta(days=30)) is True


def test_stale_after_ttl() -> None:
    assert is_stale("terraform_natural_name", V, V + timedelta(days=31)) is True


def test_never_stale_when_ttl_is_none() -> None:
    """arn_parse compares strings; string comparison does not age."""
    assert is_stale("arn_parse", V, V + timedelta(days=36500)) is False


# --- contracts -------------------------------------------------------------


def test_unknown_method_raises() -> None:
    """Fail loud: a new method without a policy entry is a bug, not a default."""
    with pytest.raises(KeyError):
        is_stale("kubernetes_owner_ref", V, V + DAY)


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
        is_stale("terraform_natural_name", verified_at, as_of)


def test_as_of_before_verified_at_is_not_stale() -> None:
    """Clock skew between CI agents is real; negative age is not expiry."""
    assert is_stale("terraform_natural_name", V, V - timedelta(days=365)) is False


def test_is_stale_is_pure() -> None:
    """Same inputs, same output — no internal state, no clock."""
    args = ("terraform_natural_name", V, V + timedelta(days=15))
    assert is_stale(*args) == is_stale(*args)


def test_ttl_for_returns_timedelta_or_none() -> None:
    for method in TTL:
        value = ttl_for(method)
        assert value is None or isinstance(value, timedelta)


# --- policy table ----------------------------------------------------------


def test_policy_version_is_declared() -> None:
    assert isinstance(TTL_POLICY_VERSION, int)
    assert TTL_POLICY_VERSION >= 1


def test_ttl_and_confidence_cover_same_methods() -> None:
    assert set(TTL) == set(MAX_CONFIDENCE)


def test_every_known_method_has_a_policy() -> None:
    """Ground truth from grep over src/ascc/. A sixth producer must land here."""
    known = {*RESOLUTION_METHODS, "observed_together", "llm"}
    assert known <= set(TTL)


def test_max_confidence_matches_resolution_tiers() -> None:
    """Mirrors src/ascc/schema/identity.py — drift here is a real defect."""
    assert MAX_CONFIDENCE["arn_parse"] == 1.0
    assert MAX_CONFIDENCE["terraform_natural_name"] == 1.0
    assert MAX_CONFIDENCE["filesystem_path_heuristic"] == 0.5
    assert MAX_CONFIDENCE["terraform_generated_id_unbridged"] == 0.4


def test_max_confidence_matches_bridge_tier() -> None:
    """Mirrors src/ascc/ingest/prowler.py — the only BridgeFact producer."""
    assert MAX_CONFIDENCE["observed_together"] == 0.95


def test_resolution_confidence_is_monotonic() -> None:
    """Trust ordering holds WITHIN resolution methods.

    observed_together (0.95) is a BridgeFact confidence — a different factor in
    effective_confidence (run.py: resolution.confidence * bridge_confidence).
    Comparing the two populations would be meaningless.
    """
    assert (
        MAX_CONFIDENCE["arn_parse"]
        == MAX_CONFIDENCE["terraform_natural_name"]
        >= MAX_CONFIDENCE["filesystem_path_heuristic"]
        >= MAX_CONFIDENCE["terraform_generated_id_unbridged"]
    )


def test_llm_ceiling_is_capped() -> None:
    """LLM contribution stays <= 0.3 — documented invariant."""
    assert MAX_CONFIDENCE["llm"] <= 0.3


# --- volatility axis -------------------------------------------------------


def test_source_bound_methods_share_one_ttl() -> None:
    """TTL models source volatility, not method trust.

    All four derive from the repository tree, so they share a TTL despite
    confidences of 1.0, 0.5, 0.4 and 0.3. A divergence here would be trust
    smuggled into the volatility axis — the double-counting the contract forbids.
    """
    ttls = {ttl_for(m) for m in SOURCE_BOUND}
    assert len(ttls) == 1
    assert None not in ttls


def test_run_bound_ttl_is_shorter_than_source_bound() -> None:
    """observed_together derives from a scanner run artefact, not the repo tree.

    A new scan supersedes it sooner than a file edit would. This is an argument
    about how fast the source changes — its confidence (0.95) is high.
    """
    run_bound = ttl_for("observed_together")
    assert run_bound is not None
    assert run_bound < ttl_for("terraform_natural_name")
