"""Freshness policy (v1): TTL and confidence ceilings, keyed by method.

TTL models source volatility, not method trust and not recomputation cost.
Trust lives in confidence (see MAX_CONFIDENCE). The two axes are independent:
double-counting — letting TTL vary with a method's trust — is forbidden.

Method literals and confidence ceilings are ground truth from
src/ascc/schema/identity.py (arn_parse, terraform_*, filesystem_path_heuristic)
and src/ascc/ingest/prowler.py (observed_together). "llm" is a forward
contract: no producer exists yet, capped at 0.3 per the documented invariant.

Pure, stdlib-only. No imports from anywhere else in ascc.
"""

from __future__ import annotations

from datetime import datetime, timedelta

TTL_POLICY_VERSION: int = 1

_THIRTY_DAYS = timedelta(days=30)
_SEVEN_DAYS = timedelta(days=7)

# Three volatility classes, three TTL values:
#   immutable    -- never expires (arn_parse compares strings; strings don't age)
#   source_bound -- tied to the repository tree; superseded by a file edit
#   run_bound    -- tied to a scanner run artefact; superseded by the next scan,
#                   which happens sooner than a file edit, hence the shorter TTL
TTL: dict[str, timedelta | None] = {
    "arn_parse": None,
    "terraform_natural_name": _THIRTY_DAYS,
    "terraform_generated_id_unbridged": _THIRTY_DAYS,
    "filesystem_path_heuristic": _THIRTY_DAYS,
    "observed_together": _SEVEN_DAYS,
    "llm": _THIRTY_DAYS,
}

MAX_CONFIDENCE: dict[str, float] = {
    "arn_parse": 1.0,
    "terraform_natural_name": 1.0,
    "terraform_generated_id_unbridged": 0.4,
    "filesystem_path_heuristic": 0.5,
    "observed_together": 0.95,
    "llm": 0.3,
}


def ttl_for(method: str) -> timedelta | None:
    """Return the TTL for `method`, or None if the method never expires.

    Raises KeyError for a method with no policy entry.
    """
    return TTL[method]


def is_stale(method: str, observed_at: datetime, as_of: datetime) -> bool:
    """Whether a fact observed at `observed_at` is stale as of `as_of`.

    Pure and primitive-only: no dataclasses, no I/O, the caller supplies both
    timestamps. Raises KeyError for an unknown method and ValueError if either
    timestamp is naive (no tzinfo). Boundary is >=: a fact is stale exactly at
    its TTL, not only after it. `as_of` before `observed_at` is clock skew, not
    expiry, and falls out of the age computation with no special branch.
    """
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        msg = "observed_at must be an aware datetime"
        raise ValueError(msg)
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        msg = "as_of must be an aware datetime"
        raise ValueError(msg)

    ttl = ttl_for(method)
    if ttl is None:
        return False

    age = as_of - observed_at
    return age >= ttl
