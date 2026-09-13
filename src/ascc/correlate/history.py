"""ШАГ 6: turn persisted Fact history into BridgeFact edges for this run.

See CLAUDE.md, "### ШАГ 6: store consumer (cross-run identity)". A Fact
written by ШАГ 5 carries a MatchKey's fields flat in its payload (payload_v
1, `{side}.{field}`); `str(MatchKey)` is NEVER parsed back — it is not
injectively parseable and it feeds Finding.dedup_key / the SARIF fingerprint,
a presentation format a durable on-disk format must not inherit (see
`_to_fact`, ШАГ 5). A pre-ШАГ-6 (v0) fact carries no such fields and needs
the caller's `known` map — built from this run's own resolved keys — to be
resolved at all; one that resolves to neither side is dropped as
"v0_unresolvable", not raised, so one bad historical fact never costs the
rest of the history.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Literal

from ascc.schema.identity import MatchKey
from ascc.schema.models import BridgeFact
from ascc.store import Fact

DropReason = Literal["stale", "llm", "v0_unresolvable", "malformed"]

FIELDS = ("partition", "service", "resource_type", "identifier")


def facts_to_bridge_facts(
    facts: Iterable[Fact], *, known: Mapping[str, MatchKey]
) -> tuple[list[BridgeFact], list[tuple[Fact, DropReason]]]:
    """Historical facts filtered for Union-Find, per CLAUDE.md ШАГ 6:

    stale (already stamped by repo.all(now=)) and method="llm" are excluded
    outright. Everything else is a bridge candidate, resolved either from its
    own payload (v1+) or from `known` (v0).
    """
    edges: list[BridgeFact] = []
    dropped: list[tuple[Fact, DropReason]] = []

    for fact in facts:
        if fact.stale:
            dropped.append((fact, "stale"))
            continue
        if fact.method == "llm":
            dropped.append((fact, "llm"))
            continue

        payload_v = fact.payload.get("payload_v")
        if payload_v is not None and int(payload_v) >= 1:
            left_values = [fact.payload[f"left.{field}"] for field in FIELDS]
            right_values = [fact.payload[f"right.{field}"] for field in FIELDS]
            if not all(left_values) or not all(right_values):
                dropped.append((fact, "malformed"))
                continue
            left = MatchKey(*left_values)
            right = MatchKey(*right_values)
        else:
            left_str, right_str = fact.key
            if left_str not in known or right_str not in known:
                dropped.append((fact, "v0_unresolvable"))
                continue
            left, right = known[left_str], known[right_str]

        edges.append(
            BridgeFact(
                left=left,
                right=right,
                method=fact.method,
                confidence=fact.confidence,
                source=fact.payload.get("source", ""),
                evidence=fact.payload.get("evidence", ""),
            )
        )

    return edges, dropped
