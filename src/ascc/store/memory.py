"""InMemoryFactRepository: the reference FactRepository implementation.

Keeps facts in a plain dict, keyed by Fact.key. No I/O, no clock: the caller
supplies `now` on every call (see CLAUDE.md, "Store"). Overwrite-by-key and
append-and-last-wins are observationally equivalent through the ABC, so this
implementation shares its conformance suite with Jsonl.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from .policy import MAX_CONFIDENCE, is_stale
from .repository import FactRepository

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

    from .models import Fact


class InMemoryFactRepository(FactRepository):
    """Facts held in a dict for the lifetime of the process."""

    def __init__(self) -> None:
        self._facts: dict[tuple[str, ...], Fact] = {}

    def put(self, fact: Fact, *, now: datetime) -> None:
        if fact.method not in MAX_CONFIDENCE:
            raise KeyError(fact.method)
        if fact.confidence > MAX_CONFIDENCE[fact.method]:
            msg = f"confidence {fact.confidence} exceeds ceiling for method {fact.method!r}"
            raise ValueError(msg)
        if fact.observed_at > now:
            msg = f"observed_at {fact.observed_at} is in the future relative to now={now}"
            raise ValueError(msg)

        self._facts[fact.key] = fact

    def get(self, key: tuple[str, ...], *, now: datetime) -> Fact | None:
        fact = self._facts.get(key)
        if fact is None:
            return None
        return self._render(fact, now=now)

    def all(self, *, now: datetime) -> Iterable[Fact]:
        return [self._render(fact, now=now) for fact in self._facts.values()]

    @staticmethod
    def _render(fact: Fact, *, now: datetime) -> Fact:
        stale = is_stale(fact.method, fact.observed_at, now)
        return replace(fact, stale=stale)
