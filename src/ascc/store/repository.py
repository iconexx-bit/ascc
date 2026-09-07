"""FactRepository: the persistence boundary. The correlate/ core stores no facts
and knows no database — facts reach it already read through this boundary
(see CLAUDE.md, "Architecture")."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import datetime

from .models import Fact


class FactRepository(ABC):
    """Abstract repository of facts. `now` is injected by the caller into every
    method — the repository never reads the clock itself (see CLAUDE.md, "Store")."""

    @abstractmethod
    def put(self, fact: Fact, *, now: datetime) -> None:
        """Store a fact.

        TTL contract: expiry marks the fact stale=True and never deletes the
        record — provenance is preserved.
        """

    @abstractmethod
    def get(self, key: tuple[str, ...], *, now: datetime) -> Fact | None:
        """Read a fact by key, or None if the key is absent.

        TTL contract: expiry marks the fact stale=True and never deletes the
        record — provenance is preserved.
        """

    @abstractmethod
    def all(self, *, now: datetime) -> Iterable[Fact]:
        """Read every fact in the repository.

        TTL contract: expiry marks the fact stale=True and never deletes the
        record — provenance is preserved.
        """
