"""Fact: an immutable record of a single observation, carrying TTL provenance."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class Fact:
    """A single fact held by a FactRepository.

    `key` is a variable-length dedup_key (see Finding.dedup_key in
    schema/models.py); the store knows nothing about where it came from.
    `stale` is the TTL flag: expiry marks a fact as stale but never deletes
    it, so provenance is preserved (see CLAUDE.md, "Store").
    """

    key: tuple[str, ...]
    method: str
    confidence: float
    observed_at: datetime
    stale: bool = False
    payload: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
