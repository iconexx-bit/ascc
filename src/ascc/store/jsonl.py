"""JsonlFactRepository: durable FactRepository backed by one append-only file.

One JSON object per line, LF-terminated; for a given key the last line wins
on read (see CLAUDE.md, "### JsonlFactRepository"). Validation mirrors
InMemoryFactRepository.put() so the two implementations reject the same
facts the same way — the shared conformance suite (tests/store/) depends on
that agreement. `now` is injected by the caller on every call; this module
never reads the clock (see CLAUDE.md, "Store").
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING

from .models import Fact
from .policy import MAX_CONFIDENCE, is_stale
from .repository import FactRepository

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

_FILENAME = "facts.jsonl"


class JsonlFactRepository(FactRepository):
    """Facts appended as JSON lines under a directory, one file per repository.

    Construction has no filesystem effects; the directory (and the file in
    it) is created on the first `put`. The file name is an implementation
    detail — no caller spells it.
    """

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def put(self, fact: Fact, *, now: datetime) -> None:
        # Same checks, same order, same exceptions as InMemoryFactRepository.put
        # — including relying on `>` to raise TypeError for a naive `now`
        # rather than checking tzinfo explicitly (see CLAUDE.md Backlog).
        if fact.method not in MAX_CONFIDENCE:
            raise KeyError(fact.method)
        if fact.confidence > MAX_CONFIDENCE[fact.method]:
            msg = f"confidence {fact.confidence} exceeds ceiling for method {fact.method!r}"
            raise ValueError(msg)
        if fact.observed_at > now:
            msg = f"observed_at {fact.observed_at} is in the future relative to now={now}"
            raise ValueError(msg)

        line = json.dumps(
            self._to_record(fact), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        self._directory.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def get(self, key: tuple[str, ...], *, now: datetime) -> Fact | None:
        fact = self._load().get(key)
        if fact is None:
            return None
        return replace(fact, stale=is_stale(fact.method, fact.observed_at, now))

    def all(self, *, now: datetime) -> Iterable[Fact]:
        return [
            replace(fact, stale=is_stale(fact.method, fact.observed_at, now))
            for fact in self._load().values()
        ]

    def _path(self) -> Path:
        return self._directory / _FILENAME

    def _load(self) -> dict[tuple[str, ...], Fact]:
        """Read every line, collapsing duplicate keys — last line wins.

        A read must not write: this only ever opens the file for reading.
        A truncated trailing line is skipped, not raised — only the last
        line of an append-only file can tear mid-write.
        """
        try:
            text = self._path().read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}

        lines = text.splitlines()
        facts: dict[tuple[str, ...], Fact] = {}
        for i, line in enumerate(lines):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                if i == len(lines) - 1:
                    continue
                raise
            fact = self._from_record(record)
            facts[fact.key] = fact
        return facts

    @staticmethod
    def _to_record(fact: Fact) -> dict[str, object]:
        # Explicit field mapping, never dataclasses.asdict(): asdict would
        # bind the on-disk format to Python field names. `stale` is rendered
        # at read time and is deliberately absent here.
        return {
            "v": 1,
            "key": list(fact.key),
            "method": fact.method,
            "confidence": fact.confidence,
            "observed_at": fact.observed_at.isoformat(),
            "payload": dict(fact.payload),
        }

    @staticmethod
    def _from_record(record: dict[str, object]) -> Fact:
        return Fact(
            key=tuple(record["key"]),
            method=record["method"],
            confidence=record["confidence"],
            observed_at=datetime.fromisoformat(record["observed_at"]),
            payload=MappingProxyType(dict(record["payload"])),
        )
