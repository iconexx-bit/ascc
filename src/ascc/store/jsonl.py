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
FORMAT_VERSION = 1


class StoreFormatError(ValueError):
    """The store file holds a line this version cannot read: a record in another
    format version, or a corrupt line that is not the trailing one."""


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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
        # Directories this put creates, deepest first; each needs its parent
        # fsynced for the new entry to survive power loss (CLAUDE.md).
        created = []
        probe = self._directory
        while not probe.exists():
            created.append(probe)
            probe = probe.parent
        self._directory.mkdir(parents=True, exist_ok=True)
        path = self._path()
        new_file = not path.exists()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        if new_file:
            _fsync_dir(self._directory)
            for directory in created:
                _fsync_dir(directory.parent)

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
        line of an append-only file can tear mid-write. Any other unreadable
        line, and any record in another format version, raises
        StoreFormatError: misreading it as v1 would be silent corruption.
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
            except json.JSONDecodeError as exc:
                if i == len(lines) - 1:
                    continue
                msg = f"{self._path()}: line {i + 1} is not valid JSON"
                raise StoreFormatError(msg) from exc
            if not isinstance(record, dict):
                msg = f"{self._path()}: line {i + 1} is not a JSON object"
                raise StoreFormatError(msg)
            # An absent "v" reads as v1 (operator decision 2026-10-25). The
            # type check matters: True == 1 and "1" would otherwise slip by.
            version = record.get("v", FORMAT_VERSION)
            if type(version) is not int or version != FORMAT_VERSION:
                msg = (
                    f"{self._path()}: line {i + 1} has format version {version!r}; "
                    f"this ascc reads version {FORMAT_VERSION}"
                )
                raise StoreFormatError(msg)
            fact = self._from_record(record)
            facts[fact.key] = fact
        return facts

    @staticmethod
    def _to_record(fact: Fact) -> dict[str, object]:
        # Explicit field mapping, never dataclasses.asdict(): asdict would
        # bind the on-disk format to Python field names. `stale` is rendered
        # at read time and is deliberately absent here.
        return {
            "v": FORMAT_VERSION,
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
