"""Нормализованная модель: Resource, Finding, ScanRun. Resource-centric — findings навешиваются на ресурс."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .identity import MatchKey, Resolution, ResourceRef
from .taxonomy import Category, Severity


@dataclass(slots=True)
class Resource:
    """Канонический ресурс. Первичная сущность (resource-centric schema)."""

    key: MatchKey
    refs: list[ResourceRef] = field(default_factory=list)
    resolutions: list[Resolution] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def resource_id(self) -> str:
        return str(self.key)

    @property
    def seen_by(self) -> set[str]:
        return {r.scanner for r in self.refs}


@dataclass(slots=True)
class Finding:
    """Сырая находка одного сканера, привязанная к одному или нескольким ресурсам."""

    scanner: str
    rule_id: str
    category: Category
    severity: Severity
    title: str
    resource_ids: list[str] = field(default_factory=list)
    resolutions: list[Resolution] = field(default_factory=list)
    cve: str | None = None
    raw: dict = field(default_factory=dict)

    @property
    def min_confidence(self) -> float:
        """Слабейшее звено привязки. correlate/ должен учитывать это при слиянии."""
        return min((r.confidence for r in self.resolutions), default=0.0)

    @property
    def dedup_key(self) -> tuple[str, ...]:
        # (resource_id, rule_id, scanner) — по README, НЕ по тексту описания
        return tuple(sorted(self.resource_ids)) + (self.rule_id, self.scanner)


@dataclass(slots=True)
class ScanRun:
    scanner: str
    started_at: datetime
    findings: list[Finding] = field(default_factory=list)
    resources: dict[str, Resource] = field(default_factory=dict)
