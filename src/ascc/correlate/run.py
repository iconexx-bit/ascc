from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ascc.schema.identity import MatchKey
from ascc.schema.models import Finding, Resource, ScanRun

from .bridge import ResourceCluster, build_clusters


@dataclass(frozen=True, slots=True)
class TagConflict:
    """Два сканера дали разное значение одного тега на одном ресурсе.

    Не ошибка данных — расхождение между IaC и живым облаком само по
    себе находка (см. CLAUDE.md, "Disagreement is data, not an error").
    """

    resource_key: MatchKey
    tag_key: str
    values: tuple[tuple[str, str], ...]  # (source_scanner, value), отсортировано


@dataclass(frozen=True, slots=True)
class CorrelationRun:
    """Результат корреляции. Ничего не вычисляет и не мутирует ScanRun —
    вся сборка в correlate()."""

    scan_runs: tuple[ScanRun, ...]
    resources: dict[str, Resource]
    clusters: tuple[ResourceCluster, ...]
    tag_conflicts: tuple[TagConflict, ...]


def correlate(runs: Iterable[ScanRun]) -> CorrelationRun:
    scan_runs = tuple(runs)
    all_facts = [fact for run in scan_runs for fact in run.bridge_facts]
    clusters = tuple(build_clusters(all_facts))
    resources, tag_conflicts = _merge_resources(scan_runs)
    return CorrelationRun(
        scan_runs=scan_runs,
        resources=resources,
        clusters=clusters,
        tag_conflicts=tag_conflicts,
    )


def _merge_resources(
    runs: tuple[ScanRun, ...],
) -> tuple[dict[str, Resource], tuple[TagConflict, ...]]:
    merged: dict[str, Resource] = {}
    tag_sources: dict[str, dict[str, list[tuple[str, str, float]]]] = {}

    for run in runs:
        for key_str, resource in run.resources.items():
            existing = merged.get(key_str)
            if existing is None:
                merged[key_str] = Resource(
                    key=resource.key,
                    refs=list(resource.refs),
                    resolutions=list(resource.resolutions),
                )
            else:
                existing.refs.extend(resource.refs)
                existing.resolutions.extend(resource.resolutions)

            if resource.tags:
                confidence = max((r.confidence for r in resource.resolutions), default=0.0)
                per_key = tag_sources.setdefault(key_str, {})
                for tag_key, value in resource.tags.items():
                    per_key.setdefault(tag_key, []).append((run.scanner, value, confidence))

    conflicts: list[TagConflict] = []
    for key_str, per_key in tag_sources.items():
        resource = merged[key_str]
        for tag_key, sources in per_key.items():
            distinct_values = {value for _, value, _ in sources}
            if len(distinct_values) == 1:
                resource.tags[tag_key] = next(iter(distinct_values))
                continue
            _, winner_value, _ = min(sources, key=lambda s: (-s[2], s[1]))
            resource.tags[tag_key] = winner_value
            conflicts.append(
                TagConflict(
                    resource_key=resource.key,
                    tag_key=tag_key,
                    values=tuple(sorted((scanner, value) for scanner, value, _ in sources)),
                )
            )

    return merged, tuple(conflicts)


def effective_confidence(
    finding: Finding, resource_key: MatchKey, run: CorrelationRun
) -> float | None:
    """Единственное место, где инвариант композиции confidence (CLAUDE.md,
    "Invariant: confidence composes") становится кодом.

    Композиция — ПРОИЗВЕДЕНИЕ, не среднее (геометрическое или любое другое).
    Причина: resolution.confidence и bridge_confidence — не независимые
    оценки одной и той же величины (для этого годилось бы среднее), а
    последовательные звенья цепи вывода: bridge_confidence имеет смысл
    ТОЛЬКО если верен resolution, на котором он строится. Это логическое
    И по независимым событиям, и его композиция — произведение.

    Следствие, ради которого это важно: произведение строго убывает
    с длиной цепи (0.9^5 = 0.59), корректно сигнализируя о накоплении
    неопределённости при удлинении вывода. Среднее с этим свойством не
    обладает (среднее пяти значений 0.9 — всё ещё 0.9) и потому НЕ
    годится, даже если path() когда-нибудь заменит direct_confidence
    на многозвенные цепочки.

    Кандидат собирается по КАЖДОМУ resolution находки независимо;
    побеждает максимум, а не первый по порядку — порядок resolutions
    зависит от обхода парсера и произволен, а утверждение о ресурсе
    настолько уверенно, насколько уверен лучший (а не первый попавшийся)
    путь к нему. Резолвы, для которых нет ни K==T, ни прямого факта
    K<->T в общем кластере, кандидата не дают и пропускаются — не
    обрывают перебор остальных resolutions.
    """
    candidates: list[float] = []
    for resolution in finding.resolutions:
        k = resolution.key
        if k == resource_key:
            candidates.append(resolution.confidence)
            continue
        cluster = next((c for c in run.clusters if k in c.keys), None)
        if cluster is None or resource_key not in cluster.keys:
            continue
        bridge_confidence = cluster.direct_confidence(k, resource_key)
        if bridge_confidence is None:
            continue
        candidates.append(resolution.confidence * bridge_confidence)
    return max(candidates) if candidates else None
