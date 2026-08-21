# Delegation log

Одна строка на делегированную агенту задачу. Спека (`task.md`) не версионируется —
здесь фиксируется только факт, скоуп и результат.

| Дата | Скоуп | Результат (commit) | Verdict |
|---|---|---|---|

| 2026-08-19 | append missing decisions to CLAUDE.md (Contracts/Determinism/Scoring/Store/K8s) | — | pending |

| 2026-08-21 | jsonschema + SARIF schema landed inside 8abfab4, outside the
20.08 rc cut. Not reverted — the same commit carries the severity mapping
and the dev-deps consolidation fix. Schema-validation test stays deferred
to 0.1.1. Lesson: check branch history for prior scope decisions before
proposing scope.