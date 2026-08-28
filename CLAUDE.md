# ASCC — AI Security Command Center

## Что это

Корреляционно-рассуждающий слой поверх сканеров облачной инфраструктуры.
НЕ сканер. Не пиши код, обращающийся к облачным API напрямую —
входные данные всегда приходят из внешних инструментов.

Вход:  Trivy, Prowler, Checkov (нативные JSON-выводы)
Выход: SARIF — только как export target, не как внутренняя модель

## Пайплайн и карта модулей

Слои: schema/ (словарь, общий для всех стадий), store/ (персистентность)
Стадии: ingest -> correlate -> score -> export

- src/ascc/cli.py       — точка входа
- src/ascc/ingest/      — парсеры сканеров, по модулю на сканер, общий интерфейс.
  base.py, registry.py, trivy.py, checkov.py, prowler.py — реализованы
- src/ascc/schema/      — нормализованная модель: Resource, Finding, связи.
  models.py, identity.py, taxonomy.py — реализованы
- src/ascc/correlate/   — ядро корреляции и рассуждения, суть проекта.
  bridge.py, run.py — реализованы
- src/ascc/store/       — персистентность фактов. ПУСТО, см. «Архитектура»
- src/ascc/export/      — рендер в SARIF. ПУСТО
- tests/                — pytest, зеркалит модули: test_trivy.py, test_prowler.py,
  test_checkov.py, test_registry.py, test_identity.py, test_bridge.py,
  test_bridge_gap.py, test_correlate.py, test_correlate_confidence.py,
  test_cli.py, conftest.py

Порядок реализации: schema -> ingest -> correlate. store/ и export/ — post-v0.1.
См. раздел «Архитектура» ниже: correlate реализован раньше store намеренно.

## Архитектура

Слои (общие для всех стадий):

- schema/  — нормализованная модель. Словарь, на котором говорят все стадии.
- store/   — персистентность. Repository на границах; ядро correlate чистое.

Поток данных (v0.1):
  ingest -> correlate -> score -> export

Поток данных (v1, с персистентностью):
  ingest -> store.save -> store.load -> correlate -> store.save -> export

Rationale: correlate реализован раньше store намеренно. v0.1 корреллирует
внутри одного прогона и персистентности не требует. store/ появляется тогда,
когда потребуется кросс-прогонная корреляция: BridgeFact, наблюдённый Prowler
в понедельник, поднимает confidence находки Trivy в пятницу с 0.4 до 1.0.
store/ — не технический долг, а следующая функциональная возможность.

Инвариант: correlate/ не выполняет запросов к БД. Он принимает факты и
возвращает кластеры. Источник фактов ему неизвестен.

## Тестовые данные

fixtures/leaky_data_lake/ — эталонный сценарий:

- trivy.json, prowler.json, checkov.json — сырые выводы трёх сканеров
- README.md — описание сценария, читай его перед работой с фикстурами

Фикстуры лежат в корне, не в tests/fixtures/ — tests/ их читает, но не владеет ими.

## Архитектурные решения — приняты, не пересматривать

- Схема: resource-centric normalized — ресурс первичен, findings навешиваются на него
- Хранилище: JSONL (v0.1) -> PostgreSQL + pgvector (когда упрёмся в объём
  или понадобится семантический поиск).
  Пересмотрено 2026-08-08. Rationale: доступ к фактам изолирован за
  FactRepository, поэтому выбор бэкенда — замена драйвера, а не
  архитектурное решение. Если кросс-прогонная корреляция не работает
  на JSONL, она не заработает и на Postgres.
- SARIF: исключительно на экспорт; внутри — собственная нормализованная модель

## Invariant: canonical execution path

All commands that run project code go through `uv run`.

- `uv run pytest`, `uv run ruff check src/`, `uv run ascc correlate --input DIR`
- `uv run` syncs the environment against `uv.lock` before execution.
  A bare `pytest` does not — it runs whatever `.venv` happens to contain.

Direct `.venv/bin/*` invocation is permitted ONLY for interactive debugging
(`.venv/bin/python -c ...`). It must never appear in README, CI, tests,
Makefile, or any documented step.

Rationale: CI executes via `uv`. If a local command can succeed on a `.venv`
that has drifted from `uv.lock`, local green and CI red diverge silently.
The failure surfaces minutes later in CI instead of immediately.

Note: the VS Code Python extension auto-activates `.venv` in every integrated
terminal (`python.terminal.activateEnvironment`, default `true`). This makes a
bare `pytest` *work*, which is exactly what makes it dangerous. Convenience,
not contract.

## Invariant: TZ convention for day-boundary decisions

`TZ='America/New_York' date` is the source of truth for any day-boundary
decision — "today's scope" in a task, tooling-freeze/deadline dates,
"commit tomorrow" style plans.

Bare `date` / `date -u` are permitted ONLY for timestamps embedded in
artifacts (logs, SARIF output, commit metadata) — never to decide what day
it is for planning purposes.

Rationale: a bare date carries no timezone and no time-of-day. Near a day
boundary that ambiguity is exactly what breaks "today vs tomorrow"
reasoning — a plan dated by the wrong day silently ships on the wrong day.
Anchoring day-boundary decisions to one named TZ makes "today" a
reproducible fact instead of whatever the local system clock or an
upstream date field happens to report.

## Инварианты

- `MatchKey.__str__` is a stability contract: it feeds `dedup_key` and SARIF
  `partialFingerprints`. Changing the format or field set invalidates every
  published fingerprint. New fields go to `Resolution`, never to `MatchKey`.
- Finding может ссылаться на несколько ресурсов — связь many-to-many
- Дедупликация по ключу (resource_id, rule_id, scanner), НЕ по тексту описания
- Парсер каждого сканера — отдельный модуль в ingest/ с общим интерфейсом;
  correlate/ и schema/ о конкретных сканерах не знают
- Матчинг по имени сущности не равен обнаружению сущности:
  детект по паттерну значения, не по упоминанию имени
- Resource.refs — счётчик наблюдений, дубликаты ожидаемы.
  Resource.resolutions может содержать идентичные записи; дедупликация
  объяснений — задача correlate/, не ingest/.
- Сканер определяется по структуре документа, а не по имени файла:
  parse_this.json и trivy-2024-01.json равноправны, решает sniff().
- Отсутствующее наблюдение — это None, а не суррогат. Сканер, не
  сообщивший время скана, не получает epoch или now(): подделка
  выглядит как данные и переживёт того, кто её вставил.
- SARIF `level` mapping (SARIF allows only none|note|warning|error):
  CRITICAL→error/9.5, HIGH→error/8.0, MEDIUM→warning/5.5,
  LOW→note/3.0, INFO→none/0.0. The numeric is
  `rule.properties.security-severity`, read by GitHub Code Scanning —
  without it CRITICAL and HIGH are indistinguishable.
  - SARIF `ruleId` = `{scanner}/{rule_id}` (e.g. `trivy/CVE-2021-44228`).
  - Scanner-namespaced because scanners do not guarantee uniqueness among
  themselves. No `ASCC-` prefix: the rule belongs to the scanner, not to
  ASCC — tool identity lives in `tool.driver.name`. Format is a published
  contract; changing it is breaking.

## Окружение и команды

Пакетный менеджер — uv. Виртуальное окружение: .venv в корне.

    uv sync                       # установка зависимостей
    uv run pytest -q              # тесты
    uv run ruff check src/        # линт
    uv run python -m ascc.cli     # запуск CLI

Makefile отсутствует — команд make не существует, не предлагай их.

## Стиль работы

- Python, type hints обязательны
- Изменения схемы БД — только через миграции, никаких ручных ALTER
- Перед реализацией нового подпакета — сначала план текстом, потом код
- Новые зависимости — только после явного согласования
- Вывод тестов и логов сокращай (-q, | tail -30), не тащи простыни в контекст
- Утверждения о структуре проекта (какие модули пустые/реализованы, что где
  лежит) подтверждаются find по факту, а не памятью или прошлой версией
  CLAUDE.md — документация устаревает, дерево каталогов нет

## Чего НЕ делать

- Не расширять scope до "добавим ещё один сканер" — это убивает дифференциацию
- Не хардкодить маппинги правил конкретного сканера в correlate/ или schema/
- Не трогать .venv/, .git/, **pycache**/ и содержимое fixtures/ без явной просьбы

## Тесты

- Один тест — одно утверждение. Объединённый assert-блок при падении
  покажет первый и остановится, остальное скроется.
- Тесты, фиксирующие ОГРАНИЧЕНИЯ (невозможность схлопнуть generated-id),
  обязаны иметь докстринг с объяснением. Иначе их однажды "починят".
- После правки schema/identity.py прогонять мутацию: подменить значение
  confidence и убедиться, что нужные тесты краснеют. Зелёный тест,
  не умеющий краснеть, — не тест.
- Не правь код, чтобы тест позеленел, не разобравшись. Красный тест
  может быть прав.

## Как формулировать задачи

- Указывай файлы через @path, не заставляй сканировать репозиторий:
  разведка стоит столько же токенов, сколько работа.
- ТЗ длиннее 40 строк класть в task.md и ссылаться @task.md —
  длинные вставки в поле ввода обрезаются.

## Identity bridging: cluster model

When two scanners produce different keys for the same real resource, ASCC
does **not** merge them. Neither `Resource` is modified, renamed, or absorbed.

Instead a `ResourceCluster` records:

- the set of keys believed to denote one resource
- the bridge facts that justify that belief, each with method, confidence
  and the observation it came from

Rationale: ingest is a protocol of what scanners observed. Merging rewrites
that protocol and makes "why did you decide these are one resource"
unanswerable. Bridging is data, not mutation — it can be recomputed,
versioned, or switched off without touching ingest output.

Rejected alternatives:

- **merge**: destroys the losing key; a later scan producing it has nowhere to land; irreversible if the bridge was wrong
- **alias**: keeps keys but forces an arbitrary "canonical" choice, and the
  justification ends up scattered across pointers

### Invariant: confidence composes, never replaces

A claim that travels over a bridge is the product of every link it crosses:

    effective = resolution.confidence * PRODUCT(bridge.confidence)

Example: a Trivy CVE bound to `aws:ec2:instance:datalake-etl` by path
heuristic (0.5), bridged to `i-0a1b2c3d4e5f67890` (0.95), is a 0.475 claim
about that instance — not a 0.95 one. Bridge confidence describes the bridge,
not the ground it connects. A chain is never stronger than its weakest link.

### fixtures/ lives at repo root, deliberately

These are project demo data, not test artifacts. Tests read them; they do
not own them. `ascc correlate --input fixtures/leaky_data_lake/` is the
documented entry point.

### Cluster representative is derived, never stored

A cluster has no canonical key. When one label is needed for display or
export, it is computed:

    representative(cluster) = max(keys, key=lambda k: (max_confidence(k), k))

Highest-confidence key wins; ties break lexicographically. Deterministic,
reproducible, and costs nothing in the schema — the rule can change
tomorrow without rewriting data.

### Transitivity: direct facts only

Clusters are connected components over observed bridge facts. Membership
is transitive; **confidence is not**.

If A↔B and B↔C were each observed, A and C belong to the same cluster, but
ASCC declares no confidence for the pair A↔C. No scanner ever saw them
together. Reporting a computed 0.9 for A↔C would be a silent merge in two
steps — exactly what this project exists to prevent.

Instead the report states the path: A→B (0.95, observed_together),
B→C (0.95, observed_together). The reader judges the chain.

Two people each confidently know an Ivanov. It does not follow that they
know the same Ivanov.

### Disagreement is data, not an error

Disagreement between scanners is data, not an error. When two
scanners report different values for the same tag, correlate()
picks a deterministic winner for display and records the
disagreement in tag_conflicts. Drift between IaC and live cloud
is exactly what this layer exists to surface — crashing on it
would throw away the finding.

## Backlog

<!-- one-liners only; no code until v0.1.0-rc tag (2026-08-21) -->

- `_record_resource` дублируется в трёх парсерах. Поднять в
  ScannerParser отдельным рефакторингом — не смешивать с добавлением
  сканера.
- SARIF-ingest: universal parser (SARIF as **input**) — cheap coverage for Semgrep/CodeQL; distinct from test-only normalizer
- Neo4j export: Alias→CanonicalResource schema + constraints (see research w33); post-store only
- Graph DB (Neo4j/Memgraph) evaluation — strictly after store/ layer, JSONL-first stands
- MERGE batch-ingest playbook: UNWIND 500–2000/tx, dedupe pre-DB, nodes-before-edges, no index on last_seen
- Prompt-injection hardening (vector A): delimit scanner-controlled strings in LLM prompts (XML tags + data-not-commands instruction)
- ASCC-META-INJECTION rule: ingest-time detection of CL4R1T4S patterns inside findings — findings-scanning-findings, unique feature
- Test: injection in resource tags/names CANNOT alter severity/confidence/identity (only message.markdown reachable)
- CLAUDE.md: document vectors A (ASCC eats untrusted findings) vs B (guards module detects injection in traffic) as separate threat models
- range-dns healthcheck: nslookup A vs dnsmasq AAAA — cosmetic, documented
- agg for asciinema→GIF (cargo install --locked agg, or asciinema upload)
- deny-pattern "Edit(./fixtures/**)" in .claude/settings.json not anchored to root, incidentally blocks tests/fixtures/ too — audit/anchor post-rc
- audit stray pip/uv installs bypassing lockfile — venv drifted to 66 extra packages (llama-index stack) outside uv.lock on 18.08, caught by deps-check pre-commit hook before merge
- identity: `MatchKey.__str__` is not injectively parseable (unescaped ':') — opaque-key-only contract
- deps: pyproject had two parallel dev mechanisms (optional-dependencies + dependency-groups); `pre-commit` was never installed by `just`. Consolidated to extras; evaluate PEP 735 migration post-rc.
- docs: delegation-log table delimiter row violates MD060; align when markdownlint lands in CI
- docs: add docs/prompts/working-agreement.md (workflow contract + operating rules); mirror to userPreferences
- docs: code for the editor is given bare, never wrapped in a shell heredoc; long terminal output goes through a file
- release: tags are created on ai-sec-ubuntu (UTC); dates are never backdated
- tests: extend leaky_data_lake fixture with LOW/INFO findings (golden covers only error/warning)
- tooling: `just determinism` recipe wrapping the seed matrix
- README markdownlint cleanup — 26 warnings (MD060, MD040, MD022), after tag
- README Status/Roadmap sync rule: schema validation moves to Status on v0.1.1
- tests: synthetic.sarif.json uses legacy ruleId form ASCC-CHAIN-003; contract is {scanner}/{rule_id}
- export: to_sarif() emits no confidence in properties — verify against Roadmap intent before v0.1.1
- tests: v0.1.1 schema validation must use committed tests/schemas/ copy, never the remote $schema URL (no egress on ai-sec-ubuntu)

## Operating rules

- Release provenance: tags are created on ai-sec-ubuntu (UTC). Dates are never backdated
- just: every recipe line is a separate shell. Early `exit` aborts only that line — join with `; \` when short-circuiting.

- Regex over diff lines (`^-[^-]`) is blind to deleted blank lines and markdown bullets. Use `git diff --numstat` column 2 as ground truth for deletions.

2026-08-21: jsonschema + SARIF schema landed inside 8abfab4, outside the
20.08 rc cut. Not reverted — the same commit carries the severity mapping
and the dev-deps consolidation fix. Schema-validation test stays deferred
to 0.1.1. Lesson: check branch history for prior scope decisions before
proposing scope.

## Status

TOOLING FREEZE until v0.1.0-rc is tagged.
New tooling ideas go to ## BACKLOG as one-liners, not code.
Exception: CI-blocking failures only.
rc scope (cut 2026-08-20): v0.1.0-rc ships to_sarif() + --output + determinism test.
SARIF schema-validation and live-golden regeneration deferred to 0.1.1.

## Contracts

- ExitCode(IntEnum): OK=0, FINDINGS=1 (reserved --fail-on), USAGE=2, NO_INPUT=3, INTERNAL=70.
- CLI: `--store` is orthogonal to `--input`; absent `--store` ⇒ byte-identical to golden baseline.

## Determinism

- `ASCC_LLM=off` ⇒ byte-identical SARIF except message.markdown fields (CI-enforced).
- results[] sorted in product code by (ruleId, resource_id, message).

## Scoring

- CVSS = base severity; KEV = hard override; EPSS = time-stamped ordering within buckets.
- Base severity NEVER confidence-discounted; only correlation-derived modifiers are.
- EPSS snapshots must carry date for reproducibility.

## Store

- effective_confidence(): pure function, computed at read time, never stored.
- TTL: expiry downgrades/marks stale, never deletes (provenance). Table method→TTL: TODO.
- Chain: InMemoryFactRepository → JsonlFactRepository → Postgres.

## Kubernetes

- Findings source only, NOT runtime. Ephemeral kind/k3d for fixtures.
- IRSA PoC (one evening) = go/no-go, strictly after store/.
- Deterministic bridges (1.0): providerID→EC2, IRSA→IAM Role, digest→ECR.
-
