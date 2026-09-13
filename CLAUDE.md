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

- `_record_resource` It’s duplicated across three parsers. Move it into ScannerParser as a separate refactoring — do not mix this change with adding the scanner.
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
- tooling: guard-claude-md should scope deletion check outside ## Backlog (crossing off done items is legitimate)
- Settings Sync scope: Extensions/MCP/Profiles excluded — declarative policy owns extensions
- ResourceRelation: implement red-first alongside the LLM edge track
(method="llm", confidence<=0.3, excluded from Union-Find). Fact.key is
a variable-length tuple — a relation fits as (src, dst) with no schema
change. Verified 2026-09-07, no rework risk.
- volatility_class как первичный ключ политики вместо method
- source_digest как жёсткий инвалидатор (слот в Fact есть с v1, логики нет)
- Jsonl append-only + история наблюдений + confirmations/contradicted_by
- корроборация llm <-> детерминированный источник
- перенести словарь методов в store, correlate импортирует (сейчас — cross-import в тестах)
- проверить резолвер terraform на for_each/count фикстуре
- store: observed_at vs verified_at/last_confirmed — split when confirmations land
- store: source_digest slot in Fact (additive, frozen dataclass with default)
- store: put() rejects a naive `now` only via TypeError from the comparison;
consider an explicit aware check for symmetry with is_stale
- guard-claude-md: detect duplicate contract blocks, not only deletions
- git: one commit, one fresh message file (/tmp/msg-N.txt); never reuse or append
- post-edit auto-formatter strips unused imports mid-write; re-run ruff after
adding type hints, not before
- pre-commit does not run on merge commits: I001 entered main via
602178b (feat/store-ttl, --no-ff). CI caught it (run #67) but the
alert was missed for two days -- the red-commit push rule above is
the fix. Optional backup: .githooks/pre-merge-commit.
- store: JsonlFactRepository writes "v":1 but never reads it. A v2 file
read by v1 code is misparsed silently. Add a version check in
_from_record before the format ever changes, not after.
- store: put() fsyncs the file but not the directory, so the file's
CREATION is not durable — only its contents. A crash right after the
first put can leave no file at all. Add an O_DIRECTORY fsync after
mkdir, or accept and document the window.
- store: validation is duplicated between memory.py and jsonl.py. The
conformance suite makes drift fail immediately, so two copies are safe;
extract a shared helper when Postgres makes it three.
- store: file mode 0o600 is unasserted by any test. Add one or drop the
claim from CLAUDE.md.
- tooling: reviewing deletions with `grep '^-[^-]'` hides deleted markdown
bullets (they render as `--`) and blank lines. Use
`git show <sha> -- FILE | grep '^-' | grep -v '^---'` and check the count
against --numstat column 2.
- Error output: paths and any untrusted string go to stderr via `typer.echo(..., err=True)`, never Rich markup — a `[/x]` in a path raised MarkupError inside the handler and replaced the exit code with a traceback (fixed in `fix(cli)`).
- `guard-claude-md`, third item: honour `ALLOW_CLAUDE_MD_DELETIONS=N` and pass only when it equals `git diff --numstat` col2, instead of a blanket `--no-verify` that also skips gitleaks.
- Multi-line CLAUDE.md edits go through a fail-closed script (anchor preconditions + numstat postcondition); paste source text into empty files only, never edit the section in place.
- `.prettierignore` for CLAUDE.md — format-on-save would reformat it and the guard would read that as deletions.

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

2026-08-23: TOOLING FREEZE lifted at v0.1.0-rc (commit bc809806).
New tooling ideas go to ## BACKLOG as one-liners, not code.
Exception: CI-blocking failures only.
rc scope (cut 2026-08-20): v0.1.0-rc ships to_sarif() + --output + determinism test.
SARIF schema-validation and live-golden regeneration deferred to 0.1.1.
LIFTED 2026-09-10 by its own gate (see Progress below) — the block that
follows is kept for provenance, not as a live rule.
ACTIVE FREEZE (scoped, 2026-09-06): no chore(tooling) commits until
the JsonlFactRepository conformance suite is green. Rationale: the
previous unscoped lift was followed by three consecutive tooling
commits and zero src/ commits for three weeks.
New tooling ideas go to ## BACKLOG as one-liners, not code.
Exception: CI-blocking failures only.
Progress 2026-09-08: the conformance suite exists and is parametrised over
implementations (tests/store/test_repository_conformance.py, 19 tests).
InMemoryFactRepository passes it as of 3f821af; policy.py and memory.py
landed with 37 contract tests in tests/store/, 170 total.
JsonlFactRepository remains — one line in IMPLEMENTATIONS plus the deferred
reload-preserves-observed_at test — so the freeze holds by its own terms.
TDD red commits are NOT pushed alone: CI runs the full suite on main
and will fail. Commit red locally, implement, push red+green together.
The pair stays visible in history; CI only ever sees green.
(Learned 2026-09-07: b6804e4 pushed alone triggered a CI failure alert.)
Progress 2026-09-10: JsonlFactRepository green. The conformance suite is
parametrised over two implementations (42 cases) plus 13 durability cases
in tests/store/test_jsonl_repository.py; 205 total. The scoped freeze of
2026-09-06 is lifted by its own terms: no chore(tooling) commits landed
while it held.

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
- TTL: expiry downgrades/marks stale, never deletes (provenance).
- Chain: InMemoryFactRepository → JsonlFactRepository → Postgres.
- `--store` is a directory (file_okay=False); never a single file.
- `--store` accepts a non-existent path. The CLI never creates the
  directory; JsonlFactRepository.put does, on first write.
- Invariant: an ABSENT or EMPTY store produces byte-identical SARIF.
  The mere presence of the flag never leaks into the artifact. A
  POPULATED store legitimately changes correlation output — that is the
  feature, not a violation, and ШАГ 6 depends on it.
  tests/test_store_invariant.py already tests the correct form: it
  points --store at a fresh tmp directory.

### Freshness policy (v1)

- TTL models SOURCE VOLATILITY, not method trust and not recomputation cost.
Trust lives in confidence. Double-counting is forbidden: any TTL other than
30d for a source-bound method needs an argument about how fast the source
changes, otherwise it is trust smuggled into the volatility axis.
- TTL is resolved at read time from a versioned constant
(ascc.store.policy, TTL_POLICY_VERSION). Changing numbers ⇒ no data migration.
- The repository never READS the clock: `now` is keyword-only and mandatory on
   put/get/all, injected by the caller (FactRepository, 5056b89). Machine-checked
   by tests/test_fact_repository.py, both behaviourally and by source grep.
- The TTL anchor is Fact.observed_at. Re-observation means a new put with a new
   observed_at; put MUST NOT rewrite it, or Jsonl reload would launder freshness.
- Fact.stale is a stored field only in the sense that it defaults to False.
   Its authoritative value is rendered at read: get/all return
   replace(fact, stale=is_stale(fact.method, fact.observed_at, now)).
   Policy is the single owner; no repository re-implements expiry.
- is_stale(method, observed_at, as_of) — pure, primitives only.
- Validation lives in put(), never in Fact.__post_init__: unknown method
   raises KeyError, confidence above MAX_CONFIDENCE[method] raises ValueError,
   observed_at > now raises ValueError. Fact stays a dumb record.
- Fact.key does NOT contain method — they are separate fields, and get(key)
   returns one fact per key. A producer that needs facts from different methods
   about the same subject to coexist MUST put the method into the key tuple.
- Source-grep guard: tests/test_fact_repository.py greps src/ascc/store/ for
   "datetime.now", "utcnow", "time.time", "time.monotonic" outside # comments.
   Docstrings and string literals count. Do not name these APIs inside the package.
- Layer provenance: Fact + FactRepository ABC in 5056b89 (models.py, not
   fact.py); policy.py and InMemoryFactRepository in ШАГ 3.
- Boundary: stale when age >= ttl. as_of < observed_at ⇒ not stale
  (falls out of the formula, no special branch).
- ascc.store introduces NO effective_confidence of its own. fact.confidence
   is used as stored; stale is an orthogonal flag, never a multiplier.
   In v1 is_stale has no consumers — that is expected.
- correlate.run.effective_confidence (resolution × bridge) is a DIFFERENT
   function, out of scope for the store layer and MUST NOT be modified.
- Fact.key does NOT contain method — they are separate fields, and get(key)
  returns one fact per key. A producer that needs facts from different methods
  about the same subject MUST put the method into the key tuple; key is
  variable-length, so no schema change is required.
  If a key element derives from MatchKey.__str__, the MatchKey stability
  contract extends to the on-disk store format.
- put overwrites by key; observation history is not kept in v1 (see Backlog).
  The provenance invariant covers TTL only.
- InMemory (overwrite) and Jsonl (append-only, last wins) are observationally
  equivalent through the ABC ⇒ one shared conformance suite.
- All datetimes are aware UTC. naive ⇒ raises, both in Fact and in is_stale.
- ascc.store is stdlib-only: no DB drivers, and it never imports ascc.correlate.
  The reverse direction (correlate → store) is allowed.
- method=terraform ⇒ natural name statically resolved. Indexed addresses
  (for_each/count) and unresolved variables MUST NOT emit a tier-1.0 bridge.
- ШАГ 3 lands policy/Fact/ABC/InMemory only. CLI wiring (including
  writable=True) is a separate step; `--store` stays output-neutral.

| method                           | max_conf | TTL  | volatility   | invalidator (planned)      |
|----------------------------------|----------|------|--------------|----------------------------|
| arn_parse                        | 1.0      | None | immutable    | —                          |
| terraform_natural_name           | 1.0      | 30d  | source_bound | source_digest (v2)         |
| terraform_generated_id_unbridged | 0.4      | 30d  | source_bound | source_digest (v2)         |
| filesystem_path_heuristic        | 0.5      | 30d  | source_bound | source_digest (v2)         |
| observed_together                | 0.95     | 7d   | run_bound    | scan run digest (v2)       |
| llm                              | 0.3      | 30d  | source_bound | sha256(prompt+input+model) |

- Method literals and confidences are ground truth from src/ascc/schema/identity.py
and src/ascc/ingest/prowler.py. This table is generated by grep, never from memory:
two of the five are passed positionally, so `grep 'method='` alone misses them.
- MAX_CONFIDENCE spans two populations. arn_parse / terraform_* /
filesystem_path_heuristic are Resolution.confidence; observed_together is
BridgeFact.confidence. They are distinct factors in
correlate.run.effective_confidence (resolution × bridge) and are NOT comparable —
monotonicity is asserted within resolution methods only.
- Three volatility classes, three TTL values. run_bound is shorter than source_bound
because a scanner run artefact is superseded by the next scan, not by a file edit.
This is an argument about source change frequency, not about trust:
observed_together carries the second-highest confidence in the table.
- Store keys are opaque: MatchKey.__str__ is not injectively parseable
(unescaped ':'), so a stored key is compared by equality and never split.

### JsonlFactRepository

- Constructor takes a DIRECTORY, mirroring `--store` (file_okay=False).
  The file name is an implementation detail; the CLI never spells ".jsonl".
- The directory is created on the first put, never in __init__: `--store`
  accepts a non-existent path and construction has no filesystem effects.
- Append-only, one JSON object per line, LF-terminated, last line per key
  wins on read. Rationale: observation history (Backlog) needs the earlier
  lines, and observed_at becomes structurally un-rewritable.
- put() = one write() + fsync. No buffer, no flush/close contract, no tmp
  file. Validation precedes the write: a rejected put leaves the file byte-
  identical.
- all() collapses duplicate keys; observationally identical to InMemory.
- stale is NEVER serialised: rendered at read from policy.
- The file encodes neither TTL nor TTL_POLICY_VERSION.
- Format version "v":1, bumped when the serialised field set changes.
  Distinct from TTL_POLICY_VERSION; the two never move together.
- Explicit field mapping, never dataclasses.asdict(): asdict would bind the
  on-disk format to field names and make a rename a silent breaking change.
- payload is Mapping[str, str]; reloaded as MappingProxyType for symmetry.
- json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False),
  encoding="utf-8", newline="\n", file mode 0o600.
- A truncated trailing line is skipped, not raised: only the last line can
  tear, and losing one fact must not cost the other N-1.
- Conformance fixture: implementations are built from a tmp directory. The
  "no arguments" contract was InMemory-shaped and did not survive contact
  with a file-backed repository.

  ### ШАГ 5: CLI wiring + producer

- --store gains writable=True. exists stays False: the path may not
  exist, and click skips the access check when it does not.
- `del store` is replaced by constructing JsonlFactRepository(store).
- ORDER IS CONTRACT: the store block sits AFTER the --output block in
  correlate(). SARIF is written only under --output, so the ordering is
  positional, not conditional. --store without --output is legitimate.
- The CLI is the clock injector: datetime.now(UTC) belongs here and is
  outside the store-package grep guard by design.
- Source: CorrelationRun.scan_runs[].bridge_facts. Only observed_together
  is ever emitted, because BridgeFact is the only thing bridge_facts
  holds — the emission criterion is satisfied structurally, not by a
  filter. arn_parse lives in Resolution and never reaches the store.
- BridgeFact -> Fact mapping lives in cli.py, not in ascc.store: the
  store package must not import ascc.schema.
    key        = tuple(sorted((str(bf.left), str(bf.right))))
    method     = bf.method
    confidence = bf.confidence
    observed_at= the injected now
    payload    = {"source": bf.source, "evidence": bf.evidence}
- The key is the sorted pair of the sides' string forms. Redundant today:
  `BridgeFact.__post_init__` already orders left/right by the same str
  comparison (verified 2026-09-10), so within one version no pair can
  yield two records. The sort stays because the persisted key is a durable
  format and must not inherit an in-memory invariant: if BridgeFact's
  ordering ever changes, an unsorted mapper would file one pair under two
  keys across versions, and append-only storage never cleans that up.
  Sorting lives in the cli.py mapper only: ResourceRelation keys (src,dst)
  are directed and must never be sorted.
- payload gets its first product writer here. source and evidence have no
  Fact field and would otherwise be dropped.
- Reading the key back is OUT OF SCOPE: MatchKey.__str__ is not
  injectively parseable. ШАГ 6 must resolve how a consumer recovers a
  MatchKey — carry it in payload, or make __str__ round-trippable.
- A store write failure after the SARIF is on disk warns on stderr and
  keeps ExitCode.OK: the artifact already succeeded.
- Store-only run (no --output): the store IS the requested product, so a
  store write failure exits ExitCode.INTERNAL with the error on stderr.
  Warn-and-OK above holds only when a SARIF artifact already succeeded.
  Fail-open here would lose history silently: ШАГ 6 would read an empty
  store as "no history".
- tests/test_store_invariant.py::test_store_writes_nothing is inverted to
  test_store_persists_facts. Its own docstring authorises exactly this
  edit; test_store_flag_is_output_neutral stays untouched.

## Kubernetes

- Findings source only, NOT runtime. Ephemeral kind/k3d for fixtures.
- IRSA PoC (one evening) = go/no-go, strictly after store/.
- Deterministic bridges (1.0): providerID→EC2, IRSA→IAM Role, digest→ECR.
-
