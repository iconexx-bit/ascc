# ASCC — AI Security Command Center

## Что это
Корреляционно-рассуждающий слой поверх сканеров облачной инфраструктуры.
НЕ сканер. Не пиши код, обращающийся к облачным API напрямую —
входные данные всегда приходят из внешних инструментов.

Вход:  Trivy, Prowler, Checkov (нативные JSON-выводы)
Выход: SARIF — только как export target, не как внутренняя модель

## Пайплайн и карта модулей
ingest -> schema -> store -> correlate -> export

- src/ascc/cli.py       — точка входа (единственный реализованный модуль)
- src/ascc/ingest/      — парсеры сканеров, по модулю на сканер, общий интерфейс. ПУСТО
- src/ascc/schema/      — нормализованная модель: Resource, Finding, связи. ПУСТО
- src/ascc/store/       — слой персистентности, PostgreSQL + pgvector. ПУСТО
- src/ascc/correlate/   — ядро корреляции и рассуждения, суть проекта. ПУСТО
- src/ascc/export/      — рендер в SARIF. ПУСТО

Проект на ранней стадии: почти все подпакеты содержат только __init__.py.
Порядок реализации: schema -> ingest -> store -> correlate -> export.

## Тестовые данные
fixtures/leaky_data_lake/ — эталонный сценарий:
- trivy.json, prowler.json, checkov.json — сырые выводы трёх сканеров
- README.md — описание сценария, читай его перед работой с фикстурами

Каталога tests/ пока НЕТ. Фикстуры лежат в корне, не в tests/fixtures/.

## Архитектурные решения — приняты, не пересматривать
- Схема: resource-centric normalized — ресурс первичен, findings навешиваются на него
- Хранилище: PostgreSQL + pgvector
- SARIF: исключительно на экспорт; внутри — собственная нормализованная модель

## Инварианты
- Finding может ссылаться на несколько ресурсов — связь many-to-many
- Дедупликация по ключу (resource_id, rule_id, scanner), НЕ по тексту описания
- Парсер каждого сканера — отдельный модуль в ingest/ с общим интерфейсом;
  correlate/ и schema/ о конкретных сканерах не знают
- Матчинг по имени сущности не равен обнаружению сущности:
  детект по паттерну значения, не по упоминанию имени
- Resource.refs — счётчик наблюдений, дубликаты ожидаемы.
  Resource.resolutions может содержать идентичные записи; дедупликация
  объяснений — задача correlate/, не ingest/.

## Окружение и команды
Пакетный менеджер — uv. Виртуальное окружение: .venv в корне.

    uv sync                       # установка зависимостей
    uv run pytest -q              # тесты (когда появятся)
    uv run ruff check src/        # линт
    uv run python -m ascc.cli     # запуск CLI

Makefile отсутствует — команд make не существует, не предлагай их.

## Стиль работы
- Python, type hints обязательны
- Изменения схемы БД — только через миграции, никаких ручных ALTER
- Перед реализацией нового подпакета — сначала план текстом, потом код
- Новые зависимости — только после явного согласования
- Вывод тестов и логов сокращай (-q, | tail -30), не тащи простыни в контекст

## Чего НЕ делать
- Не расширять scope до "добавим ещё один сканер" — это убивает дифференциацию
- Не хардкодить маппинги правил конкретного сканера в correlate/ или schema/
- Не трогать .venv/, .git/, __pycache__/ и содержимое fixtures/ без явной просьбы

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
- **merge**: destroys the losing key; a later scan producing it has nowhere
  to land; irreversible if the bridge was wrong
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
