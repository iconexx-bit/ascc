set shell := ["bash", "-uc"]

# Линт + полный прогон тестов
default: lint test

# Проверка лока и синхронности окружения (не мутирует)
deps-check:
    uv lock --check
    uv sync --check --locked --extra dev

# Форматирование и статический анализ
lint:
    uv run --locked ruff check .
    uv run --locked ruff format --check .

# Инварианты окружения — гейт для остального
test-env:
    uv run --locked pytest -m env -q

# Основной прогон, только после зелёного гейта
test: test-env
    uv run --locked pytest -m "not env" -q

# Диагностика: что видит just
show:
    just --dump
    # Привести .venv в соответствие с lock (МУТИРУЕТ окружение)
sync:
    uv sync --locked --extra dev

# fail if staged changes delete lines from CLAUDE.md
guard-claude-md:
    @if [ -n "${ALLOW_CLAUDE_MD_DELETE:-}" ]; then \
        echo "guard-claude-md: bypassed by ALLOW_CLAUDE_MD_DELETE" >&2; exit 0; \
     fi; \
     git diff --cached --numstat -- CLAUDE.md \
     | awk '$2 != 0 { print "CLAUDE.md: " $2 " line(s) deleted — manual review required" > "/dev/stderr"; exit 1 }'
