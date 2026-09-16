set shell := ["bash", "-uc"]

# Линт + полный прогон тестов
default: lint test

# Проверка лока и синхронности окружения (не мутирует)
deps-check:
    uv lock --check
    uv sync --check --locked --extra dev

# Форматирование и статический анализ
lint:
    uv run --locked ruff check --no-cache .
    uv run --locked ruff format --check --no-cache .

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

# warn on CLAUDE.md line removals; authority lives in tests/test_claude_md_contracts.py
guard-claude-md:
    @git diff --cached --numstat -- CLAUDE.md \
     | awk '$2 ~ /^[0-9]+$/ && $2 != 0 { \
         print "guard-claude-md: " $2 " line(s) removed — CI checks contract anchors" > "/dev/stderr" }'; \
     exit 0

# Git hooks live in .githooks; core.hooksPath is per-clone and must be set.
init-hooks:
    git config core.hooksPath .githooks
    @test -x .githooks/pre-commit || (echo "pre-commit not executable" >&2; exit 1)
    @echo "hooks: core.hooksPath=$(git config --get core.hooksPath)"

# Cross-run correlation demo: run 2 (no prowler.json) reads run 1's store and reports the generated-id ARNs as ghosts
demo:
    #!/usr/bin/env bash
    set -euo pipefail
    # Same technique as tests/test_store_invariant.py::
    # test_populated_store_exposes_ghost_membership_in_sarif (CLI
    # subprocess, --store, fixture copy minus prowler.json) -- not a
    # second path. ASCC_NOW is pinned: observed_together has a 7d TTL.
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    export ASCC_NOW="2026-09-15T12:00:00+00:00"
    store="$tmp/facts"
    reduced="$tmp/reduced"
    mkdir -p "$reduced"
    for f in fixtures/leaky_data_lake/*; do
        name="$(basename "$f")"
        [ "$name" = "prowler.json" ] && continue
        cp "$f" "$reduced/$name"
    done
    echo "run 1: full fixture, populates $store" >&2
    uv run --locked python -m ascc correlate \
        --input fixtures/leaky_data_lake \
        --output "$tmp/run1.sarif.json" \
        --store "$store"
    echo "run 2: fixture without prowler.json, reads $store" >&2
    uv run --locked python -m ascc correlate \
        --input "$reduced" \
        --output "$tmp/run2.sarif.json" \
        --store "$store"
    echo "--- diff run1.sarif.json run2.sarif.json ---"
    diff -u "$tmp/run1.sarif.json" "$tmp/run2.sarif.json" || true
    echo "--- ghost_members in run 2 ---"
    jq '.runs[0].results[] | select(.properties.ghost_members) | {ruleId, ghost_members: .properties.ghost_members}' "$tmp/run2.sarif.json"
