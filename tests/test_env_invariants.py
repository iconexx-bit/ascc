"""Инварианты окружения. Гейт для остальных тестов."""

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tomllib

import pytest

pytestmark = pytest.mark.env

ROOT = pathlib.Path(__file__).parents[1]


def test_entrypoint_inside_prefix():
    path = shutil.which("ascc")
    assert path is not None, "ascc не зарегистрирован"
    assert pathlib.Path(path).resolve().is_relative_to(pathlib.Path(sys.prefix).resolve())


def test_no_bare_cli_invocation_in_tests():
    bad = [
        p.name
        for p in (ROOT / "tests").rglob("*.py")
        if p.name != "test_env_invariants.py" and re.search(r'["\']ascc\s', p.read_text())
    ]
    assert not bad, f"голый вызов ascc: {bad}"


def test_no_duplicated_commands_in_ci():
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        assert "uv run" not in wf.read_text(), f"дубль команд: {wf.name}"


def test_hooks_delegate_to_just():
    hook = (ROOT / ".githooks" / "pre-commit").read_text()
    assert "uv run" not in hook, "хук дублирует команды вместо just"


def test_no_tests_outside_tests_dir():
    stray = [str(p) for p in (ROOT / "src").rglob("test_*.py")]
    assert not stray, f"тесты вне tests/: {stray}"


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="core.hooksPath is a working-copy invariant: it protects a developer's "
    "clone from committing past the local gate. CI has no local gate to protect — "
    "the workflow is the gate there.",
)
def test_hooks_path_is_configured():
    """A fresh clone has no core.hooksPath; without it .githooks/pre-commit
    never runs and the repo has no local gate at all. `just init-hooks` sets it."""
    out = subprocess.run(
        ["git", "config", "--get", "core.hooksPath"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert out.stdout.strip() == ".githooks", "just init-hooks не выполнен"


def test_dev_tools_are_a_dependency_group():
    """Dev tools live in the PEP 735 group `dev`, which `uv sync` and `uv run`
    install by default. As the extra `dev` they were removed by a plain
    `uv sync`, and `uv run pytest` fell through to /usr/bin/pytest 7.4.4
    while `uv run ruff` failed to spawn (A1, 2026-10-24)."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = data["project"].get("optional-dependencies", {})
    assert "dev" not in extras, "dev tools are a published extra, not a dependency group"
    group = data.get("dependency-groups", {}).get("dev", [])
    names = {re.split(r"[<>=!~;\[ ]", req, maxsplit=1)[0] for req in group}
    assert {"pytest", "ruff"} <= names, f"dependency-groups.dev lacks pytest/ruff: {sorted(names)}"


def test_no_extra_dev_in_entrypoints():
    """Every documented or automated sync installs the default group, so no
    entry point builds a different tool set than `uv run` syncs against."""
    paths = [
        ROOT / "justfile",
        ROOT / "README.md",
        *sorted((ROOT / ".github" / "workflows").glob("*.yml")),
    ]
    bad = [
        f"{p.relative_to(ROOT)}:{n}"
        for p in paths
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"--extra[ =]dev\b", line)
    ]
    assert not bad, f"--extra dev still used: {bad}"


def test_running_in_project_environment():
    """The interpreter running the tests is the project environment, not the
    system one a missing dev tool would fall through to."""
    env = os.environ.get("UV_PROJECT_ENVIRONMENT")
    expected = (ROOT / env if env else ROOT / ".venv").resolve()
    assert pathlib.Path(sys.prefix).resolve() == expected, (
        f"tests run outside the project environment: {sys.prefix} != {expected}"
    )


@pytest.mark.parametrize("tool", ["pytest", "ruff"])
def test_dev_tool_inside_prefix(tool):
    """`uv run <tool>` resolves through PATH: a tool missing from the project
    environment silently becomes the system one."""
    path = shutil.which(tool)
    assert path is not None, f"{tool} не найден"
    assert pathlib.Path(path).resolve().is_relative_to(pathlib.Path(sys.prefix).resolve()), (
        f"{tool} вне окружения проекта: {path}"
    )


def test_workflow_actions_pinned_by_sha():
    """Every third-party action is pinned to a full commit SHA: a tag can be
    moved to other code after review, a SHA cannot (A1, 2026-10-25)."""
    bad = []
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = re.match(r"\s*(?:-\s+)?uses:\s*([^\s#]+)", line)
            if not m or m.group(1).startswith(("./", "docker://")):
                continue
            ref = m.group(1).rpartition("@")[2]
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                bad.append(f"{wf.name}:{n} {m.group(1)}")
    assert not bad, f"actions not pinned to a commit SHA: {bad}"
