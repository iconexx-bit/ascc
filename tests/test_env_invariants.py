"""Инварианты окружения. Гейт для остальных тестов."""

import pathlib
import re
import shutil
import sys

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
