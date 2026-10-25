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


def test_dependabot_updates_pinned_actions():
    """Pinned actions get no fixes on their own: Dependabot bumps the SHA and its
    version comment, with a commit header the Commit Lint gate accepts
    (`ci(deps): ...`; its default `Bump ...` would fail every update PR)."""
    cfg = ROOT / ".github" / "dependabot.yml"
    assert cfg.is_file(), "no .github/dependabot.yml: pinned actions are never updated"
    text = cfg.read_text(encoding="utf-8")
    assert re.search(r"^version:\s*2\s*$", text, re.MULTILINE), "dependabot.yml is not version 2"
    assert re.search(r"package-ecosystem:\s*[\"']?github-actions[\"']?\s*$", text, re.MULTILINE), (
        "dependabot.yml does not track github-actions"
    )
    assert re.search(r"^\s+prefix:\s*[\"']?ci[\"']?\s*$", text, re.MULTILINE), (
        "dependabot commit messages lack the `ci` prefix Commit Lint requires"
    )
    assert re.search(r"^\s+include:\s*[\"']?scope[\"']?\s*$", text, re.MULTILINE), (
        "dependabot commit messages lack the (deps) scope"
    )


def _checkout_steps():
    """Yield (workflow, line, step lines) for every actions/checkout step."""
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        lines = wf.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if not re.match(r"\s*(?:-\s+)?uses:\s*actions/checkout@", line):
                continue
            start = i
            while start > 0 and not re.match(r"\s*-\s", lines[start]):
                start -= 1
            dash = len(lines[start]) - len(lines[start].lstrip())
            end = start + 1
            while end < len(lines) and (
                not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) > dash
            ):
                end += 1
            yield wf.name, i + 1, lines[start:end]


def test_checkout_does_not_persist_credentials():
    """No job pushes, so no job keeps GITHUB_TOKEN in .git after checkout: with
    the default persist-credentials every later step (third-party actions, test
    code) can read the token from the working copy (A1, 2026-10-25)."""
    steps = list(_checkout_steps())
    assert steps, "no actions/checkout steps found: the check would pass vacuously"
    bad = [
        f"{wf}:{n}"
        for wf, n, block in steps
        if not any(re.match(r"\s*persist-credentials:\s*false\s*(#.*)?$", ln) for ln in block)
    ]
    assert not bad, f"actions/checkout without persist-credentials: false: {bad}"


def test_pinned_actions_carry_version_comment():
    """A pinned SHA says nothing to a reviewer; the trailing `# vX.Y.Z` is what
    Dependabot rewrites with the SHA. A version kept in a separate comment line
    goes stale (codeql-analysis.yml said v4.1.7 / v3.25.11 after the bump)."""
    bad = []
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = re.match(r"\s*(?:-\s+)?uses:\s*([^\s#]+)(.*)$", line)
            if not m or m.group(1).startswith(("./", "docker://")):
                continue
            if not re.search(r"#\s*v\d+(\.\d+)*\s*$", m.group(2)):
                bad.append(f"{wf.name}:{n} {m.group(1)}")
    assert not bad, f"pinned actions without a trailing version comment: {bad}"


# Write scopes a workflow may grant, by file and scope: CodeQL uploads SARIF.
ALLOWED_WRITE = {("codeql-analysis.yml", "security-events")}


def test_workflows_declare_least_privilege_token():
    """Every workflow sets top-level `permissions:` (no reliance on the repository
    default for GITHUB_TOKEN), never `write-all`/`read-all`, and grants `write`
    only where listed in ALLOWED_WRITE (A1, 2026-10-25)."""
    bad = []
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        lines = wf.read_text(encoding="utf-8").splitlines()
        if not any(re.match(r"permissions:", ln) for ln in lines):
            bad.append(f"{wf.name}: no top-level permissions")
        for n, ln in enumerate(lines, 1):
            code = ln.split("#", 1)[0]
            if re.search(r"\b(write|read)-all\b", code):
                bad.append(f"{wf.name}:{n} {code.strip()}")
            m = re.match(r"\s*([a-z-]+):\s*write\s*$", code)
            if m and (wf.name, m.group(1)) not in ALLOWED_WRITE:
                bad.append(f"{wf.name}:{n} {m.group(1)}: write")
    assert not bad, f"workflow token permissions: {bad}"


def _setup_uv_inputs():
    """(workflow, line, key) for each `with:` key of each astral-sh/setup-uv step."""
    found = []
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        lines = wf.read_text(encoding="utf-8").splitlines()
        for n, ln in enumerate(lines):
            if "astral-sh/setup-uv@" not in ln.split("#", 1)[0]:
                continue
            found.append((wf.name, n + 1, "uses"))
            indent = len(ln) - len(ln.lstrip(" -"))
            for m, nxt in enumerate(lines[n + 1 :], n + 2):
                code = nxt.split("#", 1)[0].rstrip()
                if not code:
                    continue
                if len(code) - len(code.lstrip()) < indent or code.lstrip().startswith("- "):
                    break
                key = re.match(r"\s*([a-z-]+):", code)
                if key:
                    found.append((wf.name, m, key.group(1)))
    return found


def test_uv_version_pinned_once_in_pyproject():
    """One uv version for the VM and CI: `[tool.uv] required-version` is an exact
    pin (uv refuses to run under any other version); setup-uv takes it from
    pyproject.toml because no step sets `version`/`version-file`; the README names
    the same version (A1, 2026-10-25)."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pin = pyproject.get("tool", {}).get("uv", {}).get("required-version")
    assert isinstance(pin, str) and re.fullmatch(r"==\d+\.\d+\.\d+", pin), (
        f"[tool.uv] required-version must be an exact ==X.Y.Z pin, got {pin!r}"
    )
    inputs = _setup_uv_inputs()
    assert inputs, "no astral-sh/setup-uv step found"
    bad = [i for i in inputs if i[2] in ("version", "version-file")]
    assert not bad, f"setup-uv must read the pin from pyproject.toml: {bad}"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"uv {pin[2:]}" in readme, f"README does not name uv {pin[2:]}"
