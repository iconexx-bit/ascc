"""Release gate: the version in pyproject.toml is the single source.

Before a tag, CHANGELOG, uv.lock and the README roadmap must agree with it:
the top CHANGELOG entry is that version with a date, the lock records the
same version for the project, and the roadmap no longer promises it.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENTRY = re.compile(r"^## \[([^\]]+)\] — (\d{4}-\d{2}-\d{2})$", re.MULTILINE)


def _version() -> str:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["project"]["version"]


def test_top_changelog_entry_is_the_project_version() -> None:
    text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    top = ENTRY.search(text)
    assert top, "CHANGELOG.md has no '## [X.Y.Z] — YYYY-MM-DD' entry"
    assert top.group(1) == _version(), f"top entry {top.group(1)} != pyproject {_version()}"


def test_lock_records_the_project_version() -> None:
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    [ascc] = [p for p in lock["package"] if p["name"] == "ascc"]
    assert ascc["version"] == _version()


def test_readme_roadmap_does_not_promise_a_released_version() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    roadmap = text.split("## Roadmap", 1)[1].split("\n## ", 1)[0]
    assert f"`v{_version()}`" not in roadmap, f"README roadmap still lists v{_version()}"
