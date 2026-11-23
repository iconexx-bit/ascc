"""No tracked file carries a real AWS account ID or a real home directory.

This repository is public, and scanner output and evidence land in it. They are
sanitised before they are committed: an AWS account ID is one of the
placeholders below, and a home directory is /home/user. A 12-digit run inside a
longer hexadecimal string (a hash, a build ID) is not an account ID and is not
checked. A file name counts as content: Prowler names its output after the
account. Failure messages show only the first three characters of what they
found, because CI logs are public too.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ACCOUNT_ID = re.compile(r"(?<![0-9A-Fa-f])\d{12}(?![0-9A-Fa-f])")
HOME_DIR = re.compile(
    r"/home/([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)"
)  # a trailing dot ends the sentence
LAB_ACCOUNT = "123456789012"  # AWS documentation placeholder
MANAGED_ACCOUNT = "111122223333"  # AWS documentation placeholder
PLACEHOLDER_ACCOUNTS = {
    LAB_ACCOUNT,  # the lab account
    MANAGED_ACCOUNT,  # the account that AWS-managed roles in the lab account trust
    "999999999999",  # test data: a second account that matches nothing
}
PLACEHOLDER_HOME = "user"


def tracked() -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    return sorted(name for name in listed.split("\0") if name)


def _text(rel: str) -> str | None:
    data = (REPO_ROOT / rel).read_bytes()
    if b"\0" in data:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def _offenders(pattern: re.Pattern[str], allowed: set[str]) -> dict[str, list[str]]:
    """Masked value -> files, for every match not in `allowed`."""
    found: dict[str, list[str]] = {}
    for rel in tracked():
        text = _text(rel)
        if text is None:
            continue
        for value in sorted(set(pattern.findall(text)) - allowed):
            found.setdefault(value[:3] + "…", []).append(rel)
    return found


def test_no_account_id_but_the_placeholders() -> None:
    found = _offenders(ACCOUNT_ID, PLACEHOLDER_ACCOUNTS)
    assert not found, f"12-digit numbers that are not placeholders: {found}"


def test_no_account_id_in_file_names() -> None:
    named = [ACCOUNT_ID.sub("<12 digits>", rel) for rel in tracked() if ACCOUNT_ID.search(rel)]
    assert not named, f"12-digit numbers in tracked file names: {named}"


def test_no_home_directory_but_the_placeholder() -> None:
    found = _offenders(HOME_DIR, {PLACEHOLDER_HOME})
    assert not found, f"home directories other than /home/{PLACEHOLDER_HOME}: {found}"


def test_rule_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "No tracked file carries a real AWS account ID or a real home directory" in text
    assert LAB_ACCOUNT in text
    assert MANAGED_ACCOUNT in text
    assert f"/home/{PLACEHOLDER_HOME}" in text
