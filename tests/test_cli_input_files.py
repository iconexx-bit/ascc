"""Input files the CLI cannot turn into scanner output.

An input directory holds whatever a scan left behind.

- A file that is not valid UTF-8 JSON is not scanner output (JSON is UTF-8,
  RFC 8259). It is skipped with the line used for any file that is not valid
  JSON, and the run goes on. The skip hides no scanner failure: nothing in
  such a file identifies it as scanner output.
- JSON nested deeper than the interpreter can parse (RecursionError) is not
  scanner output either, and is skipped the same way.
- A scanner file is read as UTF-8 whatever the locale, so valid output with
  non-ASCII text is read, not refused.
- A file the CLI cannot read (OSError), or whose scanner it cannot tell apart
  (two parsers match it), may be scanner output. It stops the run with
  INTERNAL, names the file, and writes nothing.

Before this contract each of these ended in an uncaught exception: exit 1,
which is ExitCode.FINDINGS, and a traceback. test_cli_parse_errors.py pins the
other side: a recognised file whose parser fails.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "fixtures" / "leaky_data_lake"
EXIT_NO_INPUT = 3  # ExitCode.NO_INPUT, pinned as a number: shell-facing contract
EXIT_INTERNAL = 70  # ExitCode.INTERNAL
NOT_UTF8 = b"\xff\xfe\x00{not utf-8"
# Matches TrivyParser.sniff and CheckovParser.sniff at once.
AMBIGUOUS = {"Results": [], "ArtifactType": "filesystem", "check_type": "terraform", "results": {}}
# open() without an encoding decodes as ASCII here; stdio stays UTF-8 so that
# printing is not what fails.
ASCII_LOCALE = {
    "LC_ALL": "C",
    "PYTHONCOERCECLOCALE": "0",
    "PYTHONUTF8": "0",
    "PYTHONIOENCODING": "utf-8",
}


def _copy_fixture(tmp_path: Path, name: str = "in") -> Path:
    inputs = tmp_path / name
    shutil.copytree(FIXTURE, inputs)
    return inputs


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "ascc", "correlate", *args]
    full_env = {**os.environ, "ASCC_CONSOLE_WIDTH": "200", **(env or {})}
    return subprocess.run(
        cmd,
        check=False,
        cwd=REPO_ROOT,
        env=full_env,
        capture_output=True,
        text=True,
        errors="replace",
    )


def _assert_stopped_cleanly(proc: subprocess.CompletedProcess[str], name: str) -> None:
    assert proc.returncode == EXIT_INTERNAL, f"rc={proc.returncode}\n{proc.stderr}"
    assert name in proc.stderr, proc.stderr
    assert "Traceback" not in proc.stderr + proc.stdout, proc.stderr


def test_non_utf8_file_is_skipped_as_not_valid_json(tmp_path: Path) -> None:
    clean = _copy_fixture(tmp_path, "clean")
    with_blob = _copy_fixture(tmp_path, "with-blob")
    (with_blob / "blob.json").write_bytes(NOT_UTF8)
    want, got = tmp_path / "want.sarif.json", tmp_path / "got.sarif.json"
    base = _run("--input", str(clean), "--output", str(want))
    proc = _run("--input", str(with_blob), "--output", str(got))
    assert base.returncode == 0, base.stderr
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stderr}"
    assert "Skipping blob.json: not valid JSON" in proc.stdout, proc.stdout
    assert got.read_bytes() == want.read_bytes()


def test_only_non_utf8_file_ends_in_no_input(tmp_path: Path) -> None:
    (tmp_path / "blob.json").write_bytes(NOT_UTF8)
    proc = _run("--input", str(tmp_path))
    assert proc.returncode == EXIT_NO_INPUT, f"rc={proc.returncode}\n{proc.stderr}"
    assert "Traceback" not in proc.stderr + proc.stdout, proc.stderr


def test_valid_utf8_json_is_read_under_an_ascii_locale(tmp_path: Path) -> None:
    inputs = _copy_fixture(tmp_path)
    trivy = inputs / "trivy.json"
    text = trivy.read_text(encoding="utf-8")
    assert '"Title": "' in text
    trivy.write_text(text.replace('"Title": "', '"Title": "\u00e9 ', 1), encoding="utf-8")
    # The other two parsers get non-ASCII text too; rc 0 means all three read it.
    for name, key in (("checkov.json", '"check_name": "'), ("prowler.json", '"class_name": "')):
        other = inputs / name
        body = other.read_text(encoding="utf-8")
        assert key in body, name
        other.write_text(body.replace(key, key + "\u00e9 ", 1), encoding="utf-8")
    sarif = tmp_path / "out.sarif.json"
    proc = _run("--input", str(inputs), "--output", str(sarif), env=ASCII_LOCALE)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"rc={proc.returncode}\n{out}"
    assert "Skipping trivy.json" not in out, out
    assert "\u00e9 " in sarif.read_text(encoding="utf-8")


def test_json_nested_too_deep_is_skipped_as_not_valid_json(tmp_path: Path) -> None:
    clean = _copy_fixture(tmp_path, "clean")
    with_deep = _copy_fixture(tmp_path, "with-deep")
    (with_deep / "deep.json").write_text("[" * 200_000, encoding="utf-8")
    want, got = tmp_path / "want.sarif.json", tmp_path / "got.sarif.json"
    base = _run("--input", str(clean), "--output", str(want))
    proc = _run("--input", str(with_deep), "--output", str(got))
    assert base.returncode == 0, base.stderr
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stderr[-2000:]}"
    assert "Skipping deep.json: not valid JSON" in proc.stdout, proc.stdout
    assert got.read_bytes() == want.read_bytes()


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="needs a non-root POSIX user: root ignores file modes",
)
def test_unreadable_file_exits_internal_and_names_it(tmp_path: Path) -> None:
    inputs = _copy_fixture(tmp_path)
    locked = inputs / "zz-locked.json"
    locked.write_text("[]")
    locked.chmod(0)
    sarif = tmp_path / "out.sarif.json"
    store = tmp_path / "store"
    try:
        proc = _run("--input", str(inputs), "--output", str(sarif), "--store", str(store))
    finally:
        locked.chmod(0o600)
    _assert_stopped_cleanly(proc, "zz-locked.json")
    assert not sarif.exists()
    assert not store.exists()


def test_ambiguous_scanner_format_exits_internal_and_names_it(tmp_path: Path) -> None:
    inputs = _copy_fixture(tmp_path)
    (inputs / "zz-ambiguous.json").write_text(json.dumps(AMBIGUOUS))
    sarif = tmp_path / "out.sarif.json"
    store = tmp_path / "store"
    proc = _run("--input", str(inputs), "--output", str(sarif), "--store", str(store))
    _assert_stopped_cleanly(proc, "zz-ambiguous.json")
    assert "ambiguous" in proc.stderr, proc.stderr
    assert not sarif.exists()
    assert not store.exists()


def test_contract_is_written_down() -> None:
    text = " ".join((REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8").split())
    assert "an input file that is not valid UTF-8 JSON is skipped" in text
    assert (
        "an input file that cannot be read or whose scanner cannot be told apart stops the run"
        in text
    )
    assert "JSON nested too deep to parse counts as not valid JSON" in text
    assert "scanner files are read as UTF-8 whatever the locale" in text
