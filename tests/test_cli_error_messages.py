"""Failure messages on stderr must be literal text, not Rich markup.

Both OSError handlers in cli.py interpolate the exception into a Rich markup
string. The exception text carries a user-supplied path, so the path is parsed
as markup: a segment like [prod] is swallowed as an unknown style tag, and a
segment like [/x] raises MarkupError from inside the handler, replacing the
contract's exit code with a traceback.

Each test asserts the exit code AND that the path appears verbatim on stderr.
The second assertion is what pins the fix: escaping the markup keeps the exit
code but still wraps the line at Rich's default 80 columns off a terminal,
which breaks the path. Plain stderr output satisfies both.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_REL = "fixtures/leaky_data_lake"
EXIT_INTERNAL = 70  # ExitCode.INTERNAL, pinned as a number: shell-facing contract


def _run_correlate(*extra: str) -> subprocess.CompletedProcess[bytes]:
    cmd = [sys.executable, "-m", "ascc", "correlate", "--input", FIXTURE_REL, *extra]
    return subprocess.run(cmd, check=False, cwd=REPO_ROOT, capture_output=True)


def _markup_trap(tmp_path: Path) -> Path:
    """A directory path whose own name carries both markup shapes.

    A regular file stands where the first component should be, so every write
    under it fails with OSError for any user, root included. [prod] is an
    unknown opening tag; [/x] is a closing tag with no opener.
    """
    blocker = tmp_path / "[prod]"
    blocker.write_text("")
    return blocker / "[" / "x]"


def test_store_error_message_is_literal(tmp_path: Path) -> None:
    """Store-only run: the store is the product, so the run exits INTERNAL
    and the operator must be able to read the path that failed."""
    store = _markup_trap(tmp_path) / "facts"
    proc = _run_correlate("--store", str(store))
    err = proc.stderr.decode()
    assert proc.returncode == EXIT_INTERNAL, f"rc={proc.returncode}\n{err}"
    assert str(store) in err, err


def test_sarif_error_message_is_literal(tmp_path: Path) -> None:
    """The SARIF handler shares the defect. Its temp file name is random, so
    the deterministic part of the path is the directory it failed to write in."""
    out_dir = _markup_trap(tmp_path)
    proc = _run_correlate("--output", str(out_dir / "out.sarif.json"))
    err = proc.stderr.decode()
    assert proc.returncode == EXIT_INTERNAL, f"rc={proc.returncode}\n{err}"
    assert str(out_dir) in err, err
