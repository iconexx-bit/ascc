#!/usr/bin/env bash
# One-shot, fail-closed. Appends six Backlog bullets. Invoke: bash scripts/claude-md-lessons.sh
set -euo pipefail
trap 'echo "ABORTED near line $LINENO (exit $?)" >&2' ERR

F="CLAUDE.md"
ANCHOR="## Backlog"
MARK="working-copy invariant"

[[ -f "$F" ]]                     || { echo "PRE: no $F"; exit 1; }
git diff --quiet -- "$F"          || { echo "PRE: $F dirty"; exit 1; }
git diff --cached --quiet -- "$F" || { echo "PRE: $F staged"; exit 1; }
grep -qF "$ANCHOR" "$F"           || { echo "PRE: anchor missing"; exit 1; }
! grep -qF "$MARK"  "$F"          || { echo "PRE: already applied"; exit 1; }
BEFORE=$(wc -l < "$F")

python3 - "$F" "$ANCHOR" <<'PY'
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
anchor = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

BLOCK = """
- tests: an env invariant describing the developer's clone (core.hooksPath) is a
  working-copy invariant and is false in CI; it needs skipif(CI) with the reason in the
  skip text. Package invariants (entrypoint, no tests outside tests/) hold everywhere.
- tooling: pasting a multi-line block into the editor dropped a newline or a character
  five times in one session (### ШАГ 6 heading, a Backlog bullet, justfile `show:`,
  `def` where `@` belonged). Re-parse right after every multi-line edit: `just --list`
  for the justfile, `python3 -c "import ast; ast.parse(...)"` for Python, precheck greps
  for docs.
- tests: a new guard is proved by reproducing the defect it was written for, never by a
  green run. test_documented_names_exist_in_source was green until an `IdentityBridge`
  probe appended to README made it fail.
- tooling: guard-claude-md reads ALLOW_CLAUDE_MD_DELETE, not ..._DELETIONS as an earlier
  Backlog line says; ШАГ 4 used a blanket --no-verify when the scoped bypass existed.
- security: gitleaks runs only in CI (ci.yml:47). The local .pre-commit-config.yaml that
  declared it was never executed — core.hooksPath points at .githooks — and is deleted.
  A --no-verify commit therefore cannot skip the secret scan. Intentional.
- deps: `pre-commit` is still in dev extras but no hook uses it; removing it touches
  uv.lock, so it is deferred, not forgotten.
"""


def find_anchor(rows, name):
    for i, row in enumerate(rows):
        if row.strip() == name:
            return i
    raise SystemExit(f"PRE: anchor not found: {name!r}")


def insert_at_section_end(rows, name, block):
    start = find_anchor(rows, name)
    end = len(rows)
    for j in range(start + 1, len(rows)):
        if rows[j].startswith("## "):
            end = j
            break
    while end > start + 1 and rows[end - 1].strip() == "":
        end -= 1
    # No blank separator: bullets continue an existing bullet list.
    return rows[:end] + [block.lstrip("\n")] + rows[end:]


lines = insert_at_section_end(lines, anchor, BLOCK)

fd, tmp = tempfile.mkstemp(dir=str(path.parent))
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write("".join(lines))
os.replace(tmp, path)
print("insert: python done")
PY

AFTER=$(wc -l < "$F")
(( AFTER > BEFORE ))                   || { echo "POST: no growth"; exit 1; }
[[ $(grep -cF "$MARK" "$F") -eq 1 ]]   || { echo "POST: marker not unique"; exit 1; }
DEL=$(git diff --numstat -- "$F" | awk '{print $2}')
[[ "${DEL:-0}" -eq 0 ]]                || { echo "POST: $DEL deletions — ABORT"; exit 1; }
echo "OK: +$((AFTER - BEFORE)) lines, 0 deletions"
