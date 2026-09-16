#!/usr/bin/env bash
# One-shot, fail-closed. Preconditions + anchored insert + postconditions.
# Invoke: bash scripts/claude-md-step6.sh
# SPENT 2026-09-16: one-shot Step 6 edit, already applied. Anchors intentionally
# keep the pre-rename 'ШАГ' form; do not re-run.
set -euo pipefail
trap 'echo "ABORTED near line $LINENO (exit $?)" >&2' ERR

F="CLAUDE.md"
ANCHOR_STORE="## Store"
ANCHOR_BACKLOG="## Backlog"
MARK_STORE="payload_v"
MARK_BACKLOG="ШАГ 7: expose cluster membership"

# --- preconditions ---------------------------------------------------------
[[ -f "$F" ]]                       || { echo "PRE: no $F"; exit 1; }
git diff --quiet -- "$F"            || { echo "PRE: $F dirty"; exit 1; }
git diff --cached --quiet -- "$F"   || { echo "PRE: $F staged"; exit 1; }
grep -qF "$ANCHOR_STORE"   "$F"     || { echo "PRE: anchor Store missing"; exit 1; }
grep -qF "$ANCHOR_BACKLOG" "$F"     || { echo "PRE: anchor Backlog missing"; exit 1; }
! grep -qF "$MARK_STORE"   "$F"     || { echo "PRE: already applied (store)"; exit 1; }
! grep -qF "$MARK_BACKLOG" "$F"     || { echo "PRE: already applied (backlog)"; exit 1; }
BEFORE=$(wc -l < "$F")

python3 - "$F" "$ANCHOR_STORE" "$ANCHOR_BACKLOG" <<'PY'
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
anchor_store, anchor_backlog = sys.argv[2], sys.argv[3]
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

STORE_BLOCK = """
### ШАГ 6: store consumer (cross-run identity)
- Payload is `Mapping[str, str]` — flat keys only. Schema v1: `payload_v="1"`,
  `source`, `evidence`, plus `left.*` / `right.*` carrying `partition`, `service`,
  `resource_type`, `identifier` of each MatchKey.
- `str(MatchKey)` is NEVER parsed back. It feeds `Finding.dedup_key` and the SARIF
  fingerprint, and it is not injectively parseable anyway (unescaped ':'); a durable
  on-disk format must not inherit a presentation format (see `_to_fact`, ШАГ 5).
- CLI order is read -> correlate -> write. Reading after writing would let a run read
  its own fresh facts and mask an empty history.
- Ghost node = a MatchKey present only in history, absent from this run's input.
  It joins clusters as an ordinary node; see "Transitivity: direct facts only" for
  what that does and does not say about confidence.
- A ghost node participates in `representative(cluster)` on equal terms, so the console
  may name a key absent from this run's input. Intended: the representative is a
  property of the cluster, and the cluster includes history.
- Historical facts are filtered on read: `stale` (already stamped by `all(now=)`) and
  `method="llm"` are excluded from Union-Find. No clamping and no unknown-method
  branch: `put()` enforces `MAX_CONFIDENCE` and rejects methods absent from TTL policy.
- `ASCC_NOW` (RFC3339) overrides the clock. Required: `observed_together`, the only
  live bridge method, has a 7-day TTL, so a committed history fixture would expire and
  break CI with no code change. `facts.jsonl` is never committed as a golden file;
  tests build history via `repo.put(..., now=frozen)`.
- DoD: with a populated store, the second run's `CorrelationRun.clusters` contain a
  ghost key. "Correlation output" above means exactly that — measured 2026-09-13,
  `to_sarif` reads no cluster state, so SARIF bytes are unchanged and exposure is
  ШАГ 7. `test_store_flag_is_output_neutral` stays green unchanged.
"""

BACKLOG_BLOCK = """
- ШАГ 7: expose cluster membership in SARIF via `properties`, never in `fingerprint()` —
  the fingerprint is defined over `resource_ids` and must not change when history is
  attached, or downstream dedup (Code Scanning, DefectDojo) sees every finding as new.
- Cross-reference ASCC_NOW from ## Determinism and "str(MatchKey) is never parsed" from
  ## Contracts once ШАГ 6 lands — step-local today, global after.
- Line 216 states `effective = resolution.confidence * PRODUCT(bridge.confidence)` over
  every link crossed, which "Transitivity: direct facts only" forbids and the code does
  not implement (single `direct_confidence`). Reconcile: fix the formula or widen the
  invariant — decide, do not leave both.
"""


def find_anchor(rows, anchor):
    for i, row in enumerate(rows):
        if row.strip() == anchor:
            return i
    raise SystemExit(f"PRE: anchor not found: {anchor!r}")


def insert_at_section_end(rows, anchor, block):
    start = find_anchor(rows, anchor)
    end = len(rows)
    for j in range(start + 1, len(rows)):
        if rows[j].startswith("## "):
            end = j
            break
    while end > start + 1 and rows[end - 1].strip() == "":
        end -= 1
    return rows[:end] + [block.lstrip("\n")] + rows[end:]


lines = insert_at_section_end(lines, anchor_backlog, BACKLOG_BLOCK)
lines = insert_at_section_end(lines, anchor_store, STORE_BLOCK)

fd, tmp = tempfile.mkstemp(dir=str(path.parent))
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write("".join(lines))
os.replace(tmp, path)
print("insert: python done")
PY

# --- postconditions --------------------------------------------------------
AFTER=$(wc -l < "$F")
(( AFTER > BEFORE ))                          || { echo "POST: no growth"; exit 1; }
[[ $(grep -cF "$MARK_STORE"   "$F") -eq 1 ]]  || { echo "POST: store marker not unique"; exit 1; }
[[ $(grep -cF "$MARK_BACKLOG" "$F") -eq 1 ]]  || { echo "POST: backlog marker not unique"; exit 1; }
DEL=$(git diff --numstat -- "$F" | awk '{print $2}')
[[ "${DEL:-0}" -eq 0 ]]                       || { echo "POST: $DEL deletions — ABORT"; exit 1; }
echo "OK: +$((AFTER - BEFORE)) lines, 0 deletions"
