# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [0.1.0] — 2026-09-15

### Added

- Fact store (`ascc.store`): `Fact` + `FactRepository` ABC with mandatory clock
  injection, `InMemoryFactRepository`, and `JsonlFactRepository` (append-only
  JSONL, payload schema v1). stdlib-only — no database driver imports.
- Per-method TTL policy: expiry marks a fact stale and never deletes it, so
  provenance survives. Method / max-confidence / TTL / volatility table is in
  CLAUDE.md.
- `--store PATH`: persists bridge facts and replays them into later runs.
  Output-neutral by contract — SARIF bytes are identical with and without the
  flag. A store-only write failure exits INTERNAL (70) rather than warning.
- Cross-run identity resolution: cluster keys carried in from prior runs but
  absent from the current input are surfaced as ghost members instead of being
  silently dropped.
- SARIF export exposes cluster and ghost membership as
  `properties.cluster_members` / `properties.ghost_members`; both are omitted
  when empty and never materialise as extra `results[]` entries.
- Store reads degrade instead of failing: malformed endpoint records are
  dropped and an unreadable store emits a warning, leaving correlation intact.

### Fixed

- CLI failure paths are printed literally instead of being parsed as Rich
  markup. Paths containing bracketed segments previously produced truncated
  output or a MarkupError.

### Internal

- CI skips the `core.hooksPath` invariant — it guards a working copy, not a
  fresh checkout.
- Documentation guard allows one class name that appears only as a cited case
  study.
- Removed two stray trailing lines from `scripts/claude-md-step6.sh`.

## [0.1.0-rc] — 2026-08-23

### Added

- Scanner parsers for Trivy, Prowler and Checkov behind a `sniff()` dispatch registry.
- Resource-centric identity resolution with confidence tiers and a Union-Find identity bridge.
- SARIF 2.1.0 export: `to_sarif(run)` as a pure function with deterministic `results[]` ordering.
- CLI flag `--output PATH` with atomic write (`os.replace`) and an explicit exit-code contract.
- Byte-level determinism guarantees, pinned by a golden baseline and a hash-seed matrix in CI.
