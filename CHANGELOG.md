# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added

- Attack graph and chains (`ascc.correlate.graph`): nodes are identity
  clusters; edges come only from scanner data (`exposes`, `assumes`,
  `can_access`), each with a method and a confidence; a chain runs from a
  network-exposed entry to a node tagged `DataClassification`, and its
  confidence is the product of its edges.
- SARIF: chains in `runs[0].properties.chains`, graph totals in
  `runs[0].properties.graph_stats`; `results[]` is unchanged. The CLI prints
  `Attack chains: N (longest H hops, confidence C)`.

### Documentation

- README: the chain demo on `leaky_data_lake`, with per-hop provenance;
  every number in it is checked against the golden SARIF by
  `tests/test_readme_demo.py`.

## [0.1.1] — 2026-10-26

### Fixed

- Store: a record whose format version `"v"` is present and is not `1` is
  refused with `StoreFormatError` instead of being read as v1. A record
  without `"v"` still reads as v1.
- Store: a corrupt line other than the last one raises `StoreFormatError`
  instead of a bare `JSONDecodeError`. Through the CLI it surfaced as an
  uncaught exception with exit status 1 — the code reserved for findings.
- CLI: a `--store` refused for format reasons exits INTERNAL (70) before
  correlation and writes nothing (no SARIF, no appended lines). An unreadable
  store (I/O error) still degrades to no history.
- Store: the put that creates the store file also fsyncs the directory entries
  it created: the file's creation is made durable, not only its contents.

### Changed

- Development tools moved from the `dev` extra to the PEP 735 dependency group
  `dev`, installed by a plain `uv sync`; `--extra dev` is gone.
- uv is pinned to 0.13.5 (`[tool.uv] required-version` in `pyproject.toml`) for
  local work and CI.
- CI tests Python 3.11 (the `requires-python` floor) and 3.12; the README badge
  names the tested versions.

### Security

- Workflow actions are pinned to full commit SHAs and kept current by weekly
  Dependabot version updates.
- `actions/checkout` no longer persists credentials in `.git`.
- `GITHUB_TOKEN` is read-only in the CI workflow; only CodeQL holds a write
  scope (`security-events`).
- Dropped the unused `pre-commit` dev dependency and its transitive packages.
- Repository rulesets (GitHub settings, not part of the source tree): `main`
  takes changes only through a pull request with five required checks and
  signed commits; `v*` tags cannot be moved or deleted.

### Internal

- SARIF output is validated against the official 2.1.0 schema in CI.
- Commit Lint checks the pull request's own commits; free-form kebab-case scope.
- CLAUDE.md contract anchors are checked by a test instead of a deletion guard.
- Release gate: `tests/test_release.py` keeps CHANGELOG, `uv.lock` and the
  README roadmap in step with the version in `pyproject.toml`.

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
