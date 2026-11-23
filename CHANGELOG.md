# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added

- `fixtures/leaky_data_lake_real/`: real output of Prowler 5.46.0, Trivy
  0.76.1 and Checkov 3.3.30 from an AWS run of the Leaky Data Lake scenario,
  sanitised and trimmed; its README says what was replaced and what was kept.
  Checked by `tests/test_real_fixture.py`.
- `tests/test_repo_hygiene.py`: no tracked file, file names included, may
  carry an AWS account ID other than the documented placeholders or a home
  directory other than `/home/user`. `tests/data/synthetic.sarif.json` now
  uses `/home/user`.

### Fixed

- `ascc correlate`: a recognised scanner file that its parser cannot read
  exited with an uncaught traceback and code 1, the code reserved for
  findings. It now exits 70 (`INTERNAL`) with the file and scanner named on
  stderr, and writes no SARIF and no store.
  Checked by `tests/test_cli_parse_errors.py`.
- `ascc correlate`: an input file that is not valid UTF-8 exited with an
  uncaught traceback and code 1. It is now skipped with `not valid JSON`, like
  any file that is not valid JSON. A file that cannot be read, or whose scanner
  cannot be told apart (two parsers match it), exits 70 (`INTERNAL`) with the
  file named on stderr, and writes no SARIF and no store.
  Checked by `tests/test_cli_input_files.py`.
- `ascc correlate`: JSON nested deeper than the interpreter can parse exited
  with a traceback and code 1; it is now skipped with `not valid JSON`. The
  Checkov, Prowler and Trivy parsers read their file as UTF-8 whatever the
  locale; under an ASCII locale, valid output with non-ASCII text exited 70.
  Checked by `tests/test_cli_input_files.py`.
- Prowler: current OCSF output, where `finding_info.created_time` is epoch
  seconds, is read; it stopped every run with exit 70 (`TypeError`). The ISO
  8601 string of older output still works; both give an aware UTC start time.
  Checked by `tests/test_prowler_real_output.py`.
- Severity the scanner did not give: open-source Checkov output
  (`severity: null`) stopped every run with exit 70 (`AttributeError`); the
  Trivy string `UNKNOWN` and OCSF `severity_id` 0 became INFO. All of them,
  and any value ASCC does not recognise, are now `unknown`: the SARIF result
  is `warning` and the rule carries `ascc/severity: unknown` and no
  `security-severity`. Checked by `tests/test_severity_unknown.py`.
- Checkov: open-source output leaves `resource_address` null, so no Checkov
  finding was tied to a resource and Checkov correlated with no other
  scanner. The Terraform address now comes from `resource` when
  `resource_address` is null, and `ascc correlate` prints
  `Findings tied to no resource: N (...)` for findings that still resolve to
  none. Checked by `tests/test_checkov_real_output.py`.
- Attack graph: on current Prowler OCSF output it drew no edge and no chain,
  without a trace: the edge facts sit under `resources[].data.metadata`, the
  inline policy is a resource of its own and tags are `[{Key, Value}]`. Both
  layouts are read now, two current entry check IDs have a category, and on
  `fixtures/leaky_data_lake_real` the graph finds one chain, security group ->
  instance -> role -> bucket (3 hops, confidence 0.6). A managed `*/*` policy
  draws no edge. `graph_stats.unread_edge_sources` counts resources whose
  edge fields are absent in every known layout. Checked by
  `tests/test_graph_real_output.py`.
- Trivy: current output reports misconfigurations as `AWS-NNNN` without
  `AVDID`, and every one became `uncategorized`, so the open SSH rule was not
  an entry to an attack chain. The category lookup now ignores the `AVD-`
  prefix; `rule_id` is kept as the scanner gave it. Checked by
  `tests/test_trivy_real_output.py`.
- Tests: the CLI console width is pinned for every test (`tests/conftest.py`),
  so tests that assert on printed lines no longer depend on the terminal they
  run in. Checked by `tests/test_console_width.py`.

### Documentation

- README roadmap: AWS-signed binding for runtime evidence (EC2 instance
  identity document, signature verified offline) in place of
  `operator_declared`; the runtime-evidence section links to it. Checked by
  `tests/test_readme_roadmap.py`.

## [0.3.0] — 2026-10-28

### Added

- Runtime evidence from the containment lab: a SARIF log with
  `run.properties.schema` `clab/v1` (emitted by
  [ai-agent-containment-lab](https://github.com/iconexx-bit/ai-agent-containment-lab))
  is ingested as scanner `clab`. A failed control becomes a finding
  (category `containment`) with `properties.binding`; a verified or
  not-verified control becomes evidence on the graph node of the declared
  resource (`chains[].nodes[].evidence`, `graph_stats.evidence`). Evidence adds
  no result and changes no chain.
- The binding to a resource is declared by the operator, not observed:
  method `operator_declared`, confidence 0.5, said in every output. A lab file
  that breaks the contract is refused (exit 70, nothing written).
- Fixture `fixtures/leaky_data_lake_contained/`: the three scanner files plus
  the output of a live lab run (2026-10-27).

### Documentation

- README: "Runtime evidence: was the agent contained?" shows the lab's six
  controls on the chain's instance node; every row, count and claim is checked
  against the contained golden SARIF by `tests/test_readme_evidence.py`. The
  confidence table lists `operator_declared`.

### Fixed

- SARIF `$schema` now names the OASIS errata01 schema
  (`https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`).
  The previous URI (`raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/...`) no longer
  resolves: the path was removed upstream on 2024-05-02. Only that line of the output changes.

## [0.2.0] — 2026-10-27

### Added

- Attack graph and chains (`ascc.correlate.graph`): nodes are identity
  clusters; edges come only from scanner data (`exposes`, `assumes`,
  `can_access`), each with a method and a confidence; a chain runs from a
  network-exposed entry to a node tagged `DataClassification`, and its
  confidence is the product of its edges.
- SARIF: chains in `runs[0].properties.chains`, graph totals in
  `runs[0].properties.graph_stats`; no result is added for a chain. The CLI
  prints `Attack chains: N (longest H hops, confidence C)`.
- SARIF: a result on a chain node carries `properties.chain_ids` (sorted).
  Result count, order and `partialFingerprints` are unchanged.

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
