# ASCC — AI Security Command Center

[![CI](https://github.com/iconexx-bit/ascc/actions/workflows/ci.yml/badge.svg)](https://github.com/iconexx-bit/ascc/actions/workflows/ci.yml)
[![CodeQL](https://github.com/iconexx-bit/ascc/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/iconexx-bit/ascc/actions/workflows/codeql-analysis.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

ASCC is a correlation and reasoning layer over cloud infrastructure security tooling — it never talks to a cloud API itself, and every fact it works with already came from Trivy, Prowler, or Checkov.

## The problem

Trivy scans the filesystem of a production host at `/opt/datalake-etl` and reports a critical Log4Shell RCE (`CVE-2021-44228`). Prowler scans the AWS account and reports that EC2 instance `i-0a1b2c3d4e5f67890` has a public IP address. Read separately, these are two moderate findings. They are actually the same host — a vulnerable service directly reachable from the internet — but neither tool says so: Trivy never saw a cloud instance ID, Prowler never looked inside the filesystem. ASCC resolves identity first, then reasons over what remains.

## Seeing it work

```console
$ uv run ascc correlate --input fixtures/leaky_data_lake/
Read 3 file(s) (checkov, prowler, trivy), skipped 1
Skipping README.md: not valid JSON
```

Two scanners named the same resources differently. ASCC found two bridge facts:

**Clusters** — both `observed_together` at **0.95**:

- **instance** — `datalake-etl` ↔ `i-0a1b2c3d4e5f67890`
- **security-group** — `datalake-etl-sg` ↔ `sg-0f9e8d7c6b5a43210`

<sub>Full keys are `aws:ec2:<type>:<name>` — raw capture in <a href="docs/showcase.txt">docs/showcase.txt</a>.</sub>

`observed_together` is observational, not deterministic — it earns 0.95, not 1.0, and
it expires (7-day TTL, run-bound). The confidence describes the *bridge*, not the
finding. What that bridge does to the findings:

**Findings** — the same bridge, applied in both directions:

- `prowler:ec2_instance_public_ip`
  - on `i-0a1b2c3d4e5f67890` — **1.000**
  - on `datalake-etl` — **0.950** = 1.000 × 0.950 bridge
- `trivy:CVE-2021-44228`
  - on `datalake-etl` — **0.500**
  - on `i-0a1b2c3d4e5f67890` — **0.475 = 0.500 × 0.950 bridge**

<sub>Reformatted from CLI output — raw terminal capture in <a href="docs/showcase.txt">docs/showcase.txt</a>.</sub>

Log4Shell arrived as a **0.500 claim about a filesystem**. Across one observational
bridge it is a **0.475 claim about a publicly-reachable EC2 instance** — and the
arithmetic is printed, not hidden.

Neither key is destroyed. Merging would discard the losing one, and the next scan
that produces it would have nowhere to land.

## Determinism is a contract

- `results[]` sorted in product code by `(ruleId, resource_id, message)` — ordering is
  a feature, not a side effect of dict iteration
- Byte-identical SARIF across `PYTHONHASHSEED` values: `tests/test_cli_determinism.py`
  drives the CLI as a subprocess and compares raw output bytes in CI; input files are
  read in sorted order
- Golden baseline lives in `tests/data/`; the normalizer is test-only, because product
  code sorts its own output
- No wall-clock field reaches the export. `ASCC_NOW` overrides the clock so time-
  dependent behaviour is testable without freezing real time
- An absent or empty `--store` produces byte-identical SARIF. A populated store
  legitimately changes correlation output — that is the feature, not a violation

## What the SARIF carries

One result per (rule, resource) — 16 for the reference fixture — deduplicated,
deterministically ordered, valid against the official SARIF 2.1.0 schema — checked in
CI for both the golden baseline and a live run (`tests/test_sarif_schema.py`).

- resource identity in `logicalLocations.fullyQualifiedName`
  (`aws:ec2:instance:i-0a1b2c3d4e5f67890`)
- cluster membership in `properties.cluster_members`
- a stable `partialFingerprints["asccDedupKey/v1"]`, defined over resource identities
  alone — attaching cross-run history does not re-key existing findings, so re-running
  updates alerts in Code Scanning or DefectDojo instead of duplicating them

Findings here are resource-centric, not file-centric: there is no `physicalLocation`,
so viewers that key on source files will index them but not render them inline.
Multiplied confidence is deliberately CLI-only for now; carrying it into
`properties` is planned.

## Inventory

The pre-bridge view — what each scanner reported on its own terms, before identity
resolution ran:

- `aws:s3:bucket:datalake-raw` — 7 refs · checkov, prowler, trivy · `DataClassification=PII`, `Environment=production`
- `aws:iam:role:datalake-etl-role` — 2 refs · checkov, prowler · `Environment=production`
- `aws:ec2:security-group:sg-0f9e8d7c6b5a43210` — 1 ref · prowler · `Environment=production`
- `aws:ec2:instance:i-0a1b2c3d4e5f67890` — 1 ref · prowler · `Environment=production`, `Role=etl`
- `aws:ec2:instance:datalake-etl` — 4 refs · trivy · no tags
- `aws:ec2:security-group:datalake-etl-sg` — 1 ref · trivy · no tags

<sub>Reformatted from CLI output — raw capture in <a href="docs/showcase.txt">docs/showcase.txt</a>.</sub>

## Confidence, not certainty

Identity resolution is not always deterministic, and bridging across scanners composes rather than replaces that uncertainty. ASCC never hides either: every resolution and every bridge fact carries its confidence and the method that produced it.

**Resolution tiers** — how a key was derived from a scanner's own reference:

| Confidence | Method | Meaning |
|---|---|---|
| 1.0 | `arn_parse` | ARN parsed directly — key is unambiguous |
| 1.0 | `terraform_natural_name` | The Terraform resource name is the same name used in the cloud |
| 0.5 | `filesystem_path_heuristic` | Path `/opt/datalake-etl` looks like a hostname — probably |
| 0.4 | `terraform_generated_id_unbridged` | Terraform name is known, the cloud-generated ID is not |

**Bridge confidence** — a separate axis, not another resolution tier:

| Confidence | Method | Meaning |
|---|---|---|
| 0.95 | `observed_together` | A scanner reported both identifiers in one observation record |

Effective confidence for a claim that crosses a bridge is the product of its resolution tier and the bridge, never the bridge alone: `0.5 × 0.95 = 0.475` — exactly the number in the Findings table above.

## Architecture
```
schema (shared vocabulary) + store (cross-run facts, JSONL)
ingest -> correlate -> [export]
```
- Resource-centric normalized schema — the resource is primary,
  findings attach to it (many-to-many)
- Scanner parsers are isolated: `correlate/` and `schema/` know
  nothing about Trivy, Prowler, or Checkov

**Planned**
- A `score` stage between correlate and export: deterministic risk score and MITRE
  ATT&CK mapping
- PostgreSQL + pgvector will eventually be used for storage and semantic
  correlation
- SARIF is intended as an export-only target (CI/CD and IDE
  integration), never as the internal model

## Status

| Component | State |
|---|---|
| `schema/` | Identity resolution with provenance (`MatchKey`, `resolve()`), cluster bridging (`BridgeFact`, `ResourceCluster`) |
| `ingest/` | Trivy, Prowler, Checkov parsers behind a common `ScannerParser` interface, plus a `sniff()`-based registry dispatcher |
| `store/` | `FactRepository` with in-memory and JSONL backends; TTL marks facts stale, never deletes; `--store PATH` adds cross-run cluster and ghost membership to SARIF |
| `correlate/` | `build_clusters()` → `ResourceCluster` (Union-Find clustering, `bridge.py`) + `CorrelationRun` (tag-conflict resolution, `effective_confidence()`, `run.py`) |
| `export/` | `to_sarif()` — SARIF 2.1.0, deterministic result ordering, `--output PATH` with atomic write |

CI runs lint, format check and tests (including byte-level determinism and SARIF
schema validation), plus a separate `secrets-scan` job (gitleaks). Locally, the git hook
in `.githooks/pre-commit` checks lock and venv drift and runs ruff; gitleaks runs only in CI.

## Roadmap

- `v0.1.1`: store format-version check on load; durable directory fsync
- Resource graph and attack-chain detection, exported in SARIF `properties`
- Deterministic risk score with MITRE ATT&CK mapping
- PostgreSQL backend behind `FactRepository`

## Installation

Requires uv 0.13.5: the version is pinned in `pyproject.toml`
(`[tool.uv] required-version`) and uv refuses to run under any other one
(`uv self update 0.13.5`).

```bash
git clone https://github.com/iconexx-bit/ascc.git
cd ascc
uv sync    # installs the default dependency group `dev` (pytest, ruff)

# Per-clone git config — git does not transfer local settings:
git config commit.template .gitmessage    # Conventional Commits template
git config core.hooksPath .githooks       # pre-commit: uv.lock / .venv drift check
```

Without `core.hooksPath`, the pre-commit hook sits in the tree and never runs.

## Usage

```bash
uv run ascc correlate --input <path-to-scanner-output-dir>
```

## Commit Convention

We use Conventional Commits. The message template is enabled in [Installation](#installation).

**Format**: `<type>(<scope>): <message>`

**Types**: feat | fix | docs | style | refactor | perf | test | chore | ci | security
**Scopes**: parser | graph | identity-resolution | scorer | retrieval | diff | merge | cli

**Examples**:
- `feat(parser): add checkov support`
- `fix(identity-resolution): handle multi-account collisions`
- `docs: update installation guide`
- `ci: integrate real-time scanning`

## Development

```bash
uv run pytest tests/ -q                          # tests
uv run ruff format --check src/ tests/           # formatting (CI check)
```

Test fixtures live in `fixtures/leaky_data_lake/` — a synthetic AWS
scenario where a public, unencrypted, PII-tagged S3 bucket is reachable
through an over-privileged IAM role attached to an internet-exposed EC2
instance carrying a critical RCE. Three scanners see fragments of it;
`ascc correlate` is what ties them together.

See [RUNBOOK.md](RUNBOOK.md) for network/offline setup details.

## License

MIT
