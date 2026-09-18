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

Two scanners named the same host differently. ASCC found one bridge fact:

**Clusters**

| Left | Right | Method | Confidence |
|---|---|---|---|
| `aws:ec2:instance:datalake-etl` | `aws:ec2:instance:i-0a1b2c3d4e5f67890` | `observed_together` | 0.95 |
| `aws:ec2:security-group:datalake-etl-sg` | `aws:ec2:security-group:sg-0f9e8d7c6b5a43210` | `observed_together` | 0.95 |

`observed_together` is observational, not deterministic — it earns 0.95, not 1.0, and
it expires (7-day TTL, run-bound). The confidence describes the *bridge*, not the
finding. What that bridge does to the findings:

**Findings**

| Finding | Resource | Confidence |
|---|---|---|
| `prowler:ec2_instance_public_ip` | `aws:ec2:instance:i-0a1b2c3d4e5f67890` | 1.000 |
| `prowler:ec2_instance_public_ip` | `aws:ec2:instance:datalake-etl` | 0.950 = 1.000 × 0.950 bridge |
| `trivy:CVE-2021-44228` | `aws:ec2:instance:datalake-etl` | 0.500 |
| `trivy:CVE-2021-44228` | `aws:ec2:instance:i-0a1b2c3d4e5f67890` | **0.475 = 0.500 × 0.950 bridge** |

<sub>Reformatted from CLI output for width — raw terminal capture in <a href="docs/showcase.txt">docs/showcase.txt</a>.</sub>

Log4Shell arrived as a **0.500 claim about a filesystem**. Across one observational
bridge it is a **0.475 claim about a publicly-reachable EC2 instance** — and the
arithmetic is printed, not hidden.

Neither key is destroyed. Merging would discard the losing one, and the next scan
that produces it would have nowhere to land.

## Determinism is a contract

- `results[]` sorted in product code by `(ruleId, resource_id, message)` — ordering is
  a feature, not a side effect of dict iteration
- `ASCC_LLM=off` ⇒ byte-identical SARIF except `message.markdown`, enforced in CI by
  running the pipeline twice and diffing
- Golden baseline lives in `tests/data/`; the normalizer is test-only, because product
  code sorts its own output
- No wall-clock field reaches the export. `ASCC_NOW` overrides the clock so time-
  dependent behaviour is testable without freezing real time
- An absent or empty `--store` produces byte-identical SARIF. A populated store
  legitimately changes correlation output — that is the feature, not a violation

## What the SARIF carries

One result per (rule, resource) — 16 for the reference fixture — deduplicated,
deterministically ordered, valid against SARIF 2.1.0.

- resource identity in `logicalLocations.fullyQualifiedName`
  (`aws:ec2:instance:i-0a1b2c3d4e5f67890`)
- cluster membership in `properties.cluster_members`
- a stable `partialFingerprints["asccDedupKey/v1"]`, defined over resource identities
  alone — attaching cross-run history does not re-key existing findings, so re-running
  updates alerts in Code Scanning or DefectDojo instead of duplicating them

Findings here are resource-centric, not file-centric: there is no `physicalLocation`,
so viewers that key on source files will index them but not render them inline.
Multiplied confidence is deliberately CLI-only in v0.1.0-rc; carrying it into
`properties` is scoped for v0.1.1.

## Inventory

The pre-bridge view — what each scanner reported on its own terms, before identity
resolution ran:

```
                                                            Resources
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Key                                         ┃ Refs ┃ Scanners                ┃ Tags                                           ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ aws:s3:bucket:datalake-raw                  │ 7    │ checkov, prowler, trivy │ DataClassification=PII, Environment=production │
│ aws:iam:role:datalake-etl-role              │ 2    │ checkov, prowler        │ Environment=production                         │
│ aws:ec2:security-group:sg-0f9e8d7c6b5a43210 │ 1    │ prowler                 │ Environment=production                         │
│ aws:ec2:instance:i-0a1b2c3d4e5f67890        │ 1    │ prowler                 │ Environment=production, Role=etl               │
│ aws:ec2:instance:datalake-etl               │ 4    │ trivy                   │                                                │
│ aws:ec2:security-group:datalake-etl-sg      │ 1    │ trivy                   │                                                │
└─────────────────────────────────────────────┴──────┴─────────────────────────┴────────────────────────────────────────────────┘
```

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
schema (shared vocabulary) + store (persistence, post-v0.1)
ingest -> correlate -> score -> [export]
```
- Resource-centric normalized schema — the resource is primary,
  findings attach to it (many-to-many)
- Scanner parsers are isolated: `correlate/` and `schema/` know
  nothing about Trivy, Prowler, or Checkov

**Planned**
- PostgreSQL + pgvector will eventually be used for storage and semantic
  correlation
- SARIF is intended as an export-only target (CI/CD and IDE
  integration), never as the internal model

## Status

| Component | State |
|---|---|
| `schema/` | Identity resolution with provenance (`MatchKey`, `resolve()`), cluster bridging (`BridgeFact`, `ResourceCluster`) |
| `ingest/` | Trivy, Prowler, Checkov parsers behind a common `ScannerParser` interface, plus a `sniff()`-based registry dispatcher |
| `store/` | not started (JSONL first, PostgreSQL + pgvector later) |
| `correlate/` | `build_clusters()` → `ResourceCluster` (Union-Find clustering, `bridge.py`) + `CorrelationRun` (tag-conflict resolution, `effective_confidence()`, `run.py`) |
| `export/` | `to_sarif()` — SARIF 2.1.0, deterministic result ordering, `--output PATH` with atomic write |

17 test modules; CI runs lint, format check, tests, and a determinism
matrix, plus a separate `secrets-scan` job (gitleaks); pre-commit hooks
(`.pre-commit-config.yaml`) run ruff and gitleaks locally.

## Roadmap

- `v0.1.1`: validation against the official SARIF 2.1.0 JSON schema;
  live golden regeneration from CLI output
- `store/`: JSONL first, then PostgreSQL + pgvector behind `FactRepository`

## Installation

```bash
git clone https://github.com/iconexx-bit/ascc.git
cd ascc
uv sync --extra dev

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
