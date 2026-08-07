# ASCC — AI Security Command Center

[![CI](https://github.com/iconexx-bit/ascc/actions/workflows/ci.yml/badge.svg)](https://github.com/iconexx-bit/ascc/actions/workflows/ci.yml)
[![CodeQL](https://github.com/iconexx-bit/ascc/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/iconexx-bit/ascc/actions/workflows/codeql-analysis.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

ASCC is a correlation and reasoning layer over cloud infrastructure security tooling — it never talks to a cloud API itself, and every fact it works with already came from Trivy, Prowler, or Checkov.

## The problem

Trivy scans the filesystem of a production host at `/opt/datalake-etl` and reports a critical Log4Shell RCE (`CVE-2021-44228`). Prowler scans the AWS account and reports that EC2 instance `i-0a1b2c3d4e5f67890` has a public IP address. Read separately, these are two moderate findings. They are actually the same host — a vulnerable service directly reachable from the internet — but neither tool says so: Trivy never saw a cloud instance ID, Prowler never looked inside the filesystem. ASCC resolves identity first, then reasons over what remains.

## Seeing it work

```
$ ascc correlate --input fixtures/leaky_data_lake/
Read 3 file(s) (checkov, prowler, trivy), skipped 1
Skipping README.md: not valid JSON
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
                                                                               Clusters                                                                                
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Representative                              ┃ Left                                   ┃ Right                                       ┃ Method            ┃ Confidence ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ aws:ec2:security-group:sg-0f9e8d7c6b5a43210 │ aws:ec2:security-group:datalake-etl-sg │ aws:ec2:security-group:sg-0f9e8d7c6b5a43210 │ observed_together │ 0.95       │
│ aws:ec2:instance:i-0a1b2c3d4e5f67890        │ aws:ec2:instance:datalake-etl          │ aws:ec2:instance:i-0a1b2c3d4e5f67890        │ observed_together │ 0.95       │
└─────────────────────────────────────────────┴────────────────────────────────────────┴─────────────────────────────────────────────┴───────────────────┴────────────┘
                                                                    Findings                                                                     
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Finding                                                          ┃ Resource                                    ┃ Confidence                   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ checkov:CKV_AWS_20                                               │ aws:s3:bucket:datalake-raw                  │ 1.000                        │
│ checkov:CKV_AWS_19                                               │ aws:s3:bucket:datalake-raw                  │ 1.000                        │
│ checkov:CKV_AWS_18                                               │ aws:s3:bucket:datalake-raw                  │ 1.000                        │
│ checkov:CKV_AWS_40                                               │ aws:iam:role:datalake-etl-role              │ 1.000                        │
│ prowler:s3_bucket_level_public_access_block                      │ aws:s3:bucket:datalake-raw                  │ 1.000                        │
│ prowler:s3_bucket_default_encryption                             │ aws:s3:bucket:datalake-raw                  │ 1.000                        │
│ prowler:s3_bucket_server_access_logging_enabled                  │ aws:s3:bucket:datalake-raw                  │ 1.000                        │
│ prowler:iam_inline_policy_no_administrative_privileges           │ aws:iam:role:datalake-etl-role              │ 1.000                        │
│ prowler:ec2_securitygroup_allow_ingress_from_internet_to_port_22 │ aws:ec2:security-group:sg-0f9e8d7c6b5a43210 │ 1.000                        │
│ prowler:ec2_securitygroup_allow_ingress_from_internet_to_port_22 │ aws:ec2:security-group:datalake-etl-sg      │ 0.950 = 1.000 x 0.950 bridge │
│ prowler:ec2_instance_public_ip                                   │ aws:ec2:instance:i-0a1b2c3d4e5f67890        │ 1.000                        │
│ prowler:ec2_instance_public_ip                                   │ aws:ec2:instance:datalake-etl               │ 0.950 = 1.000 x 0.950 bridge │
│ trivy:CVE-2021-44228                                             │ aws:ec2:instance:datalake-etl               │ 0.500                        │
│ trivy:CVE-2021-44228                                             │ aws:ec2:instance:i-0a1b2c3d4e5f67890        │ 0.475 = 0.500 x 0.950 bridge │
│ trivy:CVE-2022-42889                                             │ aws:ec2:instance:datalake-etl               │ 0.500                        │
│ trivy:CVE-2022-42889                                             │ aws:ec2:instance:i-0a1b2c3d4e5f67890        │ 0.475 = 0.500 x 0.950 bridge │
│ trivy:CVE-2022-3602                                              │ aws:ec2:instance:datalake-etl               │ 0.500                        │
│ trivy:CVE-2022-3602                                              │ aws:ec2:instance:i-0a1b2c3d4e5f67890        │ 0.475 = 0.500 x 0.950 bridge │
│ trivy:CVE-2023-38545                                             │ aws:ec2:instance:datalake-etl               │ 0.500                        │
│ trivy:CVE-2023-38545                                             │ aws:ec2:instance:i-0a1b2c3d4e5f67890        │ 0.475 = 0.500 x 0.950 bridge │
│ trivy:AVD-AWS-0028                                               │ aws:s3:bucket:datalake-raw                  │ 1.000                        │
│ trivy:AVD-AWS-0107                                               │ aws:ec2:security-group:datalake-etl-sg      │ 0.400                        │
│ trivy:AVD-AWS-0107                                               │ aws:ec2:security-group:sg-0f9e8d7c6b5a43210 │ 0.380 = 0.400 x 0.950 bridge │
└──────────────────────────────────────────────────────────────────┴─────────────────────────────────────────────┴──────────────────────────────┘
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
ingest -> schema -> [store] -> correlate -> [export]
(bracketed stages are not built yet)
```
- Resource-centric normalized schema — the resource is primary,
  findings attach to it (many-to-many)
- Scanner parsers are isolated: `correlate/` and `schema/` know
  nothing about Trivy, Prowler, or Checkov

**Planned**
- PostgreSQL + pgvector will be used for storage and semantic
  correlation
- SARIF is intended as an export-only target (CI/CD and IDE
  integration), never as the internal model

## Status

| Component | State |
|---|---|
| `schema/` | Identity resolution with provenance (`MatchKey`, `resolve()`), cluster bridging (`BridgeFact`, `ResourceCluster`) |
| `ingest/` | Trivy, Prowler, Checkov parsers behind a common `ScannerParser` interface, plus a `sniff()`-based registry dispatcher |
| `store/` | not started (PostgreSQL + pgvector planned) |
| `correlate/` | `IdentityBridge` (clustering) + `CorrelationRun` (tag-conflict resolution, `effective_confidence()`) |
| `export/` | not started (SARIF planned) |

10 test modules; CI runs lint, format check, and tests, plus a
separate `secrets-scan` job (gitleaks); pre-commit hooks
(`.pre-commit-config.yaml`) run ruff and gitleaks locally.

## Installation

```bash
git clone https://github.com/iconexx-bit/ascc.git
cd ascc
uv sync --extra dev
```

## Usage

```bash
ascc correlate --input <path-to-scanner-output-dir>
```

## Commit Convention

We use Conventional Commits.

After cloning, enable the template:
```bash
git config commit.template .gitmessage
```

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
