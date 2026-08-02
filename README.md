# ASCC — AI Security Command Center

[![CI](https://github.com/iconexx-bit/ascc/actions/workflows/ci.yml/badge.svg)](https://github.com/iconexx-bit/ascc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

AI-powered correlation layer over cloud infrastructure security scanners
(Trivy, Prowler, Checkov). **Not another scanner** — a reasoning layer that
normalizes findings from multiple tools into a resource-centric schema and
surfaces correlated risk that no single scanner sees on its own.

## The problem

Three scanners look at the same AWS account and describe the same resource
three different ways:

| Scanner | How it names the S3 bucket |
|---|---|
| Prowler | `arn:aws:s3:::datalake-raw` |
| Checkov | `aws_s3_bucket.datalake_raw` |
| Trivy | `datalake-raw` |

Dump all three into one report and you get 16 findings across 3 tools with
no idea which ones describe the same thing. ASCC resolves identity first,
then reasons over what remains.

## Confidence, not certainty

Identity resolution is not always deterministic. ASCC never hides that —
every resolution carries its confidence and the method that produced it:
rule_id conf resource method
CVE-2021-44228 0.5 aws:ec2:instance:datalake-etl filesystem_path_heuristic
CVE-2022-42889 0.5 aws:ec2:instance:datalake-etl filesystem_path_heuristic
CVE-2022-3602 0.5 aws:ec2:instance:datalake-etl filesystem_path_heuristic
CVE-2023-38545 0.5 aws:ec2:instance:datalake-etl filesystem_path_heuristic
AVD-AWS-0028 1.0 aws:s3:bucket:datalake-raw terraform_natural_name
AVD-AWS-0107 0.4 aws:ec2:security-group:datalake-etl-sg terraform_generated_id_unbridged
- **1.0** — deterministic. An ARN and a Terraform address for a bucket
  provably describe the same resource.
- **0.5** — heuristic. A filesystem scan of `/opt/datalake-etl` probably
  refers to the host named `datalake-etl`. Probably.
- **0.4** — unbridged. `aws_instance.datalake_etl` and
  `i-0a1b2c3d4e5f67890` cannot be collapsed by string normalization.
  Merging them anyway would be a guess dressed as a fact.

A correlation engine that treats all three the same produces confident
nonsense. Contract tests actively guard the low-confidence cases against
being "fixed" by more aggressive normalization.

## Architecture
ingest -> schema -> store -> correlate -> export
- Resource-centric normalized schema — the resource is primary,
  findings attach to it (many-to-many)
- PostgreSQL + pgvector for storage and semantic correlation
- SARIF as an export-only target (CI/CD and IDE integration),
  never as the internal model
- Scanner parsers are isolated: `correlate/` and `schema/` know
  nothing about Trivy, Prowler, or Checkov

## Status

Early development.

| Component | State |
|---|---|
| `schema/` | Identity resolution with provenance |
| `ingest/` | Trivy |
| `store/` | planned |
| `correlate/` | planned |
| `export/` | planned |

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

## Development

```bash
uv run pytest tests/ -q      # tests
uv run ruff check src/       # lint
```

Test fixtures live in `fixtures/leaky_data_lake/` — a synthetic AWS
scenario where a public, unencrypted, PII-tagged S3 bucket is reachable
through an over-privileged IAM role attached to an internet-exposed EC2
instance carrying a critical RCE. Three scanners see fragments of it;
none sees the chain.

See [RUNBOOK.md](RUNBOOK.md) for network/offline setup details.

## License

MIT
