# ASCC — AI Security Command Center

AI-powered correlation layer over cloud infrastructure security scanners
(Trivy, Prowler, Checkov). Not another scanner — a reasoning layer that
normalizes findings from multiple tools into a resource-centric schema and
surfaces correlated risk that no single scanner sees on its own.

## Status

Early development. Architecture decisions (schema, storage, export format)
are settled; correlation logic is being implemented.

## Architecture

- Resource-centric normalized schema
- PostgreSQL + pgvector for storage and semantic correlation
- SARIF as export-only target (for CI/CD and IDE integration)

## Installation

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows
pip install -e ".[dev]"
```

## Usage

```bash
ascc correlate --input <path-to-scanner-output-dir>
```

See [RUNBOOK.md](RUNBOOK.md) for network/offline setup details.

## License

MIT