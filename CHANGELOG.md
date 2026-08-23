# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [0.1.0-rc] — 2026-08-22

### Added
- Scanner parsers for Trivy, Prowler and Checkov behind a `sniff()` dispatch registry.
- Resource-centric identity resolution with confidence tiers and a Union-Find identity bridge.
- SARIF 2.1.0 export: `to_sarif(run)` as a pure function with deterministic `results[]` ordering.
- CLI flag `--output PATH` with atomic write (`os.replace`) and an explicit exit-code contract.
- Byte-level determinism guarantees, pinned by a golden baseline and a hash-seed matrix in CI.