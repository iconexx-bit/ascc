# Leaky Data Lake: real scanner output

Real output of three scanners from run 2 of the AWS spike on 2026-10-30,
sanitised and trimmed. The spike built the Leaky Data Lake scenario with
Terraform in a lab AWS account, region `us-east-2`, and scanned it with:

- Prowler 5.46.0, the live account, OCSF JSON (`prowler.json`);
- Trivy 0.76.1, `trivy config` on the Terraform plan (`trivy-config.json`)
  and `trivy rootfs` on the EC2 instance (`trivy-rootfs.json`);
- Checkov 3.3.30, the Terraform module (`checkov.json`).

The synthetic fixture next to this one, `fixtures/leaky_data_lake/`, is what
the README demo and the golden tests use. This directory is real output for
the parsers to be tested against.

## What was replaced

In every file:

- The lab account ID is `123456789012`, a placeholder from the AWS
  documentation.
- The home directory of the machine that ran the scans is `/home/user`.
- Prowler names its output after the account and the time of the run; the
  file is `prowler.json` here.

## What was kept

Records are kept whole and in their original order; only whole records were
dropped.

- `prowler.json`: the 48 FAIL findings of the run and its first 3 PASS
  findings.
- `trivy-rootfs.json`: the first 3 packages of the package list; the scan
  found no vulnerabilities.
- `checkov.json` (22 failed and 24 passed checks) and `trivy-config.json`
  (5 misconfigurations): whole.

Each file keeps the layout its tool writes: indentation, key order, and
Trivy's escaping of `&`, `<` and `>` as `&`, `<` and `>`.

## Source files

SHA-256 of the files this fixture was built from: the run's share archive,
in which the account ID had already been replaced by `<account>`.

| File | SHA-256 |
|---|---|
| Prowler OCSF output | `2e1c4dd34dd0c8787019fbf27beb653d93b5c586c6dc4a8e0bdc95186c2faf9a` |
| `trivy-config.json` | `51f7fd5bd4ffbe790849c5872584db88cc791b48829918be5b27c9e52be51ae2` |
| `trivy-rootfs.json` | `cd214da7911b9087593cd1d65786a5a6d9c85653addfd60e354cfc35938653f5` |
| `checkov.json` | `1fb07e3106669fb80d064192732e7019599c715fe55a6cc37159214478bb28ef` |
