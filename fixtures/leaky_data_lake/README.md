# The Leaky Data Lake — fixture scenario

Hand-written, synthetic input for ASCC's tests and the README demo. It is not
the output of a real scan.

## What the fixture is

- `trivy.json`, `prowler.json`, `checkov.json`: 16 findings from 3 scanners
  (Trivy 6, Prowler 6, Checkov 4) about four resources in one AWS account.
- Every value (ARNs, resource IDs, finding IDs, CVEs, descriptions) is
  invented. The account ID `123456789012` is the placeholder AWS uses in its
  documentation.
- The field layout follows what ASCC's parsers read when the fixture was
  written. It is not a verified copy of real scanner output; the next section
  lists where it differs.

## How close it is to real scanner output

Compared field by field with one run against a real AWS account on
2026-10-30: Prowler version 5.46.0 (OCSF 1.5.0), Checkov version 3.3.30,
Trivy version 0.76.1. "Field" means a JSON path, with list positions
collapsed.

| Scanner | Fields in the fixture | Also in real output | What differs |
|---|---|---|---|
| Prowler | 52 | 36 | Resource attributes: the fixture keeps them flat in `resources[].data` (`security_groups`, `iam_instance_profile_arn`, `public_ip`, `inline_policy_actions`, `inline_policy_resources`, `ip_permissions`, `acl`, `public_access_block`, `server_side_encryption`, `logging_enabled`) and tags in `resources[].tags[]`; real output nests them under `resources[].data.metadata` with other names (for example `ingress_rules`, `inline_policies`, `encryption`, `logging`, `tags`). `finding_info.product_uid` and `compliance.status` are absent. `finding_info.created_time` is a string in the fixture and an integer in real output. |
| Checkov | 21 | 21 | Same paths, but `severity` and `resource_address` are `null` in all 22 real failed checks. |
| Trivy | 50 | 28 | `Misconfigurations[].AVDID` and `MisconfSummary.Exceptions` are absent. The 20 vulnerability fields cannot be compared: the real filesystem scan found no CVEs. |

What this means for the demo: every current parser reads the real output in
`fixtures/leaky_data_lake_real/`. Parsers that still stop on real output:
none. Checkov's `null` severity is reported as unknown. Its
`resource_address` is empty, so the Terraform address comes from `resource`:
11 of 22 real Checkov findings resolve to a resource; the rest sit on
Terraform types ASCC does not map yet, and the CLI counts them. The graph
found none of the Prowler resource attributes it builds edges from and
drew no edges. The demo shows what ASCC does with input laid out like this
fixture, not yet what it does with current scanner output. A graph that reads
real output is planned for v0.4.0; this section goes away when a test pins
every fixture field to real output.

## Scenario

One AWS account (`123456789012`, `us-east-1`), four related resources:

| Resource | Terraform address | Cloud identifier |
|---|---|---|
| S3 bucket with raw data | `aws_s3_bucket.datalake_raw` | `arn:aws:s3:::datalake-raw` |
| EC2 ETL host | `aws_instance.datalake_etl` | `arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f67890` |
| IAM role of the ETL host | `aws_iam_role.datalake_etl_role` | `arn:aws:iam::123456789012:role/datalake-etl-role` |
| Security group of the ETL host | `aws_security_group.datalake_etl_sg` | `arn:aws:ec2:us-east-1:123456789012:security-group/sg-0f9e8d7c6b5a43210` |

The story: the security group opens port 22 to `0.0.0.0/0`; the EC2 instance
`datalake-etl` behind it is publicly reachable and carries a critical RCE
(Log4Shell, `CVE-2021-44228`); the instance assumes the IAM role
`datalake-etl-role`, whose inline policy allows `Action: *` on `Resource: *`;
that role can reach the S3 bucket `datalake-raw`, which is publicly readable,
unencrypted, has no access logging and is tagged `DataClassification=PII`.

## Who reports what

| Resource | Trivy | Prowler | Checkov |
|---|---|---|---|
| S3 bucket `datalake-raw` | 1 misconfiguration: no encryption (`AVD-AWS-0028`) | 3: public access, no default encryption, no access logging | 3: `CKV_AWS_20`, `CKV_AWS_19`, `CKV_AWS_18` |
| EC2 `datalake-etl` | 4 CVEs in installed packages, including the critical Log4Shell | 1: public IP | — |
| IAM role `datalake-etl-role` | — | 1: administrative inline policy | 1: `CKV_AWS_40` |
| Security group `datalake-etl-sg` | 1 misconfiguration: ingress `0.0.0.0/0` to port 22 (`AVD-AWS-0107`) | 1: SSH open to the internet | — |

16 findings: Trivy 6, Prowler 6, Checkov 4. Each resource is reported by at
least two scanners, under different identifiers (ARN, Terraform address,
resource name) — the material identity resolution works on.

## What ASCC derives from it

The [README demo](../../README.md#from-findings-to-an-attack-chain) shows the
output; `tests/test_readme_demo.py` checks that the README matches the code.
In short:

- Two identity bridges (`observed_together`, confidence 0.95) join Trivy's
  names for the instance and the security group with Prowler's IDs.
- The funnel: **16 findings → 6 resource keys → 4 graph nodes → 1 chain of 3 hops.**
- The chain runs security group → instance → role → bucket, confidence 0.6.
  All three edges come from Prowler data; Trivy and Checkov add findings on
  the chain's nodes, not edges.

## Deliberate limits

- The instance → role edge (`profile_role_name`, confidence 0.6) is a
  heuristic: it holds here because the fixture names the instance profile
  after the role.
- The role → bucket edge comes from a wildcard inline policy; bucket policy,
  permissions boundary, RCPs and SCPs are not observed and are listed as such
  on the edge.
