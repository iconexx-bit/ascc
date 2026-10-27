# The Leaky Data Lake, contained — fixture scenario

The three scanner files are `fixtures/leaky_data_lake/` byte for byte
(`tests/test_clab.py` checks it). The fourth file, `clab.sarif.json`, is the
output of a live run of the containment lab
([iconexx-bit/ai-agent-containment-lab](https://github.com/iconexx-bit/ai-agent-containment-lab)),
not hand-written:

| | |
|---|---|
| lab commit | `4dcf8f5` (`integrations/ascc/emit.sh`, contract `schemas/clab.v1.json`) |
| run | `artifacts/20261027T050821Z`, probe `ts` 2026-10-27T05:08:35Z, probe sha256 `18b74eb6d37c…` |
| TTC | `docs/evidence/d6-run3-ttc.json` (sha256 `07b14be1b05f…`): median 1598 ms, n=5 |
| verdict | PASS, 6 of 6 controls `pass` |
| file sha256 | `93d2c6e9d33495e4773b2c1d6b789de13182a864fd7d752925bfa3e819a40b86` |

**The binding is declared, not observed.** The lab range is a local Docker
range on one VM. The operator declared the ETL instance of this fixture,
`arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f67890`, as the host
the agent runs on (`binding.method: operator_declared`, confidence 0.5). The
file shows where runtime containment evidence lands in the graph, not that this
instance was tested.
