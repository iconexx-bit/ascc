# ASCC Network & Offline Runbook

Everything produced in this pass, in execution order.

---

## 1. Egress allow-list

### Tier 0 — minimum for `pip` to function at all

| Domain | Why | Break if missing |
|---|---|---|
| `pypi.org` | package index / metadata | resolution fails immediately |
| `files.pythonhosted.org` | the actual `.whl` and `.tar.gz` blobs | **metadata resolves, download 403s** — the classic half-open allow-list |

> The single most common allow-list mistake: opening `pypi.org` only.
> pip will happily resolve the dependency tree and then die on download.

### Tier 1 — source control

| Domain | Why |
|---|---|
| `github.com` | `git clone`, releases |
| `raw.githubusercontent.com` | raw files, install scripts |
| `codeload.github.com` | `pip install git+https://...` tarballs |
| `objects.githubusercontent.com` | release asset redirects |
| `api.github.com` | release metadata, rate-limit checks |

### Tier 2 — container + scanner supply chain (ASCC-specific)

| Domain | Why |
|---|---|
| `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` | Docker Hub pulls (all three, or pulls hang at auth) |
| `ghcr.io`, `pkg-containers.githubusercontent.com` | Trivy / Prowler images published on GHCR |
| `mirror.gcr.io` | Trivy's default DB mirror |
| `public.ecr.aws` | AWS-published images |

### Tier 3 — vulnerability feeds

| Domain | Why |
|---|---|
| `nvd.nist.gov` | CVE enrichment |
| `avd.aquasec.com` | Trivy advisory URLs |
| `api.osv.dev` | OSV lookups |

### Tier 4 — LLM upstreams (LiteLLM)

`openrouter.ai`, `api.anthropic.com`, `api.openai.com`, `cloud.langfuse.com`

### Verifying an allow-list is actually complete

```bash
for h in pypi.org files.pythonhosted.org github.com codeload.github.com \
         registry-1.docker.io auth.docker.io ghcr.io; do
  printf '%-40s ' "$h"
  curl -sS -o /dev/null -m 8 -D - "https://$h" 2>&1 \
    | awk '/^HTTP|x-deny-reason/{printf "%s ", $0}' | tr -d '\r'; echo
done
```

Any line containing `x-deny-reason` = still blocked. No header + `HTTP 2xx/3xx/401/403` from the
service itself = allowed (some registries legitimately return 401 to unauthenticated HEADs).

---

## 2. ASCC offline core

```
ascc_core.py            # correlation engine — stdlib ONLY, zero pip installs
test_ascc.py            # 24 unit tests, stdlib unittest
fixtures/leaky_data_lake/{trivy,prowler,checkov}.json
```

Run:

```bash
python3 ascc_core.py --dir fixtures/leaky_data_lake --sarif out.sarif --json out.json
python3 -m unittest test_ascc -v
```

### What it proves

| Metric | Result |
|---|---|
| Raw findings ingested | 16 (3 tools) |
| Canonical resources after identity resolution | 4 |
| Correlated risks emitted | 5 |
| Triage noise reduction | **69 %** |
| Third-party dependencies | **0** |

### The differentiator, in one test

```python
def test_terraform_and_arn_collapse_to_same_key(self):
    tf  = A.identity_from_tf_address("aws_s3_bucket.datalake_raw")   # Checkov / Trivy
    arn = A.identity_from_arn("arn:aws:s3:::datalake-raw")           # Prowler
    self.assertEqual(tf.match_key, arn.match_key)
```

Three scanners, three naming vocabularies, one real bucket. Everything downstream —
chaining, scoring, dedup — depends on this collapsing correctly.

### Correlation rules implemented

| Rule | What it finds | Why no scanner reports it |
|---|---|---|
| `ASCC-CHAIN-003` | internet → vulnerable host → over-privileged role → sensitive data | spans 3 resources and 3 tools |
| `ASCC-CHAIN-001` | public + unencrypted + PII-tagged store, logging off | needs tags from Prowler + IaC from Checkov |
| `ASCC-CHAIN-002` | internet-reachable host with critical CVE | needs config scan + vuln scan joined |
| `ASCC-CORR-010` | ≥2 independent tools agree on a category | cross-tool confidence, kills false-positive triage |

Remediation is emitted **cheapest-link-first**, not severity-first:

```
-> Break the chain at the cheapest link first: close SG ingress (minutes, zero blast radius)
-> Then scope the IAM role down (hours, needs testing)
-> Then patch + encrypt (scheduled maintenance)
```

### Known limitations (honest backlog)

- Security group and its attached instance stay separate resources — no edge model yet.
  Prowler blames the instance, Checkov blames the SG, so the SSH finding does not corroborate.
- `_slug()` identity matching is name-based. Two buckets named `logs` in different accounts
  will merge. **Fix before any multi-account use**: include `account` in `match_key`.
- No persistence layer. PostgreSQL + pgvector plugs in behind `ResourceGraph`, which is
  deliberately the only place that knows about storage.
- Azure/GCP normalizers not written. `TF_TYPE_TO_SERVICE` is the extension point.

---

## 3. Network diagnostics

```
net-diag.sh     # Ubuntu VM  — bash net-diag.sh [--deep]
net-diag.ps1    # Windows host — powershell -ExecutionPolicy Bypass -File .\net-diag.ps1 [-Fix]
```

`net-diag.sh` covers: clock skew → L3/L2 → DNS → egress (**detects `x-deny-reason`
and tells you it is an allow-list, not your network**) → PMTU blackhole → Docker daemon.json
→ AI-SOC listener ports → firewall. Exits non-zero on failure, so it drops straight into cron
or a systemd timer.

`net-diag.ps1` covers: elevation → VMMS + switch → vEthernet gateway IP → NAT object →
**subnet overlap with the new Xfinity 10.0.0.x LAN** → VM reachability + service ports →
portproxy staleness → firewall → host egress. `-Fix` recreates a missing NAT / gateway IP
interactively.

### The PMTU trap

Post-ISP-change symptom: small requests succeed, `pip install` and `docker pull` hang at ~90 %.
Cause: interface claims MTU 1500, path only carries 1492 (PPPoE) or less (tunnels), and ICMP
"fragmentation needed" is filtered. `--deep` probes for it:

```bash
ping -c1 -M do -s 1472 8.8.8.8   # 1472 + 28 = 1500
# fails but -s 1442 works?  ->  real MTU is 1470
sudo ip link set dev eth0 mtu 1470     # then persist in netplan
```

---

## 4. Local PyPI cache

```
pypi-mirror/{Dockerfile,docker-compose.yml,bootstrap.sh}
bash pypi-mirror/bootstrap.sh --warm
```

**devpi pull-through cache, not a full mirror.** Do not run `bandersnatch` in a homelab:
a complete PyPI mirror is well past 15 TB and grows daily. devpi caches only what you
actually install, which for the ASCC dep set is a few hundred MB.

What it buys you:

- pip keeps working when upstream PyPI is blocked, rate-limited, or down
- reproducible builds — the exact wheel you tested with stays on your disk
- **supply-chain control**: one chokepoint to audit and, later, to enforce hash pinning against
- great portfolio talking point: "I run an internal package proxy" is a real security-engineering signal

Binds to `172.31.0.10:3141`, not `0.0.0.0` — it is an internal service.

---

## 5. PEP 668 — `externally-managed-environment`

Ubuntu 24.04 / Python 3.12 refuses `pip install` into system Python. This is a feature,
not a bug: on Ubuntu, `apt` itself is a Python program. Break system site-packages and you
can lose `apt`, `netplan`, `cloud-init`, and `unattended-upgrades` at the same time —
on a headless VM that is a rebuild, not a fix.

### Decision matrix

| Situation | Do this | Not this |
|---|---|---|
| ASCC development on the VM | `python3 -m venv .venv` | `--break-system-packages` |
| Fast iteration, many venvs | `uv venv && uv pip install` | global installs |
| Standalone CLI tools (ruff, checkov) | `pipx install checkov` | `pip install --user` |
| Inside a Dockerfile you own | plain `pip install` (container *is* the venv) | venv-in-container ceremony |
| Throwaway CI runner, rebuilt each job | `--break-system-packages` is fine | anything on a persistent host |
| **Any long-lived Ubuntu VM** | venv / pipx | `--break-system-packages`, ever |

### Canonical setup for ASCC

```bash
cd ~/ascc
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
# ascc_core.py needs nothing; these are for the pgvector/API layer later
pip install psycopg2-binary sqlalchemy pgvector pydantic rich typer pytest ruff
```

`pipx` for tools you invoke rather than import:

```bash
sudo apt install -y pipx && pipx ensurepath
pipx install checkov
pipx install prowler
```

### If you truly need a global override

```bash
# per-command, deliberate, visible in shell history
pip install --break-system-packages <pkg>
```

Do **not** make it permanent via `pip.conf`:

```ini
[global]
break-system-packages = true   # <- silently disarms the guardrail for every future command
```

That line is how a working VM becomes a reinstall three months later.

---

## Order of operations from a cold start

```bash
# 1. is it the network or the allow-list?
bash net-diag.sh --deep

# 2. if x-deny-reason -> fix the allow-list (section 1), nothing else will help
# 3. if the VM is genuinely broken -> run net-diag.ps1 on the Windows host

# 4. meanwhile, ASCC needs none of the above
python3 ascc_core.py --dir fixtures/leaky_data_lake --sarif out.sarif
python3 -m unittest test_ascc -v

# 5. once egress works, stop depending on it
bash pypi-mirror/bootstrap.sh --warm

# 6. and never fight PEP 668 again
python3 -m venv .venv && source .venv/bin/activate
```
