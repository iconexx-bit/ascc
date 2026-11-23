"""Public docs are English and the fixture README says what the code shows.

The repository is English-language. Tracked markdown files a visitor reads (top
level, .github/, docs/, fixtures/) carry no Cyrillic; CLAUDE.md is the agent's
working contract and is exempt, and git-ignored local files are not public. The Leaky Data Lake fixture README must say that the
fixture is synthetic and not a verified copy of real scanner output, keep the
section that lists where it differs from real output, carry the same funnel line as the README demo (which tests/test_readme_demo.py pins to
the code), and count findings per scanner as the fixture files do. SECURITY.md
must not claim that the project has no releases.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "fixtures" / "leaky_data_lake"
EXEMPT = {"CLAUDE.md"}
CYRILLIC = re.compile(r"[\u0400-\u04FF]")
FUNNEL = re.compile(
    r"\*\*\d+ findings → \d+ resource keys → \d+ graph nodes → \d+ chain of \d+ hops\.\*\*"
)


def _flat(text: str) -> str:
    return " ".join(text.split())


def public_markdown() -> list[Path]:
    # Tracked files only: what a visitor sees is what git publishes. Local,
    # git-ignored working files (agent task specs: task-*.md, tasks/) are not
    # public and stay out of the check.
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\0")
    return [REPO_ROOT / rel for rel in sorted(name for name in listed if name) if _public(rel)]


def _public(rel: str) -> bool:
    if "/" not in rel:
        return rel not in EXEMPT
    return rel.split("/", 1)[0] in (".github", "docs", "fixtures")


def test_public_markdown_is_english() -> None:
    offenders = [
        str(p.relative_to(REPO_ROOT))
        for p in public_markdown()
        if CYRILLIC.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"Cyrillic text in public markdown: {offenders}"


def test_fixture_readme_says_it_is_synthetic() -> None:
    text = _flat((FIXTURE / "README.md").read_text(encoding="utf-8"))
    assert "synthetic" in text
    assert "not a verified copy of real scanner output" in text
    assert "## How close it is to real scanner output" in text


def _parsers_that_stop_on_real_output() -> set[str]:
    from ascc.ingest.checkov import CheckovParser
    from ascc.ingest.prowler import ProwlerParser
    from ascc.ingest.trivy import TrivyParser

    real = REPO_ROOT / "fixtures" / "leaky_data_lake_real"
    stopped: set[str] = set()
    for name, parser, label in (
        ("checkov.json", CheckovParser, "Checkov"),
        ("prowler.json", ProwlerParser, "Prowler"),
        ("trivy-config.json", TrivyParser, "Trivy"),
        ("trivy-rootfs.json", TrivyParser, "Trivy"),
    ):
        try:
            parser().parse(real / name)
        except Exception:  # noqa: BLE001 — any failure counts as "stops"
            stopped.add(label)
    return stopped


def test_fixture_readme_names_the_parsers_that_stop_on_real_output() -> None:
    text = _flat((FIXTURE / "README.md").read_text(encoding="utf-8"))
    match = re.search(r"Parsers that still stop on real output: ([A-Za-z, ]+)\.", text)
    assert match, "README must say which parsers still stop on real output"
    named = {p.strip() for p in match.group(1).split(",")} - {"none"}
    assert named == _parsers_that_stop_on_real_output()


def test_fixture_readme_funnel_matches_the_readme_demo() -> None:
    demo = FUNNEL.findall((REPO_ROOT / "README.md").read_text(encoding="utf-8"))
    fixture = FUNNEL.findall((FIXTURE / "README.md").read_text(encoding="utf-8"))
    assert len(demo) == 1, f"README.md: expected one funnel line, found {demo}"
    assert fixture == demo


def _counts() -> dict[str, int]:
    trivy = json.loads((FIXTURE / "trivy.json").read_text(encoding="utf-8"))
    prowler = json.loads((FIXTURE / "prowler.json").read_text(encoding="utf-8"))
    checkov = json.loads((FIXTURE / "checkov.json").read_text(encoding="utf-8"))
    checkov_runs = checkov if isinstance(checkov, list) else [checkov]
    return {
        "Trivy": sum(
            len(r.get("Vulnerabilities") or []) + len(r.get("Misconfigurations") or [])
            for r in trivy["Results"]
        ),
        "Prowler": len(prowler),
        "Checkov": sum(len(run["results"]["failed_checks"]) for run in checkov_runs),
    }


def test_fixture_readme_counts_findings_as_the_fixture_does() -> None:
    counts = _counts()
    line = (
        f"{sum(counts.values())} findings: "
        + ", ".join(f"{name} {n}" for name, n in counts.items())
        + "."
    )
    text = _flat((FIXTURE / "README.md").read_text(encoding="utf-8"))
    assert line in text, f"fixture README must carry: {line!r}"
    stated = re.findall(r"\b(Trivy|Prowler|Checkov) (\d+)\b", text)
    wrong = [(name, int(n)) for name, n in stated if int(n) != counts[name]]
    assert not wrong, f"per-scanner counts differ from the fixture files {counts}: {wrong}"


def test_security_policy_names_the_supported_release() -> None:
    text = _flat((REPO_ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8"))
    assert "only the latest release is supported" in text
    assert "does not use release versioning" not in text
