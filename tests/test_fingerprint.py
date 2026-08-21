"""Fingerprint stability contract. See CLAUDE.md: MatchKey.__str__."""

from __future__ import annotations

from pathlib import Path

from ascc.export.sarif import FINGERPRINT_VERSION, fingerprint
from ascc.ingest.trivy import TrivyParser
from ascc.schema.identity import MatchKey


def test_version_is_pinned() -> None:
    assert FINGERPRINT_VERSION == "asccDedupKey/v1"


def test_matchkey_str_is_canonical() -> None:
    a = MatchKey("aws", "s3", "bucket", "datalake-raw")
    b = MatchKey("aws", "s3", "bucket", "datalake-raw")
    assert str(a) == str(b) == "aws:s3:bucket:datalake-raw"


def test_fingerprint_stable_across_parses(fixtures_dir: Path) -> None:
    path = fixtures_dir / "trivy.json"
    first = sorted(fingerprint(f) for f in TrivyParser().parse(path).findings)
    second = sorted(fingerprint(f) for f in TrivyParser().parse(path).findings)
    assert first == second


def test_fingerprint_is_hex_sha256(fixtures_dir: Path) -> None:
    f = TrivyParser().parse(fixtures_dir / "trivy.json").findings[0]
    fp = fingerprint(f)
    assert len(fp) == 64 and set(fp) <= set("0123456789abcdef")
