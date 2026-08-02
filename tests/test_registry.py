from __future__ import annotations

import json
from pathlib import Path

import pytest

from ascc.ingest.base import ScannerParser
from ascc.ingest.checkov import CheckovParser
from ascc.ingest.prowler import ProwlerParser
from ascc.ingest.registry import parser_for
from ascc.ingest.trivy import TrivyParser
from ascc.schema.models import ScanRun


def test_trivy_fixture_recognized_as_trivy(fixtures_dir: Path) -> None:
    data = json.loads((fixtures_dir / "trivy.json").read_text())
    assert parser_for(data) is TrivyParser


def test_prowler_fixture_recognized_as_prowler(fixtures_dir: Path) -> None:
    data = json.loads((fixtures_dir / "prowler.json").read_text())
    assert parser_for(data) is ProwlerParser


def test_checkov_fixture_recognized_as_checkov(fixtures_dir: Path) -> None:
    data = json.loads((fixtures_dir / "checkov.json").read_text())
    assert parser_for(data) is CheckovParser


def test_readme_is_not_valid_json(fixtures_dir: Path) -> None:
    """README.md никогда не доходит до parser_for — оно принимает уже
    распарсенный JSON, а README.md им не является. Распознавание
    "это не JSON вовсе" живёт на уровне CLI, не registry."""
    readme_text = (fixtures_dir / "README.md").read_text()
    with pytest.raises(json.JSONDecodeError):
        json.loads(readme_text)


@pytest.mark.parametrize(
    ("parser_cls", "foreign_fixture"),
    [
        (TrivyParser, "prowler.json"),
        (TrivyParser, "checkov.json"),
        (ProwlerParser, "trivy.json"),
        (ProwlerParser, "checkov.json"),
        (CheckovParser, "trivy.json"),
        (CheckovParser, "prowler.json"),
    ],
)
def test_sniff_rejects_foreign_fixture(
    parser_cls: type[ScannerParser], foreign_fixture: str, fixtures_dir: Path
) -> None:
    data = json.loads((fixtures_dir / foreign_fixture).read_text())
    assert parser_cls.sniff(data) is False


def test_ambiguous_sniff_raises_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeParserA(ScannerParser):
        @property
        def scanner_name(self) -> str:
            return "fake_a"

        @classmethod
        def sniff(cls, data: dict | list) -> bool:
            return True

        def parse(self, path: str | Path) -> ScanRun:
            raise NotImplementedError

    class FakeParserB(ScannerParser):
        @property
        def scanner_name(self) -> str:
            return "fake_b"

        @classmethod
        def sniff(cls, data: dict | list) -> bool:
            return True

        def parse(self, path: str | Path) -> ScanRun:
            raise NotImplementedError

    import ascc.ingest.registry as registry_module

    monkeypatch.setattr(registry_module, "PARSERS", (FakeParserA, FakeParserB))
    with pytest.raises(ValueError, match="FakeParserA.*FakeParserB"):
        registry_module.parser_for({})
