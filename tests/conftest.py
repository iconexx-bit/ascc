from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _console_width(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the CLI console width for every test.

    Rich takes the width from COLUMNS or from whatever terminal the test run
    inherited (stdin included), so tests that assert on printed lines passed
    or failed with the caller's terminal. ASCC_CONSOLE_WIDTH overrides both.
    """
    monkeypatch.setenv("ASCC_CONSOLE_WIDTH", "200")


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "fixtures" / "leaky_data_lake"
