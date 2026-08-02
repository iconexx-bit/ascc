from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ascc.schema.models import ScanRun


class ScannerParser(ABC):
    """Общий интерфейс парсера сканера. Ничего не знает о конкретном сканере."""

    @property
    @abstractmethod
    def scanner_name(self) -> str: ...

    @abstractmethod
    def parse(self, path: Path) -> ScanRun: ...
