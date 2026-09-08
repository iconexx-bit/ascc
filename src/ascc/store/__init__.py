"""Fact persistence. Repository at the boundary; the correlate/ core stays pure."""

from __future__ import annotations

from .memory import InMemoryFactRepository
from .models import Fact
from .repository import FactRepository

__all__ = ["Fact", "FactRepository", "InMemoryFactRepository"]
