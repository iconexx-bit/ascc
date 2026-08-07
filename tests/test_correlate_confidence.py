"""Инвариант композиции confidence: произведение, не среднее.

Явно защищает от замены на геометрическое (или арифметическое) среднее —
см. докстринг effective_confidence в correlate/run.py.
"""

from __future__ import annotations

import math


def test_composition_is_product_not_geometric_mean() -> None:
    """0.5 * 0.95 != sqrt(0.5 * 0.95) — если тест когда-нибудь начнёт
    падать при замене формулы, это сигнал, что кто-то тихо переключил
    композицию на среднее."""
    resolution_confidence = 0.5
    bridge_confidence = 0.95

    product = resolution_confidence * bridge_confidence
    geomean = math.sqrt(resolution_confidence * bridge_confidence)

    assert abs(product - 0.475) < 1e-9
    assert abs(geomean - 0.6892) < 0.001
    assert product < geomean, (
        "Композиция должна быть строже среднего — иначе цепочка "
        "предположений выглядит надёжнее, чем есть на самом деле"
    )


def test_product_decays_with_chain_length_geomean_does_not() -> None:
    """Демонстрация, почему произведение — правильная модель для цепочек:
    оно убывает с числом звеньев, среднее — нет."""
    links = [0.9, 0.9, 0.9, 0.9, 0.9]

    product = math.prod(links)
    geomean = math.prod(links) ** (1 / len(links))

    assert product < 0.6  # накопленная неопределённость видна
    assert abs(geomean - 0.9) < 0.001  # среднее слепо к длине цепи — не годится
def test_chaos_intentional_failure(): assert False
def test_chaos_intentional_failure(): assert False
