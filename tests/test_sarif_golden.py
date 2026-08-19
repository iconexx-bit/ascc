"""Golden tests for tests/sarif_normalizer.py against a synthetic SARIF fixture.

The fixture (tests/data/synthetic.sarif.json) is hand-written, not produced by
a real `ascc correlate` run -- SARIF export does not exist yet (src/ascc/export/
is empty). It exists to exercise every normalization rule in one document:
volatile invocations, driver version, guids, float precision, absolute repo
paths, and out-of-order results.
"""

import json
from pathlib import Path

from sarif_normalizer import normalize_sarif

FIXTURE = Path(__file__).parent / "data" / "synthetic.sarif.json"


def _load_fixture() -> dict:
    return json.loads(FIXTURE.read_text())


def test_normalizes_synthetic_fixture() -> None:
    normalized = normalize_sarif(_load_fixture())
    run = normalized["runs"][0]

    assert "invocations" not in run

    driver = run["tool"]["driver"]
    assert "version" not in driver
    assert "semanticVersion" not in driver

    results = run["results"]
    assert all("guid" not in r and "correlationGuid" not in r for r in results)

    rule_ids = [r["ruleId"] for r in results]
    resource_ids = [r["properties"]["resource_id"] for r in results]
    messages = [r["message"]["text"] for r in results]
    assert list(zip(rule_ids, resource_ids, messages)) == sorted(
        zip(rule_ids, resource_ids, messages)
    )

    rounded = next(
        r["properties"]["score_weight"] for r in results if "score_weight" in r["properties"]
    )
    assert rounded == round(0.123456789, 6)

    uris = [
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for r in results
        for loc in r["locations"]
    ]
    assert all(not uri.startswith("file:///home/") for uri in uris)
    assert all(uri.startswith("file:///REPO/") for uri in uris)


def test_two_runs_identical() -> None:
    doc = _load_fixture()
    first = normalize_sarif(doc)
    second = normalize_sarif(doc)
    assert first == second
