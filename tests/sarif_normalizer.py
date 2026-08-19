"""Normalize a SARIF document for byte-stable golden comparison.

Strips fields that vary run-to-run (wall clock, driver version, guids),
rounds floats to a stable precision, relativizes absolute repo paths, and
sorts results deterministically. Test-only: not part of the ascc package.
"""

from __future__ import annotations

import copy
import re
from typing import Any

# Driver fields that vary across builds/checkouts and carry no signal for
# golden comparison.
VOLATILE_DRIVER_FIELDS = frozenset({"version", "semanticVersion"})

# Matches an absolute file:// URI up to and including the repo root
# directory name "ascc/", regardless of where the checkout lives on disk.
_REPO_PATH_RE = re.compile(r"file://[^\"']*?/ascc/")

FLOAT_NDIGITS = 6


def _relativize_paths(value: Any) -> Any:
    if isinstance(value, str):
        return _REPO_PATH_RE.sub("file:///REPO/", value)
    if isinstance(value, dict):
        return {k: _relativize_paths(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_relativize_paths(v) for v in value]
    return value


def _round_floats(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, FLOAT_NDIGITS)
    if isinstance(value, dict):
        return {k: _round_floats(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_round_floats(v) for v in value]
    return value


def _result_sort_key(result: dict[str, Any]) -> tuple[str, str, str]:
    rule_id = result.get("ruleId", "")
    resource_id = result.get("properties", {}).get("resource_id", "")
    message = result.get("message", {}).get("text", "")
    return (rule_id, resource_id, message)


def normalize_sarif(doc: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized copy of a SARIF document.

    - drops runs[].invocations[] (wall clock, non-reproducible)
    - drops tool.driver.{version,semanticVersion} (VOLATILE_DRIVER_FIELDS)
    - drops results[].guid and results[].correlationGuid
    - rounds every float to FLOAT_NDIGITS decimals
    - relativizes file:///.../ascc/ paths to file:///REPO/
    - sorts each run's results by (ruleId, properties.resource_id, message.text)

    Does not mutate the input.
    """
    normalized = copy.deepcopy(doc)

    for run in normalized.get("runs", []):
        run.pop("invocations", None)

        driver = run.get("tool", {}).get("driver", {})
        for field in VOLATILE_DRIVER_FIELDS:
            driver.pop(field, None)

        results = run.get("results", [])
        for result in results:
            result.pop("guid", None)
            result.pop("correlationGuid", None)

        results.sort(key=_result_sort_key)

    normalized = _round_floats(normalized)
    normalized = _relativize_paths(normalized)
    return normalized
