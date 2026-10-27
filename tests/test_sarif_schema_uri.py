"""$schema of the exported SARIF names a schema that exists (CLAUDE.md, "Determinism").

Up to 0.2.0 the export named
raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json.
oasis-tcs/sarif-spec has no master branch any more and Schemata/ was removed on
2024-05-02 (a560296, "Seeding the SARIF v2.2 workplace"), so editors cannot
load it. The OASIS errata01 URI is the id the published schema gives itself.
Validation is unaffected either way: tests/test_sarif_schema.py uses the
committed copy in tests/schemas/, never the network.
"""

from __future__ import annotations

import json
from pathlib import Path

from ascc.correlate.run import correlate
from ascc.export.sarif import to_sarif

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = REPO_ROOT / "tests" / "data" / "leaky_data_lake.sarif.json"
OASIS = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
REMOVED = "oasis-tcs/sarif-spec/master/Schemata"


def test_export_names_the_oasis_errata01_schema() -> None:
    assert to_sarif(correlate([]))["$schema"] == OASIS


def test_golden_names_the_same_schema() -> None:
    assert json.loads(GOLDEN.read_text(encoding="utf-8"))["$schema"] == OASIS


def test_removed_github_path_is_gone_from_code_and_golden() -> None:
    for path in (REPO_ROOT / "src" / "ascc" / "export" / "sarif.py", GOLDEN):
        assert REMOVED not in path.read_text(encoding="utf-8"), path
