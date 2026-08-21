"""SARIF 2.1.0 export. Pure functions over the domain model."""

from __future__ import annotations

import hashlib
import json

from ascc.schema.models import Finding

FINGERPRINT_VERSION = "asccDedupKey/v1"


def fingerprint(finding: Finding) -> str:
    """Stable identity of a finding across runs.

    Backed by Finding.dedup_key, which is backed by MatchKey.__str__.
    Changing either invalidates every published fingerprint — bump the
    version suffix instead.
    """
    payload = json.dumps(
        list(finding.dedup_key),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
