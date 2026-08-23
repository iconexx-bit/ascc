"""Determinism tests for `ascc correlate --output`.

Byte-for-byte SARIF determinism is a CI-enforced contract (see CLAUDE.md,
"Determinism"): the same findings must serialize to the same bytes
regardless of PYTHONHASHSEED or the order scanner files were read from
disk. This drives the CLI as a real subprocess -- the boundary that
matters -- and compares raw output bytes. Never re-serialize with json:
two JSON documents can compare equal while differing byte-for-byte (key
order, whitespace), which is exactly the class of drift this test exists
to catch.
Caveat: on ext4 with dir_index, readdir order is hash-based, not
insertion-based, so test_stable_across_input_order is vacuous on this
filesystem -- both directories enumerate identically. It is kept because
it becomes meaningful on filesystems with insertion-ordered readdir and
guards the contract explicitly. The real guarantee is sorted(input.iterdir())
in the CLI plus test_stable_across_hash_seeds.
"""

from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_REL = Path("fixtures") / "leaky_data_lake"


def _run_correlate(input_arg: str, output: Path, *, env: dict[str, str]) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "ascc",
            "correlate",
            "--input",
            input_arg,
            "--output",
            str(output),
        ],
        check=True,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
    )


def test_stable_across_hash_seeds(tmp_path: Path) -> None:
    outputs = []
    for seed in ("0", "1", "2"):
        out = tmp_path / f"seed-{seed}.sarif.json"
        env = {**os.environ, "PYTHONHASHSEED": seed}
        _run_correlate(str(FIXTURE_REL), out, env=env)
        outputs.append(out.read_bytes())

    assert outputs[0] == outputs[1] == outputs[2]


def test_stable_across_input_order(tmp_path: Path) -> None:
    fixture_dir = REPO_ROOT / FIXTURE_REL
    files = sorted(fixture_dir.iterdir())

    in_order_dir = tmp_path / "in_order"
    shuffled_dir = tmp_path / "shuffled"
    in_order_dir.mkdir()
    shuffled_dir.mkdir()

    for file in files:
        shutil.copy2(file, in_order_dir / file.name)

    shuffled_files = files.copy()
    random.Random(1337).shuffle(shuffled_files)
    for file in shuffled_files:
        shutil.copy2(file, shuffled_dir / file.name)

    env = {**os.environ}
    out_in_order = tmp_path / "in_order.sarif.json"
    out_shuffled = tmp_path / "shuffled.sarif.json"
    _run_correlate(str(in_order_dir), out_in_order, env=env)
    _run_correlate(str(shuffled_dir), out_shuffled, env=env)

    assert out_in_order.read_bytes() == out_shuffled.read_bytes()
