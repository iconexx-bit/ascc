import json
import os
import tempfile
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ascc.correlate.history import facts_to_bridge_facts
from ascc.correlate.run import correlate as run_correlate
from ascc.correlate.run import effective_confidence
from ascc.export.sarif import to_sarif
from ascc.ingest.registry import parser_for
from ascc.schema.models import BridgeFact, ScanRun
from ascc.store import Fact, JsonlFactRepository


class ExitCode(IntEnum):
    """Контракт кодов возврата. Публичный API для CI-интеграций."""

    OK = 0
    FINDINGS = 1  # зарезервирован под --fail-on
    USAGE = 2  # выставляется Click
    NO_INPUT = 3
    INTERNAL = 70  # sysexits.h EX_SOFTWARE


_MATCH_KEY_FIELDS = ("partition", "service", "resource_type", "identifier")


def _to_fact(bf: BridgeFact, *, observed_at: datetime) -> Fact:
    """Map a BridgeFact to a store Fact. Explicit field mapping only.

    key is the sorted pair of the sides' string forms. BridgeFact.__post_init__
    already orders left/right the same way, so within one version this sort is
    redundant — but the persisted key is a durable on-disk format and must not
    inherit an in-memory invariant that could change later (see CLAUDE.md,
    "Step 5: CLI wiring + producer").

    payload_v 1 (Step 6): each side's four MatchKey fields, flat-prefixed
    `{side}.{field}`, so a consumer (ascc.correlate.history) can reconstruct
    MatchKey(*fields) without ever parsing str(MatchKey) — see CLAUDE.md,
    "Step 6: store consumer". getattr defaults to "" for a side that is not a
    real MatchKey: test_cli_store.py exercises this mapper's sort behaviour
    with a stand-in carrying only __str__, and a real BridgeFact's sides
    always have all four fields.
    """
    payload: dict[str, str] = {
        "payload_v": "1",
        "source": bf.source,
        "evidence": bf.evidence,
    }
    for side, key in (("left", bf.left), ("right", bf.right)):
        for field in _MATCH_KEY_FIELDS:
            payload[f"{side}.{field}"] = getattr(key, field, "")
    return Fact(
        key=tuple(sorted((str(bf.left), str(bf.right)))),
        method=bf.method,
        confidence=bf.confidence,
        observed_at=observed_at,
        payload=payload,
    )


def _now() -> datetime:
    """`ASCC_NOW` (RFC3339) overrides the clock when set; otherwise the real
    clock. Required for reproducible history fixtures: observed_together's
    7-day TTL would expire a committed fixture with no code change (see
    CLAUDE.md, "Step 6: store consumer")."""
    raw = os.environ.get("ASCC_NOW")
    if raw is not None:
        return datetime.fromisoformat(raw)
    return datetime.now(UTC)


app = typer.Typer(name="ascc", help="AI Security Command Center")


def _make_console() -> Console:
    width = int(os.environ["ASCC_CONSOLE_WIDTH"]) if "ASCC_CONSOLE_WIDTH" in os.environ else None
    return Console(width=width)


@app.callback()
def main() -> None:
    """AI Security Command Center — correlation layer over Trivy, Prowler, Checkov."""


@app.command()
def correlate(
    input: Path = typer.Option(
        ...,
        "--input",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Path to a directory of scanner fixtures (Trivy/Prowler/Checkov JSON).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        dir_okay=False,
        writable=True,
        help="Write SARIF 2.1.0 log to PATH.",
    ),
    store: Path | None = typer.Option(
        None,
        "--store",
        file_okay=False,
        dir_okay=True,
        writable=True,
        help="Path to a fact store; persists observed_together bridge facts.",
    ),
) -> None:
    console = _make_console()
    scan_runs: list[ScanRun] = []
    skipped: list[tuple[str, str]] = []

    for file in sorted(input.iterdir()):
        if not file.is_file():
            continue
        try:
            data = json.loads(file.read_text())
        except json.JSONDecodeError:
            skipped.append((file.name, "not valid JSON"))
            continue
        parser_cls = parser_for(data)
        if parser_cls is None:
            skipped.append((file.name, "unrecognized format"))
            continue
        scan_runs.append(parser_cls().parse(file))

    if not scan_runs:
        console.print(f"[red]No recognized scanner files in[/red] {input}")
        raise typer.Exit(code=ExitCode.NO_INPUT)

    scanners = ", ".join(sorted({run.scanner for run in scan_runs}))
    console.print(
        f"[bold]Read {len(scan_runs)} file(s)[/bold] ({scanners}), skipped {len(skipped)}"
    )
    for name, reason in skipped:
        console.print(f"[yellow]Skipping {name}: {reason}[/yellow]")

    now = _now()

    # Step 6: read → correlate → write. `repo` is created here (not inside the
    # persist block below) so the same instance and the same `now` serve both
    # the read and the write side of one run.
    repo: JsonlFactRepository | None = None
    historical: list[BridgeFact] = []
    if store is not None:
        repo = JsonlFactRepository(store)
        try:
            historical, _dropped = facts_to_bridge_facts(repo.all(now=now), known={})
        except OSError as exc:
            # An unreadable store degrades to no history rather than aborting
            # the run — the write block below hits the same path and is where
            # a --store failure is actually surfaced (see CLAUDE.md, "Step 5:
            # CLI wiring + producer").
            typer.echo(f"Store unreadable, continuing without history: {exc}", err=True)
            historical = []

    try:
        correlation_run = run_correlate(scan_runs, extra_facts=historical)
    except Exception:  # noqa: BLE001 — CLI boundary: any internal failure maps to INTERNAL
        console.print_exception()
        raise typer.Exit(code=ExitCode.INTERNAL) from None

    if output is not None:
        doc = to_sarif(correlation_run)
        tmp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                dir=output.parent,
                prefix=".ascc-",
                suffix=".tmp",
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp_name = tmp.name
                json.dump(doc, tmp, sort_keys=True, ensure_ascii=False, indent=2)
                tmp.write("\n")
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, output)
            tmp_name = None
        except OSError as exc:
            typer.echo(f"Failed to write SARIF output: {exc}", err=True)
            raise typer.Exit(code=ExitCode.INTERNAL) from None
        finally:
            if tmp_name is not None and os.path.exists(tmp_name):
                os.unlink(tmp_name)

    if repo is not None:
        # Facts are written only here, after the whole `if output is not
        # None:` block above and at the same indentation level — never
        # nested inside it. SARIF generation has already completed by this
        # point, so an absent or empty --store cannot leak into the
        # artifact; that is what keeps --store output-neutral.
        try:
            for run in correlation_run.scan_runs:
                for bf in run.bridge_facts:
                    repo.put(_to_fact(bf, observed_at=now), now=now)
        except OSError as exc:
            typer.echo(f"Failed to persist store: {exc}", err=True)
            if output is None:
                raise typer.Exit(code=ExitCode.INTERNAL) from None

    resources_table = Table(title="Resources")
    resources_table.add_column("Key")
    resources_table.add_column("Refs")
    resources_table.add_column("Scanners")
    resources_table.add_column("Tags")
    for key, resource in correlation_run.resources.items():
        scanners_seen = ", ".join(sorted({ref.scanner for ref in resource.refs}))
        tags = ", ".join(f"{k}={v}" for k, v in resource.tags.items())
        resources_table.add_row(key, str(len(resource.refs)), scanners_seen, tags)
    console.print(resources_table)

    if correlation_run.clusters:
        clusters_table = Table(title="Clusters")
        clusters_table.add_column("Representative")
        clusters_table.add_column("Left")
        clusters_table.add_column("Right")
        clusters_table.add_column("Method")
        clusters_table.add_column("Confidence")
        for cluster in correlation_run.clusters:
            representative = str(cluster.representative())
            for fact in cluster.facts:
                clusters_table.add_row(
                    representative,
                    str(fact.left),
                    str(fact.right),
                    fact.method,
                    f"{fact.confidence:g}",
                )
        console.print(clusters_table)

    findings_table = Table(title="Findings")
    findings_table.add_column("Finding")
    findings_table.add_column("Resource")
    findings_table.add_column("Confidence")
    for run in correlation_run.scan_runs:
        for finding in run.findings:
            finding_id = f"{finding.scanner}:{finding.rule_id}"
            for resolution in finding.resolutions:
                own_key = resolution.key
                findings_table.add_row(finding_id, str(own_key), f"{resolution.confidence:.3f}")
                cluster = next((c for c in correlation_run.clusters if own_key in c.keys), None)
                if cluster is None:
                    continue
                for other_key in sorted(cluster.keys, key=str):
                    if other_key == own_key:
                        continue
                    bridge_confidence = cluster.direct_confidence(own_key, other_key)
                    if bridge_confidence is None:
                        continue
                    eff = effective_confidence(finding, other_key, correlation_run)
                    findings_table.add_row(
                        finding_id,
                        str(other_key),
                        f"{eff:.3f} = {resolution.confidence:.3f} x {bridge_confidence:.3f} bridge",
                    )
    console.print(findings_table)

    if correlation_run.tag_conflicts:
        conflicts_table = Table(title="Tag conflicts")
        conflicts_table.add_column("Resource")
        conflicts_table.add_column("Tag")
        conflicts_table.add_column("Values")
        for conflict in correlation_run.tag_conflicts:
            values = ", ".join(f"{scanner}={value}" for scanner, value in conflict.values)
            conflicts_table.add_row(str(conflict.resource_key), conflict.tag_key, values)
        console.print(conflicts_table)


if __name__ == "__main__":
    app()
