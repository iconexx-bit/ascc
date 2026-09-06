import json
import os
import tempfile
from enum import IntEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ascc.correlate.run import correlate as run_correlate
from ascc.correlate.run import effective_confidence
from ascc.export.sarif import to_sarif
from ascc.ingest.registry import parser_for
from ascc.schema.models import ScanRun


class ExitCode(IntEnum):
    """Контракт кодов возврата. Публичный API для CI-интеграций."""

    OK = 0
    FINDINGS = 1  # зарезервирован под --fail-on
    USAGE = 2  # выставляется Click
    NO_INPUT = 3
    INTERNAL = 70  # sysexits.h EX_SOFTWARE


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
        help="Path to a fact store (reserved; not yet implemented).",
    ),
) -> None:
    del store  # no-op until FactRepository lands
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

    try:
        correlation_run = run_correlate(scan_runs)
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
            Console(stderr=True).print(f"[red]Failed to write SARIF output:[/red] {exc}")
            raise typer.Exit(code=ExitCode.INTERNAL) from None
        finally:
            if tmp_name is not None and os.path.exists(tmp_name):
                os.unlink(tmp_name)

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
